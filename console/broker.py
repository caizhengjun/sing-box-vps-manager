"""Root-owned, Unix-socket-only command broker. No arbitrary shell endpoint.

Web API runs separately as sb-console. Only this broker reads the manager DB.
Queued inputs stay in memory; SSH passwords are never written to the task DB.
"""
import base64
import contextlib
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import sqlite3
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import queue

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import controller as ctl
from common import Error, canonical, domain, label, labels, lock, now, port, uid

BASE = Path(os.environ.get('SB_CONSOLE_BROKER_HOME', '/var/lib/sb-console-broker'))
SOCKET = os.environ.get('SB_CONSOLE_SOCKET', '/run/sb-console/broker.sock')
JOBS = queue.Queue(maxsize=30)
PROBES = {}
PROBE_LOCK = threading.Lock()
FORMATS = ('singbox', 'karing', 'mihomo', 'links', 'base64')

def database():
    BASE.mkdir(parents=True, mode=0o700, exist_ok=True)
    d = sqlite3.connect(BASE/'tasks.sqlite', timeout=10)
    d.row_factory = sqlite3.Row
    d.executescript('''PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,kind TEXT,actor TEXT,created INTEGER,
        updated INTEGER,state TEXT,step TEXT,error TEXT);
      CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,actor TEXT,action TEXT,target TEXT,created INTEGER);
    ''')
    return d

def progress(task, step, state='running', error=''):
    with database() as d:
        d.execute('UPDATE tasks SET step=?,state=?,updated=?,error=? WHERE id=?',
                  (step,state,now(),error,task))

def safe_actor(value):
    return label(str(value))

def snapshot():
    # WAL read transaction: consistent view without taking the long reconcile lock.
    d = sqlite3.connect('file:'+str(ctl.DB)+'?mode=ro', uri=True, timeout=5)
    d.row_factory = sqlite3.Row
    try:
        d.execute('BEGIN')
        nodes = [{k:r[k] for k in r.keys() if k != 'ssh_key'} for r in d.execute('SELECT * FROM nodes WHERE state!="deleted"')]
        plans = [dict(r) for r in d.execute('SELECT * FROM plans')]
        for p in plans:
            policy=d.execute('SELECT mode FROM plan_access WHERE plan_id=?',(p['id'],)).fetchone()
            p['access_mode']=policy['mode'] if policy else 'tags'
            p['node_ids']=[r[0] for r in d.execute('SELECT node_id FROM plan_nodes WHERE plan_id=?',(p['id'],))]
            p['matched_node_ids']=[n['id'] for n in nodes if (n['id'] in p['node_ids'] if p['access_mode']=='selected'
                                   else bool(set(json.loads(n['tags'])) & set(json.loads(p['tags']))))]
        users = []
        for r in d.execute('SELECT * FROM users WHERE state!="deleted"'):
            u = {k:r[k] for k in r.keys() if k != 'token'}
            u['nodes'] = ctl.assigned_nodes(d,r)
            u['used_display'] = ctl.human_bytes(r['upload']+r['download'])
            u['quota_display'] = '不限流量' if r['is_admin'] else ctl.human_bytes(r['quota'])
            u['node_rules']={v['node_id']:v['rule'] for v in d.execute('SELECT * FROM user_node_rules WHERE user_id=?',(r['id'],))}
            eligible=r['state']=='active' and (r['is_admin'] or (r['expires']>now() and r['upload']+r['download']<r['quota']))
            u['entitled_node_ids']=[n['id'] for n in nodes if ctl.node_entitlement(d,r,n)]
            u['desired_node_ids']=[n['id'] for n in nodes if eligible and n['state']=='active' and n['stats_ready'] and ctl.node_entitlement(d,r,n)]
            users.append(u)
        for n in nodes:
            health=d.execute('SELECT * FROM node_health WHERE node_id=?',(n['id'],)).fetchone()
            n['health']=json.loads(health['payload']) if health else None
            n['health_checked']=health['checked'] if health else None
            n['applied_users']=[{'id':r['id'],'name':r['name'],'state':r['state']} for r in d.execute('''
              SELECT users.id,users.name,users.state FROM grants JOIN users
              ON grants.principal='m_'||users.id||'_'||users.cycle WHERE grants.node_id=?''',(n['id'],))]
            n['assigned_user_count']=len(n['applied_users'])
            n['desired_user_count']=len(ctl.effective(d,n))
            n['historical_used_user_count']=d.execute('SELECT COUNT(DISTINCT substr(principal,3,32)) FROM samples WHERE node_id=? AND up+down>0',(n['id'],)).fetchone()[0]
            n['recorded_traffic']=d.execute('SELECT COALESCE(SUM(up+down),0) FROM samples WHERE node_id=?',(n['id'],)).fetchone()[0]
        return {'nodes':nodes,'plans':plans,'users':users,'server_time':now()}
    finally:d.close()

def public_host(value):
    ip = ipaddress.ip_address(str(value))
    if not ip.is_global:raise Error('节点 IP 必须是公网地址。')
    return str(ip)

def connect_probe(p):
    import paramiko
    host = public_host(p['host']); sp = port(p.get('ssh_port',22))
    # Read host key without authentication. No password goes to an unconfirmed host.
    sock = socket.create_connection((host,sp),timeout=10)
    t = paramiko.Transport(sock)
    try:
        t.start_client(timeout=10); key = t.get_remote_server_key()
        fp = 'SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        token = secrets.token_urlsafe(32)
        with PROBE_LOCK:
            for k,v in list(PROBES.items()):
                if v['expires'] < now():PROBES.pop(k,None)
            if len(PROBES)>=30:raise Error('检查请求过多，请稍后再试。')
            PROBES[token] = {'host':host,'port':sp,'key_type':key.get_name(),
                             'key':key.get_base64(),'fingerprint':fp,'expires':now()+600}
        return {'probe_id':token,'fingerprint':fp,'expires':now()+600}
    finally:t.close();sock.close()

def initialise(p, task):
    import paramiko
    with PROBE_LOCK:probe = PROBES.pop(p.get('probe_id',''),None)
    if not probe or probe['expires']<now():raise Error('指纹检查已过期，请重新检查。')
    if p.get('fingerprint')!=probe['fingerprint']:raise Error('必须确认刚刚核对的指纹。')
    username = p.get('ssh_user','root')
    if username!='root':raise Error('首版网页初始化仅支持 root；非 root 节点请通过命令行接管。')
    dom=domain(p['domain']);sni=domain(p.get('sni','www.microsoft.com'))
    name=label(p['name']);tags=labels(p['tags']);email=p.get('email','')
    if not tags:raise Error('至少需要一个节点标签。')
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email):raise Error('证书邮箱格式无效。')
    client=paramiko.SSHClient()
    key=paramiko.PKey.from_type_string(probe['key_type'],base64.b64decode(probe['key']))
    hostkey_name=probe['host'] if probe['port']==22 else '['+probe['host']+']:'+str(probe['port'])
    client.get_host_keys().add(hostkey_name,key.get_name(),key)
    progress(task,'验证密码和主机指纹')
    try:
        client.connect(probe['host'],port=probe['port'],username=username,password=p.pop('password'),
                       allow_agent=False,look_for_keys=False,timeout=15,auth_timeout=15,banner_timeout=15)
        progress(task,'配置专属管理密钥')
        nid=uid();keydir=ctl.HOME/'node-keys';keydir.mkdir(mode=0o700,exist_ok=True)
        private=keydir/nid
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(private)],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        pub=private.with_suffix('.pub').read_text().strip()
        # Fixed remote program; stdin carries only a generated public key, never a password.
        command="umask 077; mkdir -p /root/.ssh; chmod 700 /root/.ssh; cat >> /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys"
        stdin,stdout,stderr=client.exec_command(command,timeout=15)
        stdin.write(pub+'\n');stdin.channel.shutdown_write()
        if stdout.channel.recv_exit_status()!=0:raise Error('管理密钥配置失败。')
    finally:client.close()
    with open(ctl.HOME/'known_hosts','a') as f:
        f.write(hostkey_name+' '+probe['key_type']+' '+probe['key']+'\n')
    os.chmod(ctl.HOME/'known_hosts',0o600)
    record={'id':nid,'name':name,'host':probe['host'],'ssh_port':probe['port'],'ssh_user':username,
            'ssh_key':str(private),'mode':'ssh','domain':dom,'sni':sni,'email':email}
    with lock(ctl.HOME/'lock'):
        d=ctl.database()
        try:
            if d.execute('SELECT 1 FROM nodes WHERE host=? AND state!="deleted"',(record['host'],)).fetchone():
                raise Error('该 IP 已登记，请勿重复初始化。')
            if p.get('install',True):
                progress(task,'安装依赖、代理程序与证书（可能需要数分钟）');ctl.install_new(record)
            progress(task,'上传节点管理程序');ctl.bootstrap(record)
            inspect=ctl.rpc(record,{'op':'inspect'})
            if inspect['domain']!=dom:raise Error('节点域名与现有部署不一致。')
            progress(task,'构建并验证逐用户流量统计（可能需要数分钟）')
            enrolled=ctl.rpc(record,{'op':'enrol','controller':ctl.data(d,'controller')})
            if not enrolled['stats_ready']:raise Error('逐用户计量验证未通过。')
            with d:d.execute('''INSERT INTO nodes(id,name,domain,host,ssh_port,ssh_user,ssh_key,mode,sni,tags,state,
                revision,status,stats_ready,version,ports,last_online) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (nid,name,dom,record['host'],record['ssh_port'],username,str(private),'ssh',sni,canonical(tags),
                 'active',None,'待同步',1,enrolled['version'],canonical(enrolled['ports']),now()))
            progress(task,'同步用户授权并发布订阅');ctl.sync_one(d,ctl.node(d,nid))
        finally:d.close()

def operate(kind,p,task):
    if kind=='node.initialise':return initialise(p,task)
    action=kind.split('.')
    with lock(ctl.HOME/'lock'):
        d=ctl.database()
        try:
            if kind=='reconcile':ctl.reconcile(d);return
            if len(action)!=2:raise Error('无效操作。')
            entity,verb=action
            args=SimpleNamespace(action=verb,id=p.get('id'),sni=p.get('sni'))
            if entity=='node' and verb in ('enable','disable','delete','sync','sni','edit'):
                if verb=='edit':
                    n=ctl.node(d,args.id);name=label(p['name']);ts=labels(p['tags'])
                    with d:d.execute('UPDATE nodes SET name=?,tags=?,revision=NULL WHERE id=?',(name,canonical(ts),n['id']))
                    ctl.reconcile(d)
                else:ctl.node_cmd(d,args)
            elif entity=='plan' and verb in ('add','edit'):
                quota=int(p['quota_gb'])*1024**3;days=int(p['days'])
                if not 0<quota<2**60 or not 0<days<=36500:raise Error('额度或天数无效。')
                values=(label(p['name']),canonical(labels(p.get('tags',''))),quota,days,label(p['price']))
                mode=p.get('access_mode','tags')
                if mode not in ('tags','selected'):raise Error('节点分配模式无效。')
                selected=validate_node_ids(d,p.get('node_ids',[]))
                pid=uid() if verb=='add' else ctl.plan(d,args.id)['id']
                with d:
                    if verb=='add':d.execute('INSERT INTO plans VALUES(?,?,?,?,?,?)',(pid,)+values)
                    else:d.execute('UPDATE plans SET name=?,tags=?,quota=?,days=?,price=? WHERE id=?',values+(pid,))
                    if 'access_mode' in p or verb=='add':
                        d.execute('INSERT OR REPLACE INTO plan_access VALUES(?,?)',(pid,mode))
                        d.execute('DELETE FROM plan_nodes WHERE plan_id=?',(pid,))
                        d.executemany('INSERT INTO plan_nodes VALUES(?,?)',[(pid,nid) for nid in selected])
                ctl.reconcile(d)
            elif entity=='user' and verb=='edit':
                u=ctl.user(d,args.id);plan=ctl.plan(d,p['plan_id']);name=label(p['name'])
                quota=0 if u['is_admin'] else int(float(p['quota_gb'])*1024**3)
                expires=0 if u['is_admin'] else int(p['expires'])
                if not u['is_admin'] and (not 0<quota<2**60 or expires<=u['started']):raise Error('流量额度或结束时间无效。')
                rules=p.get('node_rules',{})
                if not isinstance(rules,dict) or any(v not in ('allow','deny') for v in rules.values()):raise Error('用户节点规则无效。')
                validate_node_ids(d,list(rules))
                with d:
                    d.execute('UPDATE users SET name=?,plan_id=?,quota=?,expires=? WHERE id=?',(name,plan['id'],quota,expires,u['id']))
                    d.execute('DELETE FROM user_node_rules WHERE user_id=?',(u['id'],))
                    d.executemany('INSERT INTO user_node_rules VALUES(?,?,?)',[(u['id'],nid,rule) for nid,rule in rules.items()])
                ctl.reconcile(d)
            elif entity=='user' and verb in ('add','add-admin','renew','disable','enable','delete','rotate-token'):
                # Adapt the existing fixed CLI prompts; one sequential worker only.
                prompts={'用户名':p.get('name'),'套餐名称或 ID':p.get('plan_id'),
                         '已收款金额及货币（未收费填 0）':p.get('amount','0'),
                         '已收款金额及货币':p.get('amount','0'),'付款备注':p.get('note','网页操作')}
                original=ctl.ask
                def answer(prompt,default=None):
                    value=prompts.get(prompt,default)
                    if value is None:raise Error('缺少字段：'+prompt)
                    return label(str(value))
                ctl.ask=answer
                try:ctl.user_cmd(d,args)
                finally:ctl.ask=original
            else:raise Error('不支持的操作。')
        finally:d.close()

def validate_node_ids(d,values):
    if not isinstance(values,list) or len(values)>1000 or any(not isinstance(v,str) for v in values):raise Error('节点列表无效。')
    valid={r[0] for r in d.execute('SELECT id FROM nodes WHERE state!="deleted"')}
    if not set(values)<=valid:raise Error('选中的节点已删除或不存在，请刷新页面。')
    return sorted(set(values))

KINDS={'reconcile','node.initialise','node.enable','node.disable','node.delete','node.sync','node.sni','node.edit',
       'plan.add','plan.edit','user.add','user.add-admin','user.edit','user.renew','user.disable','user.enable','user.delete','user.rotate-token'}

def worker():
    while True:
        task,kind,p=JOBS.get()
        try:
            progress(task,'等待管理锁')
            # Suppress legacy CLI output: may include internal details; progress is explicit.
            with contextlib.redirect_stdout(io.StringIO()):operate(kind,p,task)
            progress(task,'完成','succeeded')
        except Exception as e:
            # Never persist raw SSH/subprocess errors or supplied secrets.
            message=str(e) if isinstance(e,(Error,ValueError)) else '操作失败；请检查节点状态，必要时重新输入 SSH 密码。'
            for k in ('password','token'):
                if p.get(k):message=message.replace(str(p[k]),'[已隐藏]')
            progress(task,'失败','failed',message[:240])
        finally:p.clear();JOBS.task_done()

def dispatch(req):
    op=req.get('op');p=req.get('params',{})
    if op=='snapshot':return snapshot()
    if op=='tasks':
        with database() as d:return [dict(r) for r in d.execute('SELECT * FROM tasks ORDER BY created DESC LIMIT 100')]
    if op=='audit':
        with database() as d:return [dict(r) for r in d.execute('SELECT * FROM audit ORDER BY created DESC LIMIT 200')]
    if op=='probe':return connect_probe(p)
    if op=='subscription':
        with lock(ctl.HOME/'lock'):
            d=ctl.database()
            try:
                u=ctl.user(d,p['id']);base=ctl.subscription_base(d,u)
                return {fmt:base+'?format='+fmt for fmt in FORMATS}
            finally:d.close()
    if op!='submit' or req.get('kind') not in KINDS:raise Error('无效请求。')
    if JOBS.full():raise Error('任务队列已满。')
    task=uid();kind=req['kind'];actor=safe_actor(req.get('actor','admin'))
    if kind=='node.initialise' and not p.get('confirm_fingerprint'):raise Error('请先核对 SSH 指纹。')
    if kind=='node.initialise':
        # Reauthentication credentials belong only to the HTTP auth layer.
        p.pop('admin_password',None);p.pop('code',None)
    with database() as d:
        d.execute('INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?)',(task,kind,actor,now(),now(),'queued','等待执行',''))
        d.execute('INSERT INTO audit VALUES(?,?,?,?,?)',(uid(),actor,kind,str(p.get('id','new'))[:80],now()))
    JOBS.put_nowait((task,kind,p));return {'task_id':task}

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        try:
            raw=self.rfile.readline(65537)
            if len(raw)>65536:raise Error('请求过大。')
            result=dispatch(json.loads(raw))
            response={'ok':True,'data':result}
        except Exception as e:
            response={'ok':False,'error':str(e)[:240] if isinstance(e,Error) else '请求失败。'}
        self.wfile.write((json.dumps(response,ensure_ascii=False)+'\n').encode())

if __name__=='__main__':
    import grp
    os.umask(0o077)
    with database() as d:
        d.execute("UPDATE tasks SET state='failed',step='服务重启',error='任务已中断，请核对节点后重试。' WHERE state IN ('queued','running')")
    Path(SOCKET).parent.mkdir(parents=True,exist_ok=True)
    if Path(SOCKET).exists():Path(SOCKET).unlink()
    class Server(socketserver.ThreadingUnixStreamServer):daemon_threads=True
    server=Server(SOCKET,Handler)
    os.chown(SOCKET,0,grp.getgrnam('sb-console').gr_gid);os.chmod(SOCKET,0o660)
    threading.Thread(target=worker,daemon=True).start()
    server.serve_forever()
