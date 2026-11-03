#!/usr/bin/env python3
"""Administrator control plane. Keeps secrets in a root-only SQLite database."""
import argparse
from datetime import datetime
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from urllib.parse import quote
from common import Error, canonical, db_open, domain, label, labels, lock, now, port, run, uid, write_json

ROOT=Path(__file__).resolve().parent.parent
HOME=Path(os.environ.get('SB_MANAGER_HOME','/var/lib/sb-manager'))
PUBLIC_DIR=Path(os.environ.get('SB_MANAGER_PUBLIC','/var/lib/sb-subscription'))
DB=HOME/'manager.sqlite'
BUNDLE=ROOT

def database():
    HOME.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(HOME,0o700)
    d=db_open(DB)
    d.executescript('''
    CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY,name TEXT NOT NULL,domain TEXT NOT NULL,host TEXT NOT NULL,
      ssh_port INTEGER NOT NULL,ssh_user TEXT NOT NULL,ssh_key TEXT NOT NULL,mode TEXT NOT NULL,
      sni TEXT NOT NULL,tags TEXT NOT NULL,state TEXT NOT NULL,revision TEXT,status TEXT,
      stats_ready INTEGER NOT NULL DEFAULT 0,version TEXT,ports TEXT,last_online INTEGER,last_sample INTEGER,epoch TEXT);
    CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY,name TEXT UNIQUE NOT NULL,tags TEXT NOT NULL,
      quota INTEGER NOT NULL,days INTEGER NOT NULL,price TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT UNIQUE NOT NULL,plan_id TEXT NOT NULL,
      token TEXT UNIQUE NOT NULL,state TEXT NOT NULL,cycle TEXT NOT NULL,started INTEGER NOT NULL,
      expires INTEGER NOT NULL,quota INTEGER NOT NULL,upload INTEGER NOT NULL DEFAULT 0,
      download INTEGER NOT NULL DEFAULT 0,is_admin INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(plan_id) REFERENCES plans(id));
    CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,amount TEXT NOT NULL,
      note TEXT NOT NULL,created INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS grants(node_id TEXT NOT NULL,principal TEXT NOT NULL,outs TEXT NOT NULL,
      PRIMARY KEY(node_id,principal));
    CREATE TABLE IF NOT EXISTS samples(node_id TEXT NOT NULL,principal TEXT NOT NULL,epoch TEXT NOT NULL,
      up INTEGER NOT NULL,down INTEGER NOT NULL,PRIMARY KEY(node_id,principal));
    CREATE TABLE IF NOT EXISTS history(user_id TEXT NOT NULL,cycle TEXT NOT NULL,up INTEGER NOT NULL,
      down INTEGER NOT NULL,started INTEGER NOT NULL,ended INTEGER NOT NULL);
    ''')
    if 'is_admin' not in {r[1] for r in d.execute('PRAGMA table_info(users)')}:
        with d:d.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0')
    with d:d.execute("INSERT OR IGNORE INTO meta VALUES('controller',?)",(uid(),))
    return d

def data(d,key):return d.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone()[0]

def ask(prompt,default=None):
    text=input(prompt+(' ['+str(default)+']' if default is not None else '')+': ').strip()
    if not text and default is not None:return str(default)
    if not text:raise Error('缺少必填值：'+prompt)
    return text

def node(d,nid):
    r=d.execute('SELECT * FROM nodes WHERE id=?',(nid,)).fetchone()
    if not r:raise Error('节点不存在。')
    return r

def plan(d,pid):
    r=d.execute('SELECT * FROM plans WHERE id=? OR name=?',(pid,pid)).fetchone()
    if not r:raise Error('套餐不存在。')
    return r

def user(d,who):
    r=d.execute('SELECT * FROM users WHERE id=? OR name=?',(who,who)).fetchone()
    if not r:raise Error('用户不存在。')
    return r

def subscription_base(d,u):
    return 'https://'+data(d,'subscription_domain')+('/admin/' if u['is_admin'] else '/sub/')+u['token']

def human_bytes(value):
    value=max(0,int(value))
    if value >= 1024**3:return f'{value/1024**3:.2f} GB'
    return f'{value/1024**2:.2f} MB'

def human_time(value):
    return '永久' if not value else datetime.fromtimestamp(int(value)).astimezone().strftime('%Y-%m-%d %H:%M')

def assigned_nodes(d,u):
    principal='m_'+u['id']+'_'+u['cycle']
    result=[]
    for r in d.execute('''SELECT nodes.name,nodes.domain,nodes.state,nodes.status,grants.outs
                          FROM grants JOIN nodes ON nodes.id=grants.node_id
                          WHERE grants.principal=? AND nodes.state!="deleted"
                          ORDER BY nodes.name''',(principal,)):
        protocols=sorted({o.get('type','?') for o in json.loads(r['outs'])})
        result.append({'name':r['name'],'domain':r['domain'],'state':r['state'],
                       'status':r['status'],'protocols':protocols})
    return result

def print_user(d,u,include_id=True):
    if include_id:print('ID：'+u['id'])
    print('用户：'+u['name']+'　状态：'+u['state']+('　类型：管理员' if u['is_admin'] else ''))
    print('时间：'+human_time(u['started'])+' → '+human_time(u['expires']))
    used=human_bytes(u['upload']+u['download'])
    print('流量：'+used+' / '+('不限流量' if u['is_admin'] else human_bytes(u['quota'])))
    nodes=assigned_nodes(d,u)
    if not nodes:print('节点：尚未同步到任何节点')
    for n in nodes:
        suffix='' if n['state']=='active' else ' ['+n['state']+'，'+str(n['status'])+']'
        print('节点：'+n['name']+' ('+n['domain']+')　协议：'+(', '.join(n['protocols']) or '无')+suffix)

def effective(d,n):
    tags=set(json.loads(n['tags']))
    if n['state']!='active' or not tags or not n['stats_ready']:return []
    result=[]
    for u in d.execute('SELECT users.*,plans.tags AS plan_tags FROM users JOIN plans ON users.plan_id=plans.id'):
        if u['state']!='active':continue
        if not u['is_admin'] and (u['expires']<=now() or u['upload']+u['download']>=u['quota']):continue
        if tags.intersection(json.loads(u['plan_tags'])):
            result.append({'principal':'m_'+u['id']+'_'+u['cycle'],'name':u['name']})
    return result

def revision(d,n):
    return hashlib.sha256(canonical(effective(d,n)).encode()).hexdigest()

def ssh_args(n):
    key=Path(n['ssh_key'])
    if not key.is_file():raise Error('SSH 私钥不存在。')
    if not Path(n['host']).name == n['host'] or not re.fullmatch(r'[A-Za-z0-9.:-]+',n['host']):raise Error('SSH 地址无效。')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]*',n['ssh_user']):raise Error('SSH 用户名无效。')
    return ['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','UserKnownHostsFile='+str(HOME/'known_hosts'),'-o','IdentitiesOnly=yes',
            '-o','ConnectTimeout=10','-p',str(n['ssh_port']),'-i',str(key),
            '--',n['ssh_user']+'@'+n['host']]

def rpc(n,payload):
    if n['mode']=='local':cmd=['python3',str(BUNDLE/'lib/node.py')]
    else:cmd=ssh_args(n)+[('' if n['ssh_user']=='root' else 'sudo -n ')+'python3 /opt/sb-node/lib/node.py']
    raw=run(cmd,canonical(payload).encode(),timeout=2400 if payload['op']=='enrol' else 90)
    try:result=json.loads(raw)
    except ValueError as e:raise Error('节点响应无效。') from e
    if not result.get('ok'):raise Error(result.get('error','节点操作失败。'))
    return result['result']

def setup_ssh_key(host,ssh_port,expected):
    if not re.fullmatch(r'[A-Za-z0-9.:-]+',host):raise Error('SSH 地址格式无效。')
    scan=run(['ssh-keyscan','-T','10','-p',str(ssh_port),host],timeout=20)
    entries=[line for line in scan.decode().splitlines() if line and not line.startswith('#')]
    if not entries:raise Error('无法读取 SSH 主机公钥。')
    matched=[]
    for line in entries:
        with tempfile.NamedTemporaryFile(mode='w',delete=False) as f:
            f.write(line+'\n');path=f.name
        try:finger=run(['ssh-keygen','-lf',path,'-E','sha256']).decode()
        finally:os.unlink(path)
        if expected in finger:matched.append(line)
    if not matched:raise Error('SSH 主机指纹不匹配；请从服务商控制台独立核对。')
    with open(HOME/'known_hosts','a') as f:f.write('\n'.join(matched)+'\n')
    os.chmod(HOME/'known_hosts',0o600)

def bootstrap(n):
    if n['mode']=='local':return
    # Transfer audited local source files without embedding credentials in a command line.
    import base64,tarfile,io
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w') as t:
        for path in [BUNDLE/'lib/common.py',BUNDLE/'lib/formats.py',BUNDLE/'lib/node.py',BUNDLE/'build-stats.sh']:
            t.add(path,arcname=('lib/' if path.parent.name=='lib' else '')+path.name)
    receiver='''import os,sys,tarfile,io,pathlib
p=pathlib.Path('/opt/sb-node');p.mkdir(mode=0o700,parents=True,exist_ok=True)
b=io.BytesIO(sys.stdin.buffer.read(2_000_000))
with tarfile.open(fileobj=b) as t:
 for m in t:
  if m.name not in ('lib/common.py','lib/formats.py','lib/node.py','build-stats.sh') or not m.isfile():raise SystemExit(1)
  f=p/m.name;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(t.extractfile(m).read());f.chmod(0o700 if f.suffix=='.sh' else 0o600)
'''
    # Encoded fixed receiver avoids remote-shell quoting of user input.
    encoded=base64.b64encode(receiver.encode()).decode()
    command=("" if n['ssh_user']=='root' else "sudo -n ")+"python3 -c 'import base64;exec(base64.b64decode(\""+encoded+"\"))'"
    run(ssh_args(n)+[command],buf.getvalue())

def install_new(n):
    if n['mode']=='local':raise Error('主服务器请先运行基础安装脚本，再选择接管。')
    # Upload then run fixed installer; no use of a shell-expanded user domain.
    source=BUNDLE/'install-sing-box-vps.sh'
    argv=['bash','-s','--','--domain',n['domain'],'--email',n['email'],'--sni',n['sni']]
    remote=('' if n['ssh_user']=='root' else 'sudo -n ')+' '.join(shlex.quote(x) for x in argv)
    run(ssh_args(n)+[remote],source.read_bytes(),timeout=2400)

def sync_one(d,n):
    desired=effective(d,n)
    rev=revision(d,n)
    response=rpc(n,{'op':'apply','controller':data(d,'controller'),'revision':rev,
                    'domain':n['domain'],'name':n['name'],'grants':desired})
    accept_stats(d,n,response)
    with d:
        d.execute('UPDATE nodes SET revision=?,status=?,last_online=? WHERE id=?',(rev,'已同步',now(),n['id']))
        d.execute('DELETE FROM grants WHERE node_id=?',(n['id'],))
        for name,outs in response['grants'].items():
            d.execute('INSERT INTO grants VALUES(?,?,?)',(n['id'],name,canonical(outs)))
        if n['state']=='deleting':
            d.execute("UPDATE nodes SET state='deleted',status='已删除' WHERE id=?",(n['id'],))
    publish(d)

def accept_stats(d,n,response):
    epoch=response['epoch']
    old_epoch=n['epoch']
    if old_epoch and old_epoch!=epoch:
        with d:d.execute("UPDATE nodes SET stats_ready=0,status='统计代次变化，待人工核对' WHERE id=?",(n['id'],))
        raise Error('节点统计数据库已重置，停止计费授权，需人工核对旧用量。')
    with d:
        for p,v in response['totals'].items():
            if not re.fullmatch(r'm_[0-9a-f]{32}_[0-9a-f]{32}',p):continue
            previous=d.execute('SELECT * FROM samples WHERE node_id=? AND principal=?',(n['id'],p)).fetchone()
            du=v['up']-previous['up'] if previous else v['up']
            dd=v['down']-previous['down'] if previous else v['down']
            if du<0 or dd<0:raise Error('节点累计流量回退，停止自动结算。')
            userid,cycle=p.split('_')[1:]
            u=d.execute('SELECT * FROM users WHERE id=?',(userid,)).fetchone()
            if u and u['cycle']==cycle:
                d.execute('UPDATE users SET upload=upload+?,download=download+? WHERE id=?',(du,dd,userid))
            else:
                d.execute('UPDATE history SET up=up+?,down=down+? WHERE user_id=? AND cycle=?',(du,dd,userid,cycle))
            d.execute('INSERT OR REPLACE INTO samples VALUES(?,?,?,?,?)',(n['id'],p,epoch,v['up'],v['down']))
        d.execute('UPDATE nodes SET epoch=?,last_sample=?,last_online=?,status=? WHERE id=?',
                  (epoch,response['sample_at'],now(),'在线',n['id']))

def poll_one(d,n):
    response=rpc(n,{'op':'poll'})
    accept_stats(d,n,response)
    reported=response.get('status',{}).get('sni')
    if reported and reported!=n['sni']:
        with d:d.execute('UPDATE nodes SET sni=?,revision=NULL,status=? WHERE id=?',(reported,'SNI 已变化，待刷新订阅',n['id']))

def publish(d):
    items=[]
    for u in d.execute('SELECT * FROM users'):
        outs=[]
        eligible=u['state']=='active' and (u['is_admin'] or (u['expires']>now() and u['upload']+u['download']<u['quota']))
        if eligible:
            p='m_'+u['id']+'_'+u['cycle']
            for n in d.execute('SELECT * FROM nodes WHERE state="active" AND stats_ready=1'):
                if n['revision']!=revision(d,n):continue
                g=d.execute('SELECT outs FROM grants WHERE node_id=? AND principal=?',(n['id'],p)).fetchone()
                if g:outs.extend(json.loads(g[0]))
        items.append({'token_hash':hashlib.sha256(u['token'].encode()).hexdigest(),
                      'name':u['name'],'started':u['started'],'expires':0 if u['is_admin'] else u['expires'],
                      'upload':u['upload'],'download':u['download'],'quota':0 if u['is_admin'] else u['quota'],
                      'is_admin':bool(u['is_admin']),'outs':outs})
    PUBLIC_DIR.mkdir(parents=True,exist_ok=True)
    os.chmod(PUBLIC_DIR,0o750)
    dest=PUBLIC_DIR/'published.json';write_json(dest,items)
    os.chmod(dest,0o640)
    # Public server account only reads a sanitized snapshot, never the billing database.
    import grp
    try:
        gid=grp.getgrnam('sb-sub').gr_gid
        os.chown(PUBLIC_DIR,0,gid)
        os.chown(dest,0,gid)
    except KeyError:pass

def reconcile(d):
    for n in d.execute("SELECT * FROM nodes WHERE state!='deleted'").fetchall():
        try:
            poll_one(d,n)
            n=node(d,n['id'])
            if n['revision']!=revision(d,n) or n['state']=='deleting':sync_one(d,n)
        except Exception as e:
            with d:d.execute('UPDATE nodes SET status=? WHERE id=?',('待处理：'+str(e)[:140],n['id']))
    publish(d)

def affected(d,old,new):
    oldset,newset=set(old),set(new)
    plans=[];users=[]
    for p in d.execute('SELECT * FROM plans'):
        t=set(json.loads(p['tags']))
        if bool(t&oldset)!=bool(t&newset):
            plans.append(p['name'])
            users.extend([r[0] for r in d.execute('SELECT name FROM users WHERE plan_id=?',(p['id'],))])
    print('受影响套餐：'+(', '.join(plans) or '无')+'；用户数：'+str(len(users)))

def add_node(d):
    name=label(ask('节点名称'));host=ask('SSH 地址，主服务器填 local')
    mode='local' if host=='local' else 'ssh'
    if d.execute('SELECT 1 FROM nodes WHERE host=? AND state!="deleted"',(host,)).fetchone():
        raise Error('这台服务器已登记为节点；请编辑或同步现有节点。')
    dom=domain(ask('客户端连接域名'))
    sni=domain(ask('REALITY SNI','www.microsoft.com'))
    tags=labels(ask('标签，逗号分隔'))
    if mode=='ssh':
        sp=port(ask('SSH 端口','22'));su=ask('SSH 用户','root');key=ask('SSH 私钥绝对路径')
        email=ask('Let’s Encrypt 联系邮箱')
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email):raise Error('邮箱格式无效。')
        expected=ask('从服务商控制台核对的 SSH SHA256 指纹')
        if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',expected):raise Error('指纹格式无效。')
        setup_ssh_key(host,sp,expected)
    else:sp=22;su='root';key='';email=''
    nid=uid();record={'id':nid,'name':name,'host':host,'ssh_port':sp,'ssh_user':su,'ssh_key':key,
                      'mode':mode,'domain':dom,'sni':sni,'email':email}
    if mode=='ssh':
        installed=ask('远端已有本套安装吗？输入 yes 接管，no 全新安装','yes')
        if installed=='no':install_new(record)
        elif installed!='yes':raise Error('只能填写 yes/no。')
        bootstrap(record)
    inspect=rpc(record,{'op':'inspect'})
    if inspect['domain']!=dom:raise Error('远端证书域名与填写域名不一致。')
    enrolled=rpc(record,{'op':'enrol','controller':data(d,'controller')})
    if not enrolled['stats_ready']:raise Error('未通过逐用户计量验证。')
    with d:d.execute('INSERT INTO nodes(id,name,domain,host,ssh_port,ssh_user,ssh_key,mode,sni,tags,state,revision,status,stats_ready,version,ports,last_online,last_sample) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
          (nid,name,dom,host,sp,su,key,mode,sni,canonical(tags),'active',None,'待同步',1,enrolled['version'],canonical(enrolled['ports']),now(),None))
    try:sync_one(d,node(d,nid))
    except Exception as e:print('节点已接管，首次同步待处理：'+str(e))
    print('节点 ID：'+nid)

def edit_node(d,n):
    name=label(ask('节点名称',n['name']))
    tags=labels(ask('标签，逗号分隔',','.join(json.loads(n['tags']))))
    affected(d,json.loads(n['tags']),tags)
    # The node name is embedded in every exported outbound tag, so a rename
    # must invalidate the applied revision even when grants are unchanged.
    with d:d.execute('UPDATE nodes SET name=?,tags=?,revision=NULL,status=? WHERE id=?',(name,canonical(tags),'待同步',n['id']))
    reconcile(d)

def change_sni(d,n,target):
    target=domain(target)
    result=rpc(n,{'op':'set_sni','controller':data(d,'controller'),'sni':target})
    if result.get('sni')!=target:raise Error('节点返回的 SNI 不一致。')
    with d:d.execute('UPDATE nodes SET sni=?,revision=NULL,status=? WHERE id=?',(target,'SNI 已更新，待同步',n['id']))
    sync_one(d,node(d,n['id']))

def node_cmd(d,args):
    if args.action=='list':
        for n in d.execute('SELECT * FROM nodes WHERE state!="deleted"'):
            print(n['id'],n['name'],','.join(json.loads(n['tags'])),n['state'],n['status'],n['last_sample'])
    elif args.action=='add':add_node(d)
    else:
        n=node(d,args.id)
        if args.action=='show':
            print(canonical({k:n[k] for k in n.keys() if k!='ssh_key'}))
            print('受管用户数：',d.execute('SELECT COUNT(*) FROM grants WHERE node_id=?',(n['id'],)).fetchone()[0])
            print('累计流量：',d.execute('SELECT COALESCE(SUM(up),0)+COALESCE(SUM(down),0) FROM samples WHERE node_id=?',(n['id'],)).fetchone()[0])
        elif args.action=='edit':edit_node(d,n)
        elif args.action=='sync':sync_one(d,n)
        elif args.action=='sni':change_sni(d,n,args.sni)
        elif args.action in ('disable','enable','delete'):
            state={'disable':'disabled','enable':'active','delete':'deleting'}[args.action]
            with d:d.execute('UPDATE nodes SET state=?,status=? WHERE id=?',(state,'待同步',n['id']))
            reconcile(d)

def plan_cmd(d,args):
    if args.action=='list':
        for p in d.execute('SELECT * FROM plans'):print(p['id'],p['name'],p['tags'],p['quota'],p['days'],p['price'])
        return
    if args.action in ('add','edit'):
        old=plan(d,args.id) if args.action=='edit' else None
        name=label(ask('套餐名称',old['name'] if old else None))
        tags=labels(ask('可用节点标签，逗号分隔',','.join(json.loads(old['tags'])) if old else None))
        quota=int(ask('总上下行额度 GB',str(old['quota']//(1024**3)) if old else None))*1024**3
        days=int(ask('有效天数',str(old['days']) if old else None))
        price=ask('手动收款价格与货币',old['price'] if old else None)
        if quota<=0 or days<=0:raise Error('额度和天数须大于零。')
        with d:
            if old:d.execute('UPDATE plans SET name=?,tags=?,quota=?,days=?,price=? WHERE id=?',(name,canonical(tags),quota,days,price,old['id']))
            else:d.execute('INSERT INTO plans VALUES(?,?,?,?,?,?)',(uid(),name,canonical(tags),quota,days,price))
        reconcile(d)

def user_cmd(d,args):
    if args.action=='list':
        rows=list(d.execute('SELECT * FROM users ORDER BY name'))
        if not rows:print('暂无用户。')
        for index,u in enumerate(rows):
            if index:print('─'*48)
            print_user(d,u)
        return
    if args.action in ('add','add-admin'):
        name=label(ask('用户名'));p=plan(d,ask('套餐名称或 ID'));ts=now();user_id=uid()
        admin=args.action=='add-admin'
        amount='0' if admin else ask('已收款金额及货币（未收费填 0）')
        note='管理员专属订阅' if admin else ask('付款备注','初次开通')
        with d:
            d.execute('INSERT INTO users(id,name,plan_id,token,state,cycle,started,expires,quota,is_admin) VALUES(?,?,?,?,?,?,?,?,?,?)',
                      (user_id,name,p['id'],secrets.token_urlsafe(48),'active',uid(),ts,
                       0 if admin else ts+p['days']*86400,0 if admin else p['quota'],int(admin)))
            d.execute('INSERT INTO payments VALUES(?,?,?,?,?)',(uid(),user_id,amount,note,ts))
        reconcile(d);print('用户 ID：'+user_id);return
    u=user(d,args.id)
    if args.action=='show':
        print_user(d,u)
        base=subscription_base(d,u)
        print('订阅：')
        for fmt in ('singbox','mihomo','base64','links'):print(fmt,base+'?format='+fmt)
    elif args.action=='renew':
        if u['is_admin']:raise Error('管理员订阅无需续费。')
        p=plan(d,u['plan_id']);amount=ask('已收款金额及货币');note=ask('付款备注','手动收款')
        with d:
            d.execute('INSERT INTO history VALUES(?,?,?,?,?,?)',(u['id'],u['cycle'],u['upload'],u['download'],u['started'],now()))
            d.execute('UPDATE users SET cycle=?,started=?,expires=?,quota=?,upload=0,download=0,state="active" WHERE id=?',
                      (uid(),now(),now()+p['days']*86400,p['quota'],u['id']))
            d.execute('INSERT INTO payments VALUES(?,?,?,?,?)',(uid(),u['id'],amount,note,now()))
        reconcile(d)
    elif args.action in ('disable','enable','delete'):
        state={'disable':'disabled','enable':'active','delete':'deleted'}[args.action]
        with d:d.execute('UPDATE users SET state=? WHERE id=?',(state,u['id']))
        reconcile(d)
    elif args.action=='rotate-token':
        with d:d.execute('UPDATE users SET token=? WHERE id=?',(secrets.token_urlsafe(48 if u['is_admin'] else 32),u['id']))
        publish(d)
    elif args.action=='qr':
        if args.format not in ('singbox','mihomo','base64','links'):raise Error('二维码订阅格式无效。')
        base=subscription_base(d,u)+'?format='+args.format
        print('\n紧凑二维码（请扩大终端窗口后扫描）：')
        subprocess.run(['qrencode','-t','UTF8','-m','1'],input=base.encode(),check=True)
        if args.output:
            run(['qrencode','-s','8','-m','4','-o',args.output],base.encode())
            os.chmod(args.output,0o600)
            print('高清 PNG 已保存：'+args.output)


def menu(d):
    choices={
      '1':('node','list'),'2':('node','add'),'3':('node','show'),'4':('node','edit'),
      '5':('node','sync'),'6':('node','disable'),'7':('node','enable'),'8':('node','delete'),
      '9':('plan','list'),'10':('plan','add'),'11':('plan','edit'),
      '12':('user','list'),'13':('user','add'),'14':('user','show'),
      '15':('user','renew'),'16':('user','disable'),'17':('user','enable'),
      '18':('user','delete'),'19':('user','qr'),'20':('user','rotate-token'),
      '22':('user','add-admin')}
    while True:
        print('\n节点: 1 列表 2 新增 3 详情 4 编辑 5 同步 6 停用 7 启用 8 删除')
        print('套餐: 9 列表 10 新增 11 编辑')
        print('用户: 12 列表 13 新增 14 详情 15 续费 16 停用 17 启用 18 删除 19 二维码 20 换订阅令牌 22 新增管理员')
        print('21 全部对账  0 退出')
        choice=input('选择：').strip()
        if choice=='0':return
        if choice=='21':reconcile(d);continue
        if choice not in choices:print('无效选择');continue
        kind,action=choices[choice]
        needs_id=action not in ('list','add','add-admin')
        item=ask('节点 ID' if kind=='node' else '套餐/用户 ID 或名称') if needs_id else None
        a=argparse.Namespace(action=action,id=item,format='singbox',output=None)
        if action=='qr':a.format=ask('订阅格式 singbox/mihomo/base64/links','singbox')
        try:{'node':node_cmd,'plan':plan_cmd,'user':user_cmd}[kind](d,a)
        except (Error,ValueError,sqlite3.Error) as e:print('错误：'+str(e))

def main():
    if os.geteuid()!=0 and not os.environ.get('SB_MANAGER_TEST'):raise Error('管理命令需要 root。')
    os.umask(0o077)
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest='kind')
    for name,actions in [('node',['list','show','add','edit','sync','disable','enable','delete','sni']),
                         ('plan',['list','add','edit']),
                         ('user',['list','show','add','add-admin','renew','disable','enable','delete','rotate-token','qr'])]:
        p=sub.add_parser(name);a=p.add_subparsers(dest='action',required=True)
        for act in actions:
            q=a.add_parser(act)
            if act in ('show','edit','sync','disable','enable','delete','renew','rotate-token','qr','sni'):q.add_argument('id')
            if act=='sni':q.add_argument('sni')
            if act=='qr':q.add_argument('--format',choices=['singbox','mihomo','base64','links'],default='singbox');q.add_argument('--output')
    sub.add_parser('reconcile');setup=sub.add_parser('setup');setup.add_argument('--domain',required=True)
    args=parser.parse_args()
    with lock(HOME/'lock'):
        d=database()
        try:
            if args.kind=='setup':
                with d:d.execute("INSERT OR REPLACE INTO meta VALUES('subscription_domain',?)",(domain(args.domain),))
                publish(d)
            elif args.kind=='node':node_cmd(d,args)
            elif args.kind=='plan':plan_cmd(d,args)
            elif args.kind=='user':user_cmd(d,args)
            elif args.kind=='reconcile':reconcile(d)
            else:menu(d)
        finally:d.close()

if __name__=='__main__':
    try:main()
    except (Error,ValueError,sqlite3.Error) as e:print('错误：'+str(e),file=sys.stderr);sys.exit(1)
