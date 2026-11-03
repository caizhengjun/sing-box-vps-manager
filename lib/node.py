#!/usr/bin/env python3
"""Root-only node worker. Invoked over verified SSH; no network management listener."""
import argparse
import copy
import functools
import http.server
import ipaddress
import json
import os
from pathlib import Path
import pwd
import grp
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

from common import (BASE, BIN, UNIT, VERSION, PRINCIPAL, Error, atomic, canonical,
                    credentials, db_open, digest, domain, load_json, lock, now,
                    query_stats, run, uid, write_json)
from formats import outbounds

HOME = Path('/var/lib/sb-node')
ROOT = Path(__file__).resolve().parent.parent
API = '127.0.0.1:10085'
SUPPORTED = {'naive','vless','trojan','hysteria2','tuic','anytls','shadowsocks'}

def database():
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(HOME,0o700)
    db=db_open(HOME/'node.sqlite')
    db.executescript('''
    CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS counters(principal TEXT PRIMARY KEY, generation TEXT NOT NULL,
      raw_up INTEGER NOT NULL,raw_down INTEGER NOT NULL,total_up INTEGER NOT NULL,total_down INTEGER NOT NULL);
    ''')
    with db:
        db.execute("INSERT OR IGNORE INTO meta VALUES('epoch',?)",(uid(),))
    return db

def generation():
    pid=run(['systemctl','show',UNIT,'-p','MainPID','--value']).decode().strip()
    if not pid.isdigit() or int(pid)==0: raise Error('sing-box 未运行。')
    stat=Path('/proc',pid,'stat').read_text()
    start=stat[stat.rfind(')')+2:].split()[19]
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+pid+':'+start

def collect(db):
    g=generation()
    values=query_stats(API)
    if generation()!=g: raise Error('采样期间进程已更换，稍后重试。')
    with db:
        for name,v in values.items():
            if not PRINCIPAL.fullmatch(name): continue
            old=db.execute('SELECT * FROM counters WHERE principal=?',(name,)).fetchone()
            if old:
                same=old['generation']==g
                du=v['up']-old['raw_up'] if same and v['up']>=old['raw_up'] else v['up']
                dd=v['down']-old['raw_down'] if same and v['down']>=old['raw_down'] else v['down']
                up,down=old['total_up']+du,old['total_down']+dd
            else:up,down=v['up'],v['down']
            db.execute('INSERT OR REPLACE INTO counters VALUES(?,?,?,?,?,?)',
                       (name,g,v['up'],v['down'],up,down))
        db.execute("INSERT OR REPLACE INTO meta VALUES('sample_at',?)",(str(now()),))

def totals(db):
    return {'epoch':db.execute("SELECT value FROM meta WHERE key='epoch'").fetchone()[0],
            'sample_at':int((db.execute("SELECT value FROM meta WHERE key='sample_at'").fetchone() or [0])[0]),
            'totals':{r['principal']:{'up':r['total_up'],'down':r['total_down']} for r in db.execute('SELECT * FROM counters')}}

def read_config():
    cfg=load_json(BASE/'config.json')
    if not isinstance(cfg.get('inbounds'),list) or not cfg['inbounds']:raise Error('缺少兼容入站配置。')
    tags=set()
    for i in cfg['inbounds']:
        if i.get('type') not in SUPPORTED or not i.get('tag') or i['tag'] in tags:raise Error('不支持的入站或重复 tag。')
        tags.add(i['tag'])
        if i['type']!='shadowsocks' and not i.get('users'):raise Error('已有配置包含空用户入站，拒绝接管。')
        if i.get('tls',{}).get('certificate_provider'):raise Error('只接管当前文件证书部署。')
    return cfg

def status():
    cfg=read_config()
    state=load_json(HOME/'state.json',{})
    ver=run([BIN,'version']).decode()
    active=subprocess.run(['systemctl','is-active','--quiet',UNIT]).returncode==0
    available=state.get('baseline',cfg)
    reality=next((i for i in available['inbounds'] if i.get('tag')=='vless-reality'),None)
    listeners={}
    for transport,flag in (('tcp','-ltnH'),('udp','-lunH')):
        listeners[transport]={int(row.split()[3].rsplit(':',1)[1]) for row in run(['ss',flag]).decode().splitlines()
                              if len(row.split())>3 and row.split()[3].rsplit(':',1)[-1].isdigit()}
    ports=[]
    addresses=[]
    try:
        for interface in json.loads(run(['ip','-j','-4','address','show','scope','global'])):
            addresses.extend(a['local'] for a in interface.get('addr_info',[]) if a.get('family')=='inet' and ipaddress.ip_address(a['local']).is_global)
    except (Error,ValueError,KeyError):pass
    for i in cfg['inbounds']:
        transports=['udp'] if i['type'] in ('hysteria2','tuic') else ['tcp','udp'] if i['type'] in ('naive','shadowsocks') else ['tcp']
        ports.append({'protocol':i['tag'],'type':i['type'],'port':i['listen_port'],
                      'listeners':{t:i['listen_port'] in listeners[t] for t in transports},
                      'configured_users':len(i.get('users',[])), 'wan_verified':False})
    return {'sni':reality.get('tls',{}).get('server_name') if reality else None,'version':ver.splitlines()[0], 'active':active,
            'domain':(BASE/'domain').read_text().strip(),
            'ports':ports,'addresses':sorted(set(addresses)),
            'stats_ready':bool(state.get('stats_ready')), 'revision':state.get('revision'),
            'unmanaged_accounts':state.get('unmanaged_accounts',0)}

def config_permissions(path):
    os.chmod(path,0o640);os.chown(path,0,grp.getgrnam('sb-vps').gr_gid)

def check(cfg, binary=BIN):
    with tempfile.NamedTemporaryFile(mode='w',dir=BASE,prefix='.check.',suffix='.json',delete=False) as f:
        json.dump(cfg,f);name=f.name
    try:
        config_permissions(name)
        run([binary,'check','-c',name])
        run(['runuser','-u','sb-vps','--',binary,'check','-c',name])
    finally:os.unlink(name)

def restart():
    run(['systemctl','restart',UNIT]);time.sleep(2)
    run(['systemctl','is-active','--quiet',UNIT])
    query_stats(API)

def install_client():
    """Download complete fixed official runtime, including libcronet.so when present."""
    import urllib.request,hashlib,tarfile,platform
    # A custom server build with the Naive outbound is also a complete client.
    current=run([BIN,'version']).decode()
    if current.splitlines()[0]=='sing-box version '+VERSION and 'with_naive_outbound' in current:
        return BIN
    arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
    if not arch:raise Error('不支持的架构。')
    target=Path('/usr/local/lib/sing-box-vps/client-runtime')
    if (target/'sing-box').exists():
        v=run([target/'sing-box','version']).decode()
        if v.splitlines()[0]=='sing-box version '+VERSION:return target/'sing-box'
    meta=json.load(urllib.request.urlopen('https://api.github.com/repos/SagerNet/sing-box/releases/tags/v'+VERSION,timeout=30))
    name=f'sing-box-{VERSION}-linux-{arch}.tar.gz'
    asset=next(a for a in meta['assets'] if a['name']==name)
    expected=asset.get('digest','')
    if not expected.startswith('sha256:'):raise Error('官方客户端资产缺少 SHA-256。')
    url=f'https://github.com/SagerNet/sing-box/releases/download/v{VERSION}/{name}'
    with urllib.request.urlopen(url,timeout=120) as r:data=r.read()
    if hashlib.sha256(data).hexdigest()!=expected[7:]:raise Error('客户端校验失败。')
    import io
    target.mkdir(mode=0o755,parents=True,exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        prefix=f'sing-box-{VERSION}-linux-{arch}/'
        for m in t.getmembers():
            if not m.name.startswith(prefix) or not m.isfile():continue
            rel=Path(m.name[len(prefix):])
            if '..' in rel.parts or rel.is_absolute():raise Error('客户端归档路径无效。')
            if m.size>400_000_000:raise Error('客户端资产过大。')
            p=target/rel;p.parent.mkdir(parents=True,exist_ok=True)
            atomic(p,t.extractfile(m).read(),0o755 if p.name=='sing-box' else 0o644)
    return target/'sing-box'

def free_port(socktype=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET,socktype) as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]

def metered_config(baseline, grants):
    cfg=copy.deepcopy(baseline)
    kept=[]
    for i in cfg['inbounds']:
        if i['tag']=='ss-legacy':kept.append(i);continue
        kind=i['type'];users=i.setdefault('users',[])
        for g in grants:
            c=g['credentials'];p=g['principal']
            if kind=='naive':users.append({'username':p,'password':c['password']})
            elif kind=='vless':
                u={'name':p,'uuid':c['uuid']}
                if i.get('tls',{}).get('reality',{}).get('enabled'):u['flow']='xtls-rprx-vision'
                users.append(u)
            elif kind=='tuic':users.append({'name':p,'uuid':c['uuid'],'password':c['password']})
            else:users.append({'name':p,'password':c['ss'] if kind=='shadowsocks' else c['password']})
        if users:kept.append(i) # Never leave an auth-less listener behind.
    cfg['inbounds']=kept
    cfg.setdefault('experimental',{})['v2ray_api']={'listen':API,'stats':{'enabled':True,'users':[g['principal'] for g in grants]}}
    return cfg

def selftest(baseline, client=None, binary=BIN):
    """Every managed protocol must transfer traffic AND increment its named user counter."""
    client=client or install_client()
    g={'principal':'m_'+uid()+'_'+uid(),'credentials':credentials(binary)}
    used_ports=set()
    def choose():
        for _ in range(100):
            p=free_port()
            if p not in used_ports:
                used_ports.add(p);return p
        raise Error('无法分配测试端口。')
    fixture=copy.deepcopy(baseline)
    fixture['inbounds']=[i for i in fixture['inbounds'] if i['tag']!='ss-legacy']
    for i in fixture['inbounds']:
        i['users']=[];i['listen']='127.0.0.1';i['listen_port']=choose()
    cfg=metered_config(fixture,[g]);api='127.0.0.1:'+str(choose())
    cfg['experimental']['v2ray_api']['listen']=api
    cfg['route']={'rules':[],'final':'direct'}
    cfg['outbounds']=[{'type':'direct','tag':'direct'}]
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body=b'sb-meter-proof-'*4096
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.send_header('Connection','close');self.end_headers();self.wfile.write(body)
        def log_message(self,*a):pass
    origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=origin.serve_forever,daemon=True);thread.start()
    result=[]
    with tempfile.TemporaryDirectory(prefix='sb-proof-',dir=HOME) as d:
        d=Path(d);write_json(d/'server.json',cfg)
        err=open(d/'runtime.log','wb')
        server=subprocess.Popen([str(binary),'run','-c',str(d/'server.json')],stdout=err,stderr=err)
        try:
            time.sleep(2)
            if server.poll() is not None:raise Error('计量自测服务无法启动。')
            outs=outbounds(cfg,(BASE/'domain').read_text().strip(),'proof','proof',g['principal'],g['credentials'])
            previous={'up':0,'down':0}
            for o in outs:
                o['server']='127.0.0.1'
                local=choose()
                cc={'log':{'level':'error'},'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':local}],
                    'outbounds':[o],'route':{'final':o['tag']}}
                write_json(d/'client.json',cc)
                proc=subprocess.Popen([str(client),'run','-c',str(d/'client.json')],stdout=err,stderr=err)
                try:
                    time.sleep(.6)
                    body=run(['curl','--fail','--silent','--max-time','20','--noproxy','','--proxy',f'socks5h://127.0.0.1:{local}',
                              f'http://127.0.0.1:{origin.server_port}/'],timeout=25)
                    if body!=b'sb-meter-proof-'*4096:raise Error('计量自测内容不匹配。')
                    time.sleep(.15)
                    current=query_stats(api).get(g['principal'],{})
                    if current.get('up',0)<=previous['up'] or current.get('down',0)<=previous['down']:
                        raise Error('逐用户流量计数未增加：'+o['type'])
                    result.append(o['type']+('-h3' if o.get('quic') else '-h2') if o['type']=='naive' else o['type'])
                    previous=current
                finally:
                    proc.terminate()
                    try:proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait()
        finally:
            server.terminate()
            try:server.wait(timeout=5)
            except subprocess.TimeoutExpired:server.kill();server.wait()
            err.close();origin.shutdown();origin.server_close()
    return result

def enable_collector():
    drop=Path('/etc/systemd/system')/(UNIT+'.d')
    drop.mkdir(parents=True,exist_ok=True)
    atomic(drop/'accounting.conf','[Service]\nExecStop=/usr/bin/python3 /opt/sb-node/lib/node.py before-stop\n')
    atomic('/etc/systemd/system/sb-node-collect.service','''[Unit]
Description=Durable sing-box per-user accounting collector
After=sing-box-vps.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/sb-node/lib/node.py collect-loop
Restart=always
RestartSec=5
UMask=0077
[Install]
WantedBy=multi-user.target
''',0o644)
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable','--now','sb-node-collect.service'])


def open_managed_ports():
    if shutil.which('ufw'):
        try:
            if run(['ufw','status']).decode().startswith('Status: active'):
                for p,proto in [(8447,'tcp'),(8447,'udp'),(8389,'tcp'),(8389,'udp')]:
                    run(['ufw','allow',f'{p}/{proto}','comment','sb-managed'])
                return
        except Error:pass
    if subprocess.run(['systemctl','is-active','--quiet','firewalld']).returncode==0:
        zones=[x for x in run(['firewall-cmd','--get-active-zones']).decode().splitlines() if x and not x.startswith(' ')]
        if len(zones)!=1:raise Error('firewalld 活动 zone 不唯一，无法自动修改。')
        for p,proto in [(8447,'tcp'),(8447,'udp'),(8389,'tcp'),(8389,'udp')]:
            run(['firewall-cmd','--zone='+zones[0],'--add-port='+f'{p}/{proto}'])
            run(['firewall-cmd','--permanent','--zone='+zones[0],'--add-port='+f'{p}/{proto}'])

def enrol(request):
    state=load_json(HOME/'state.json',{})
    if state:
        if state['controller']!=request['controller']:raise Error('节点已归其他主控管理。')
        return status()
    cfg=read_config()
    if any(PRINCIPAL.fullmatch(u.get('name',u.get('username',''))) for i in cfg['inbounds'] for u in i.get('users',[])):
        raise Error('已有受管格式账号但缺少管理状态，需人工恢复，拒绝覆盖。')
    version=run([BIN,'version']).decode()
    if version.splitlines()[0]!='sing-box version '+VERSION:raise Error('仅接管固定版本 '+VERSION)
    domain((BASE/'domain').read_text().strip())
    # Read-only checks precede backups and any compatibility migration.
    for i in cfg['inbounds']:
        if i['type']=='shadowsocks' and (i.get('users') or i.get('method')!='2022-blake3-aes-256-gcm'):
            raise Error('仅支持当前单用户 SS2022 默认配置的迁移。')
    original=copy.deepcopy(cfg)
    backup=HOME/('pre-enrol-'+str(now()));backup.mkdir(mode=0o700)
    shutil.copy2(BASE/'config.json',backup/'config.json')
    shutil.copy2(BIN,backup/'sing-box')
    for name in ('client-outbounds.json','naive-client-h2.json','naive-client-h3.json'):
        if (BASE/name).exists():shutil.copy2(BASE/name,backup/name)
    baseline=copy.deepcopy(cfg)
    ports={i['listen_port'] for i in cfg['inbounds']}
    for i in baseline['inbounds']:
        if i['type']=='naive' and i['listen_port']==443:
            if 8447 in ports:raise Error('Naive 8447 端口冲突。')
            for flag in ('-ltnH','-lunH'):
                if run(['ss',flag,'sport = :8447']).strip():raise Error('Naive 8447 已被占用。')
            i['listen_port']=8447
        if i['type']=='shadowsocks':i['tag']='ss-legacy'
    legacy=next((i for i in baseline['inbounds'] if i['tag']=='ss-legacy'),None)
    if legacy:
        if 8389 in ports or any(run(['ss',flag,'sport = :8389']).strip() for flag in ('-ltnH','-lunH')):raise Error('受管 SS2022 8389 已被占用。')
        new=copy.deepcopy(legacy);new.update(tag='shadowsocks',listen_port=8389,password=credentials()['ss'],users=[])
        baseline['inbounds'].append(new)
    # Build before replacing anything; keep an official client runtime for per-protocol proofs.
    if 'with_v2ray_api' not in version or 'with_grpc' not in version:
        run(['bash',ROOT/'build-stats.sh'],timeout=2400)
        binary=Path('/usr/local/lib/sing-box-vps/sing-box-metered')
    else:binary=BIN
    tests=selftest(baseline,binary=binary)
    open_managed_ports()
    candidate=metered_config(baseline,[])
    check(candidate,binary)
    try:
        if binary!=BIN:atomic(BIN,binary.read_bytes(),0o755)
        write_json(BASE/'config.json',candidate,mode=0o640,group=grp.getgrnam('sb-vps').gr_gid)
        for fn in ('client-outbounds.json','naive-client-h2.json','naive-client-h3.json'):
            path=BASE/fn
            if path.exists():
                content=load_json(path)
                if fn=='client-outbounds.json':
                    for o in content.get('outbounds',[]):
                        if o.get('type')=='naive' and o.get('server_port')==443:o['server_port']=8447
                elif 'proxy' in content:content['proxy']=content['proxy'].replace(':443',':8447')
                write_json(path,content)
        restart()
        unmanaged=sum(len(i.get('users',[])) or int(i.get('tag')=='ss-legacy') for i in baseline['inbounds'])
        state={'controller':request['controller'],'revision':None,'baseline':baseline,'grants':{},'stats_ready':True,
               'proofs':tests,'unmanaged_accounts':unmanaged,'backup':str(backup)}
        write_json(HOME/'state.json',state)
        enable_collector()
    except Exception:
        atomic(BIN,(backup/'sing-box').read_bytes(),0o755)
        write_json(BASE/'config.json',original,mode=0o640,group=grp.getgrnam('sb-vps').gr_gid)
        for fn in ('client-outbounds.json','naive-client-h2.json','naive-client-h3.json'):
            if (backup/fn).exists():shutil.copy2(backup/fn,BASE/fn)
        run(['systemctl','restart',UNIT])
        if (HOME/'state.json').exists():(HOME/'state.json').unlink()
        raise
    return status()

def apply(request,db):
    state=load_json(HOME/'state.json')
    if request['controller']!=state['controller']:raise Error('主控 ID 不匹配。')
    if not state['stats_ready']:raise Error('节点未通过计量检查。')
    desired=request['grants']
    if len({g['principal'] for g in desired})!=len(desired):raise Error('重复用户。')
    previous=state.get('grants',{})
    # Validate requested principals; use node-local native generation and stable credentials.
    grants=[]
    for g in desired:
        if not PRINCIPAL.fullmatch(g['principal']):raise Error('非法受管用户。')
        grants.append(dict(g,credentials=previous.get(g['principal'],{}).get('credentials') or credentials()))
    cfg=metered_config(state['baseline'],grants)
    cfg_hash=digest(cfg)
    current=read_config()
    if digest(current)!=state.get('config_hash',digest(metered_config(state['baseline'],list(previous.values())))):
        raise Error('配置已在管理器外被修改，拒绝覆盖；请先核对恢复。')
    if cfg_hash!=digest(current):
        check(cfg)
        collect(db)
        backup=HOME/'last-good.json';write_json(backup,current)
        state_old=copy.deepcopy(state)
        # Persist transaction intent before replacement; replay or recover after interrupted SSH.
        write_json(HOME/'pending.json',{'old':current,'state':state_old,'new':cfg})
        try:
            write_json(BASE/'config.json',cfg,mode=0o640,group=grp.getgrnam('sb-vps').gr_gid)
            restart()
        except Exception:
            write_json(BASE/'config.json',current,mode=0o640,group=grp.getgrnam('sb-vps').gr_gid)
            restart()
            (HOME/'pending.json').unlink(missing_ok=True)
            raise
    state.update(grants={g['principal']:g for g in grants},revision=request['revision'],config_hash=cfg_hash)
    write_json(HOME/'state.json',state)
    (HOME/'pending.json').unlink(missing_ok=True)
    collect(db)
    response=totals(db)
    response.update(revision=request['revision'], grants={g['principal']:outbounds(cfg,request['domain'],request['name'],g['name'],g['principal'],g['credentials']) for g in grants})
    return response

def recover():
    pending=load_json(HOME/'pending.json',{})
    if pending:
        # Unknown outcome is restored to known previous state, then desired state can be replayed.
        write_json(BASE/'config.json',pending['old'],mode=0o640,group=grp.getgrnam('sb-vps').gr_gid)
        restart();write_json(HOME/'state.json',pending['state']);(HOME/'pending.json').unlink()

def set_sni(req, db):
    target=domain(req['sni'])
    state=load_json(HOME/'state.json')
    if state['controller']!=req['controller']:raise Error('主控 ID 不匹配。')
    if target==(BASE/'domain').read_text().strip():raise Error('REALITY SNI 不能是本机域名。')
    proof=run(['openssl','s_client','-connect',target+':443','-servername',target,
               '-tls1_3','-alpn','h2','-verify_return_error','-verify_hostname',target],
              data=b'',timeout=25)
    if b'ALPN protocol: h2' not in proof:raise Error('新 SNI 不支持 h2。')
    old=read_config()
    if digest(old)!=state['config_hash']:raise Error('配置发生外部修改，拒绝改 SNI。')
    baseline=copy.deepcopy(state['baseline'])
    r=next((i for i in baseline['inbounds'] if i.get('tag')=='vless-reality'),None)
    if not r:raise Error('缺少 REALITY 入站。')
    r['tls']['server_name']=target
    r['tls']['reality']['handshake']['server']=target
    grants=list(state['grants'].values())
    candidate=metered_config(baseline,grants)
    check(candidate)
    collect(db)
    write_json(HOME/'pending.json',{'old':old,'state':state,'new':candidate})
    try:
        write_json(BASE/'config.json',candidate,mode=0o640,group=grp.getgrnam('sb-vps').gr_gid)
        restart()
        state['baseline']=baseline
        state['config_hash']=digest(candidate)
        write_json(HOME/'state.json',state)
        (HOME/'pending.json').unlink(missing_ok=True)
    except Exception:
        write_json(BASE/'config.json',old,mode=0o640,group=grp.getgrnam('sb-vps').gr_gid)
        restart()
        (HOME/'pending.json').unlink(missing_ok=True)
        raise
    return status()

def handle(req):
    db=database()
    try:
        recover()
        op=req['op']
        if op=='inspect':return status()
        if op=='enrol':return enrol(req)
        if op=='apply':return apply(req,db)
        if op=='set_sni':return set_sni(req,db)
        if op=='poll':collect(db);return dict(totals(db),status=status())
        raise Error('未知节点操作。')
    finally:db.close()

def main():
    if os.geteuid()!=0:raise Error('节点操作需要 root。')
    os.umask(0o077)
    cmd=sys.argv[1] if len(sys.argv)>1 else 'rpc'
    if cmd in ('collect-loop','before-stop'):
        while True:
            try:
                with lock(HOME/'lock',blocking=False):
                    db=database()
                    try:collect(db)
                    finally:db.close()
            except Exception:
                if cmd=='collect-loop':print('流量采样未成功；保留已有计数，等待重试。',file=sys.stderr,flush=True)
            if cmd=='before-stop':return
            time.sleep(5)
    with lock(HOME/'lock'):
        req=json.loads(sys.stdin.buffer.read(4*1024*1024))
        response=handle(req)
        print(canonical({'ok':True,'result':response}))

if __name__=='__main__':
    try:main()
    except Exception as e:
        print(canonical({'ok':False,'error':str(e) if isinstance(e,Error) else '节点操作失败；请检查节点服务日志与状态。'}))
        sys.exit(1)
