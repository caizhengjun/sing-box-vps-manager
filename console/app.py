"""Unprivileged console HTTP API. Access JWT + password/TOTP + CSRF sessions."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import time
import threading

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
import jwt
import pyotp
import qrcode

BASE=Path(os.environ.get('SB_CONSOLE_HOME','/var/lib/sb-console'))
ROOT=Path(__file__).resolve().parent
ORIGIN=os.environ.get('SB_CONSOLE_ORIGIN','https://console.example.com')
TEAM=os.environ.get('SB_ACCESS_TEAM','')
AUD=os.environ.get('SB_ACCESS_AUD','')
EMAIL=os.environ.get('SB_ACCESS_EMAIL','')
SOCKET=os.environ.get('SB_CONSOLE_SOCKET','/run/sb-console/broker.sock')
PASSWORD=PasswordHasher()
AUTH_LOCK=threading.Lock()
JWKS=None
app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)

def db():
    BASE.mkdir(mode=0o700,parents=True,exist_ok=True)
    d=sqlite3.connect(BASE/'auth.sqlite',timeout=10);d.row_factory=sqlite3.Row
    d.executescript('''PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS admin(id INTEGER PRIMARY KEY,password TEXT,totp TEXT,last_counter INTEGER DEFAULT -1);
      CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,csrf TEXT,identity TEXT,created INTEGER,last_seen INTEGER);
      CREATE TABLE IF NOT EXISTS failures(identity TEXT PRIMARY KEY,count INTEGER,until INTEGER);
    ''')
    return d

def timestamp():return int(time.time())

def broker(op,params=None,**extra):
    payload={'op':op,'params':params or {},**extra}
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(20)
    try:
        s.connect(SOCKET);s.sendall((json.dumps(payload)+'\n').encode())
        raw=b''
        while not raw.endswith(b'\n'):
            chunk=s.recv(65536)
            if not chunk:break
            raw+=chunk
            if len(raw)>8_000_000:raise HTTPException(502,'响应过大')
        result=json.loads(raw)
        if not result.get('ok'):raise HTTPException(400,result.get('error','操作失败'))
        return result['data']
    except (OSError,ValueError):raise HTTPException(503,'管理执行服务暂不可用')
    finally:s.close()

def identity(request):
    global JWKS
    if not TEAM or not AUD or not EMAIL:raise HTTPException(503,'管理员尚未配置 Cloudflare Access 认证')
    if not re.fullmatch(r'[a-z0-9-]+',TEAM):raise HTTPException(503,'Access 配置无效')
    token=request.headers.get('Cf-Access-Jwt-Assertion','')
    if not token:raise HTTPException(401,'请先通过 Cloudflare Access 登录')
    try:
        if JWKS is None:JWKS=jwt.PyJWKClient(f'https://{TEAM}.cloudflareaccess.com/cdn-cgi/access/certs',timeout=5)
        claims=jwt.decode(token,JWKS.get_signing_key_from_jwt(token).key,algorithms=['RS256'],
                          audience=AUD,issuer=f'https://{TEAM}.cloudflareaccess.com',
                          options={'require':['exp','iat','iss','aud','sub','email']})
        if claims['email'].casefold()!=EMAIL.casefold():raise ValueError('identity')
        return claims['email']
    except Exception:raise HTTPException(401,'Access 身份无效或已过期')

@app.middleware('http')
async def security(request,call_next):
    try:
        request.state.identity=identity(request)
        if request.method not in ('GET','HEAD') and request.headers.get('origin')!=ORIGIN:
            raise HTTPException(403,'来源验证失败')
        response=await call_next(request)
    except HTTPException as e:response=JSONResponse({'detail':e.detail},status_code=e.status_code)
    response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
       'X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
       'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
       'Strict-Transport-Security':'max-age=31536000'})
    return response

def session(request,mutating=False):
    token=request.cookies.get('__Host-sb-session','');key=hashlib.sha256(token.encode()).hexdigest()
    with db() as d:
        row=d.execute('SELECT * FROM sessions WHERE hash=?',(key,)).fetchone();ts=timestamp()
        if not row or row['identity']!=request.state.identity or ts-row['last_seen']>1800 or ts-row['created']>28800:
            raise HTTPException(401,'请重新登录后台')
        if mutating and not secrets.compare_digest(request.headers.get('x-csrf-token',''),row['csrf']):
            raise HTTPException(403,'操作验证失败')
        d.execute('UPDATE sessions SET last_seen=? WHERE hash=?',(ts,key))
        return dict(row)

def check_password(value):
    if not isinstance(value,str) or not 14<=len(value)<=256:raise HTTPException(400,'密码长度应为 14–256 个字符')

def credentials(body,who):
    with AUTH_LOCK,db() as d:
        ts=timestamp();f=d.execute('SELECT * FROM failures WHERE identity=?',(who,)).fetchone()
        if f and f['count']>=5 and f['until']>ts:raise HTTPException(429,'登录失败次数过多，请 15 分钟后再试')
        r=d.execute('SELECT * FROM admin WHERE id=1').fetchone()
        good=False
        if r:
            try:good=PASSWORD.verify(r['password'],str(body.get('password',''))[:256])
            except VerificationError:pass
        code=str(body.get('code',''));counter=ts//30
        valid_counter=next((v for v in (counter-1,counter,counter+1)
                            if r and re.fullmatch(r'\d{6}',code) and secrets.compare_digest(pyotp.TOTP(r['totp']).at(v*30),code)),None)
        if not good or valid_counter is None or valid_counter<=r['last_counter']:
            count=f['count']+1 if f and f['until']>ts else 1
            d.execute('INSERT OR REPLACE INTO failures VALUES(?,?,?)',(who,count,ts+900))
            d.commit();raise HTTPException(401,'密码或动态验证码错误；验证码不可重复使用')
        d.execute('UPDATE admin SET last_counter=? WHERE id=1',(valid_counter,))
        d.execute('DELETE FROM failures WHERE identity=?',(who,))

@app.get('/api/auth/status')
def auth_status(request:Request):
    with db() as d:configured=bool(d.execute('SELECT 1 FROM admin').fetchone())
    try:s=session(request);return {'configured':configured,'authenticated':True,'csrf':s['csrf'],'email':request.state.identity}
    except HTTPException:return {'configured':configured,'authenticated':False,'email':request.state.identity}

@app.post('/api/auth/enroll')
def enroll(request:Request,body:dict):
    token_file=BASE/'setup-token'
    with AUTH_LOCK,db() as d:
        if d.execute('SELECT 1 FROM admin').fetchone():raise HTTPException(409,'管理员已创建')
        if not token_file.exists() or not secrets.compare_digest(str(body.get('token','')),token_file.read_text().strip()):
            raise HTTPException(403,'首次设置令牌无效')
        secret_path=BASE/'pending-totp'
        if not secret_path.exists():
            secret_path.write_text(pyotp.random_base32());secret_path.chmod(0o600)
        secret=secret_path.read_text().strip()
        return {'secret':secret,'uri':pyotp.TOTP(secret).provisioning_uri(name=request.state.identity,issuer_name='VPS Console')}

@app.post('/api/auth/setup')
def setup(request:Request,body:dict):
    check_password(body.get('password'))
    with AUTH_LOCK,db() as d:
        if d.execute('SELECT 1 FROM admin').fetchone():raise HTTPException(409,'管理员已创建')
        token_file=BASE/'setup-token';secret_path=BASE/'pending-totp'
        if not token_file.exists() or not secret_path.exists() or not secrets.compare_digest(str(body.get('token','')),token_file.read_text().strip()):
            raise HTTPException(403,'首次设置令牌无效')
        secret=secret_path.read_text().strip()
        if not pyotp.TOTP(secret).verify(str(body.get('code',''))):raise HTTPException(400,'动态验证码不正确')
        d.execute('INSERT INTO admin(id,password,totp) VALUES(1,?,?)',(PASSWORD.hash(body['password']),secret))
        d.commit();token_file.unlink();secret_path.unlink()
    return {'ok':True}

@app.post('/api/auth/login')
def login(request:Request,body:dict):
    credentials(body,request.state.identity)
    token=secrets.token_urlsafe(48);csrf=secrets.token_urlsafe(32)
    with db() as d:
        d.execute('DELETE FROM sessions WHERE last_seen<?',(timestamp()-1800,))
        d.execute('INSERT INTO sessions VALUES(?,?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),csrf,
                   request.state.identity,timestamp(),timestamp()))
    r=JSONResponse({'csrf':csrf});r.set_cookie('__Host-sb-session',token,httponly=True,secure=True,samesite='strict',max_age=28800,path='/')
    return r

@app.post('/api/auth/logout')
def logout(request:Request):
    s=session(request,True)
    with db() as d:d.execute('DELETE FROM sessions WHERE hash=?',(s['hash'],))
    r=JSONResponse({'ok':True});r.delete_cookie('__Host-sb-session',path='/',secure=True,httponly=True,samesite='strict');return r

@app.get('/api/data')
def data(request:Request):session(request);return broker('snapshot')

@app.get('/api/tasks')
def tasks(request:Request):session(request);return broker('tasks')

@app.get('/api/audit')
def audit(request:Request):session(request);return broker('audit')

@app.post('/api/probe')
def probe(request:Request,body:dict):session(request,True);return broker('probe',body)

@app.post('/api/tasks')
def submit(request:Request,body:dict):
    session(request,True)
    if body.get('kind') in ('node.delete','node.initialise','user.delete','user.rotate-token'):
        credentials(body.get('reauth',{}),request.state.identity)
    return broker('submit',body.get('params',{}),kind=body.get('kind'),actor=request.state.identity)

@app.get('/api/users/{user_id}/subscription')
def subscriptions(user_id:str,request:Request):session(request);return broker('subscription',{'id':user_id})

@app.get('/api/users/{user_id}/qr/{fmt}')
def qr(user_id:str,fmt:str,request:Request):
    session(request)
    if fmt not in ('singbox','karing','mihomo','base64','links'):raise HTTPException(400,'格式无效')
    links=broker('subscription',{'id':user_id});buf=io.BytesIO();qrcode.make(links[fmt]).save(buf,format='PNG')
    return Response(buf.getvalue(),media_type='image/png')

app.mount('/assets',StaticFiles(directory=ROOT/'static'),name='assets')

@app.get('/{path:path}')
def index(path:str):return FileResponse(ROOT/'static/index.html')
