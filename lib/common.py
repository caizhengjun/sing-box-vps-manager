"""Shared primitives. No shell interpolation of administrator/user input."""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time
import uuid

VERSION = '1.14.4'
TAGS = 'with_quic,with_utls,with_v2ray_api,with_grpc,with_naive_outbound'
BASE = Path('/etc/sing-box-vps')
BIN = Path('/usr/local/lib/sing-box-vps/sing-box')
UNIT = 'sing-box-vps.service'
PRINCIPAL = re.compile(r'^m_[0-9a-f]{32}_[0-9a-f]{32}$')

class Error(Exception):
    pass

def now():
    return int(time.time())

def uid():
    return uuid.uuid4().hex

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def run(args, data=None, timeout=120, env=None):
    try:
        p = subprocess.run([str(x) for x in args], input=data, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as e:
        raise Error('命令执行超时：' + str(args[0])) from e
    except OSError as e:
        raise Error('命令无法启动：' + str(args[0])) from e
    if p.returncode:
        # Do not echo raw subprocess stderr: it may contain a URL or candidate secrets.
        raise Error('命令执行失败：' + str(args[0]) + '（退出码 ' + str(p.returncode) + '）')
    return p.stdout

def atomic(path, value, mode=0o600, group=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(value if isinstance(value, bytes) else value.encode())
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        if group is not None:
            os.chown(tmp, 0, group)
        os.replace(tmp, path)
        d = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(d)
        finally: os.close(d)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def write_json(path, value, **kwargs):
    atomic(path, canonical(value) + '\n', **kwargs)

def load_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        if default is not None: return default
        raise

@contextlib.contextmanager
def lock(path, blocking=True):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a+') as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError as e:
            raise Error('另一个管理操作正在运行，请稍后重试。') from e
        yield

def db_open(path):
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    return db

def domain(value):
    value = value.lower().strip()
    if len(value) > 253 or len(value.split('.')) < 2 or value.split('.')[-1].isdigit():
        raise Error('需要有效的域名。')
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')):
        raise Error('域名格式无效。')
    return value

def label(value):
    value = value.strip()
    if not value or len(value) > 80 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Error('名称/标签必须为 1–80 个可显示字符。')
    return value

def labels(value):
    items = value.split(',') if isinstance(value, str) else value
    return sorted(set(label(x) for x in items if x.strip()))

def port(value):
    n = int(value)
    if not 1 <= n <= 65535: raise Error('端口须在 1–65535 之间。')
    return n

def public_key(private):
    # X25519 PKCS#8 DER, no private key in process arguments or a temporary file.
    raw = base64.urlsafe_b64decode(private + '=')
    if len(raw) != 32: raise Error('REALITY 私钥格式无效。')
    der = bytes.fromhex('302e020100300506032b656e04220420') + raw
    out = run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'], data=der)
    return base64.urlsafe_b64encode(out[-32:]).decode().rstrip('=')

def credentials(binary=BIN):
    def gen(*args): return run([binary, 'generate', *args]).decode().strip()
    return {'uuid': gen('uuid'), 'password': gen('rand', '--base64', '32'),
            'ss': gen('rand', '--base64', '32')}

def principal(user, cycle):
    value = 'm_' + user + '_' + cycle
    if not PRINCIPAL.fullmatch(value): raise Error('内部用户标识无效。')
    return value

# Minimal protobuf codec for the pinned official stats.proto. No generated/runtime version mismatch.
def fields(data):
    def varint(pos):
        value = 0
        for shift in range(0, 70, 7):
            if pos >= len(data): raise Error('统计响应截断。')
            b = data[pos]; pos += 1
            value |= (b & 127) << shift
            if b < 128: return value, pos
        raise Error('统计响应整数溢出。')
    pos = 0
    while pos < len(data):
        key, pos = varint(pos)
        kind = key & 7
        if kind == 0:
            value, pos = varint(pos)
        elif kind == 2:
            size, pos = varint(pos)
            if pos + size > len(data): raise Error('统计响应长度错误。')
            value = data[pos:pos + size]; pos += size
        elif kind in (1, 5):
            size = 8 if kind == 1 else 4
            value = data[pos:pos + size]; pos += size
            if len(value) != size: raise Error('统计响应长度错误。')
        else: raise Error('不支持的统计响应字段。')
        yield key >> 3, value

def query_stats_detailed(address='127.0.0.1:10085'):
    import grpc
    with grpc.insecure_channel(address) as channel:
        method = channel.unary_unary('/v2ray.core.app.stats.command.StatsService/QueryStats',
                                     request_serializer=lambda x: x, response_deserializer=lambda x: x)
        response = method(b'', timeout=5)  # Never reset live counters.
    result = {'users': {}, 'outbounds': {}}
    for number, raw in fields(response):
        if number != 1: continue
        item = dict(fields(raw))
        name = item.get(1, b'').decode()
        val = item.get(2, 0)
        if val >= (1 << 63): raise Error('统计计数器溢出。')
        parts = name.split('>>>')
        if len(parts) == 4 and parts[0] in ('user','outbound') and parts[2] == 'traffic' and parts[3] in ('uplink', 'downlink'):
            target=result['users' if parts[0]=='user' else 'outbounds']
            target.setdefault(parts[1], {'up': 0, 'down': 0})['up' if parts[3] == 'uplink' else 'down'] = val
    return result

def query_stats(address='127.0.0.1:10085'):
    return query_stats_detailed(address)['users']
