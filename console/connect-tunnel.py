"""Read an EXISTING Cloudflare connector token from stdin; never echo it."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys

if os.geteuid()!=0:raise SystemExit('root required')
token=sys.stdin.buffer.readline(16385).strip()
if token.startswith(b'sudo cloudflared service install '):
    token=token.removeprefix(b'sudo cloudflared service install ').strip()
if not 30<len(token)<16000 or not re.fullmatch(rb'[A-Za-z0-9_=+/-]+',token):
    raise SystemExit('Invalid connector token')
try:
    metadata=json.loads(base64.b64decode(token+b'='*((-len(token))%4),validate=True))
    if not all(k in metadata for k in ('a','t','s')):raise ValueError()
except Exception:raise SystemExit('Invalid connector token encoding')
base=Path('/etc/sb-console-tunnel');base.mkdir(mode=0o700,exist_ok=True)
p=base/'token'
if p.exists():raise SystemExit('Existing token found; refusing to overwrite')
os.umask(0o077)
p.write_bytes(token+b'\n');p.chmod(0o600)
unit=Path('/etc/systemd/system/sb-console-tunnel.service')
if unit.exists():raise SystemExit('Existing tunnel service found')
unit.write_text('''[Unit]
Description=Cloudflare connector for console
After=network-online.target sb-console.service
Wants=network-online.target
[Service]
Type=simple
User=root
ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token-file /etc/sb-console-tunnel/token
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
''')
unit.chmod(0o644)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','sb-console-tunnel.service'],check=True)
print('Connector service started; token saved root-only.')
