"""Move an existing service's connector token out of public argv/unit files.

Does not rotate credentials or change routing. Refuses unknown unit layouts.
"""
import os
from pathlib import Path
import re
import subprocess

if os.geteuid()!=0:raise SystemExit('root required')
unit=Path('/etc/systemd/system/cloudflared.service')
text=unit.read_text()
if '--token-file ' in text:raise SystemExit('Already using a token file')
matches=list(re.finditer(r'--token\s+([A-Za-z0-9_=+/-]{40,})',text))
if len(matches)!=1:raise SystemExit('Unrecognized token layout; no changes made')
base=Path('/etc/sb-console-tunnel');base.mkdir(mode=0o700,exist_ok=True)
base.chmod(0o700)
token=base/'token';backup=base/'cloudflared.service.before-token-file'
if token.exists() or backup.exists():raise SystemExit('Existing token/backup; no changes made')
os.umask(0o077)
backup.write_text(text);backup.chmod(0o600)
m=matches[0]
token.write_text(m.group(1)+'\n');token.chmod(0o600)
unit.write_text(text[:m.start()]+'--token-file /etc/sb-console-tunnel/token'+text[m.end():])
unit.chmod(0o644)
try:
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','restart','cloudflared'],check=True)
except subprocess.CalledProcessError:
    unit.write_text(backup.read_text());unit.chmod(0o600)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','restart','cloudflared'],check=True)
    raise SystemExit('Restart failed; original unit restored')
print('Existing connector now reads a root-only token file; credential unchanged.')
