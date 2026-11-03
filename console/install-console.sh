#!/usr/bin/env bash
# Installs locally only. Does not expose HTTP or configure Cloudflare policies.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || { echo '需要 root。' >&2; exit 1; }
SOURCE=$(cd -- "$(dirname -- "$0")" && pwd)
[[ -f /var/lib/sb-manager/manager.sqlite && -f /opt/sb-manager/lib/controller.py ]] || { echo '请先安装管理器并登记节点。' >&2; exit 1; }
[[ ! -e /opt/sb-console ]] || { echo '后台已安装；请使用审阅后的更新流程，避免覆盖运行中的版本。' >&2; exit 1; }
[[ -z $(ss -ltnH 'sport = :18080') ]] || { echo '18080 端口已占用。' >&2; exit 1; }
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3-venv
id -u sb-console >/dev/null 2>&1 || useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin sb-console
install -d -m 755 /opt/sb-console /opt/sb-console/static
install -m 644 "$SOURCE"/*.py "$SOURCE"/requirements.txt /opt/sb-console/
install -m 644 "$SOURCE"/static/* /opt/sb-console/static/
python3 -m venv --system-site-packages /opt/sb-console/venv
/opt/sb-console/venv/bin/pip install --disable-pip-version-check -r /opt/sb-console/requirements.txt
# Package code is public; runtime credentials remain outside this directory.
chmod -R a+rX /opt/sb-console/venv
install -d -m 700 /var/lib/sb-console-broker /etc/sb-console
install -d -o sb-console -g sb-console -m 700 /var/lib/sb-console
cat >/etc/sb-console/console.env <<'ENV'
SB_CONSOLE_ORIGIN=https://console.example.com
SB_ACCESS_TEAM=
SB_ACCESS_AUD=
SB_ACCESS_EMAIL=
ENV
chmod 600 /etc/sb-console/console.env
/opt/sb-console/venv/bin/python - <<'PY'
from pathlib import Path
import secrets,os,pwd
p=Path('/var/lib/sb-console/setup-token')
p.write_text(secrets.token_urlsafe(48));p.chmod(0o600)
u=pwd.getpwnam('sb-console');os.chown(p,u.pw_uid,u.pw_gid)
PY
cat >/etc/systemd/system/sb-console-broker.service <<'UNIT'
[Unit]
Description=Restricted sing-box console task broker
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Group=sb-console
RuntimeDirectory=sb-console
RuntimeDirectoryMode=0750
Environment=PYTHONPATH=/opt/sb-manager/lib
ExecStart=/opt/sb-console/venv/bin/python /opt/sb-console/broker.py
Restart=on-failure
RestartSec=5
UMask=0077
PrivateTmp=true
ProtectHome=true
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/sb-console.service <<'UNIT'
[Unit]
Description=Unprivileged sing-box console HTTP API
After=sb-console-broker.service
Requires=sb-console-broker.service
[Service]
Type=simple
User=sb-console
Group=sb-console
EnvironmentFile=/etc/sb-console/console.env
WorkingDirectory=/opt/sb-console
ExecStart=/opt/sb-console/venv/bin/uvicorn app:app --host 127.0.0.1 --port 18080 --no-proxy-headers --no-access-log
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sb-console
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now sb-console-broker.service sb-console.service
systemctl is-active sb-console-broker.service sb-console.service
echo '后台已安装，但未配置 Access 时拒绝所有访问。请配置 console.env 后接入 Tunnel。'
echo '首次设置令牌在 /var/lib/sb-console/setup-token，请勿公开。'
