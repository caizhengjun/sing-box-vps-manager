#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $EUID == 0 && $(uname -s) == Linux ]] || { echo '需要 Linux root。' >&2; exit 1; }
[[ $# == 2 && $1 == --domain ]] || { echo '用法：sudo bash install-manager.sh --domain sub.example.com' >&2; exit 1; }
DOMAIN=$2
SOURCE=$(cd -- "$(dirname -- "$0")" && pwd)
[[ -f /etc/sing-box-vps/config.json ]] || { echo '先在主服务器运行基础安装脚本。' >&2; exit 1; }
[[ $DOMAIN =~ ^[A-Za-z0-9.-]+$ && $DOMAIN == *.* ]] || { echo '订阅域名无效。' >&2; exit 1; }
openssl x509 -in /etc/sing-box-vps/tls/current/fullchain.pem -checkhost "$DOMAIN" -noout >/dev/null || { echo '现有证书未覆盖订阅域名，请先扩展证书。' >&2; exit 1; }
if systemctl is-active --quiet sb-subscription.service; then
 echo '订阅服务已存在，请用管理命令更新。' >&2; exit 1
fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-aiohttp python3-grpcio qrencode openssh-client ca-certificates
id -u sb-sub >/dev/null 2>&1 || useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin sb-sub
if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -q '^Status: active'; then
 ufw allow 443/tcp comment sb-subscription
elif systemctl is-active --quiet firewalld; then
 mapfile -t zones < <(firewall-cmd --get-active-zones | sed -n '/^[^ ]/p')
 ((${#zones[@]} == 1)) || { echo 'firewalld 活动 zone 不唯一。' >&2; exit 1; }
 firewall-cmd --zone="${zones[0]}" --add-port=443/tcp
 firewall-cmd --permanent --zone="${zones[0]}" --add-port=443/tcp
fi
install -d -m 755 /opt/sb-manager
install -m 755 "$SOURCE"/*.sh /opt/sb-manager/
install -d -m 755 /opt/sb-manager/lib
install -m 644 "$SOURCE"/lib/*.py /opt/sb-manager/lib/
chmod 755 /opt/sb-manager /opt/sb-manager/lib /opt/sb-manager/*.sh /opt/sb-manager/lib/*.py
install -d -m 700 /var/lib/sb-manager
install -d -o root -g sb-sub -m 750 /var/lib/sb-subscription
install -d -m 700 /opt/sb-node/lib
cp /opt/sb-manager/lib/{common,formats,node}.py /opt/sb-node/lib/
cp /opt/sb-manager/build-stats.sh /opt/sb-node/
python3 /opt/sb-manager/lib/controller.py setup --domain "$DOMAIN"
install -d -o root -g sb-sub -m 750 /etc/sb-subscription
install -o root -g sb-sub -m 640 /etc/sing-box-vps/tls/current/fullchain.pem /etc/sb-subscription/fullchain.pem
install -o root -g sb-sub -m 640 /etc/sing-box-vps/tls/current/privkey.pem /etc/sb-subscription/privkey.pem
cat >/etc/sing-box-vps/deploy-subscription-certificate <<'HOOK'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
install -o root -g sb-sub -m 640 /etc/sing-box-vps/tls/current/fullchain.pem /etc/sb-subscription/fullchain.pem
install -o root -g sb-sub -m 640 /etc/sing-box-vps/tls/current/privkey.pem /etc/sb-subscription/privkey.pem
systemctl try-restart sb-subscription.service
HOOK
chmod 700 /etc/sing-box-vps/deploy-subscription-certificate
if ! grep -q 'deploy-subscription-certificate' /etc/sing-box-vps/deploy-certificate; then
 # The existing Certbot deploy hook invokes this after installing a renewed certificate.
 cat >>/etc/sing-box-vps/deploy-certificate <<'HOOK'
if [[ -x /etc/sing-box-vps/deploy-subscription-certificate ]]; then
 /etc/sing-box-vps/deploy-subscription-certificate
fi
HOOK
fi
cat >/etc/systemd/system/sb-subscription.service <<'UNIT'
[Unit]
Description=sing-box subscription HTTPS
Wants=network-online.target
After=network-online.target sing-box-vps.service
[Service]
Type=simple
User=sb-sub
Group=sb-sub
ExecStart=/usr/bin/python3 /opt/sb-manager/lib/subscription.py
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictSUIDSGID=true
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/sb-manager-reconcile.service <<'UNIT'
[Unit]
Description=Synchronize sing-box users, nodes and traffic
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/sb-manager/lib/controller.py reconcile
UMask=0077
UNIT
cat >/etc/systemd/system/sb-manager-reconcile.timer <<'UNIT'
[Unit]
Description=Periodic sing-box management reconciliation
[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s
Persistent=true
[Install]
WantedBy=timers.target
UNIT
cat >/etc/systemd/system/sb-sni-monitor.service <<'UNIT'
[Unit]
Description=Check Reality SNI and refresh subscriptions if needed
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/module/Reality-SNI-Check.sh
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/sb-manager/lib/sni_monitor.py
UMask=0077
UNIT
cat >/etc/systemd/system/sb-sni-monitor.timer <<'UNIT'
[Unit]
Description=Weekly Reality SNI compliance check
[Timer]
OnCalendar=Sun *-*-* 04:00:00
RandomizedDelaySec=1800
Persistent=true
[Install]
WantedBy=timers.target
UNIT
chmod 644 /etc/systemd/system/sb-subscription.service /etc/systemd/system/sb-manager-reconcile.service /etc/systemd/system/sb-manager-reconcile.timer /etc/systemd/system/sb-sni-monitor.service /etc/systemd/system/sb-sni-monitor.timer
systemctl daemon-reload
# Enrol local node first; only then is 443/TCP freed for the subscription endpoint.
python3 /opt/sb-manager/lib/controller.py node list
printf '\n请使用 sudo /opt/sb-manager/manage-servers.sh add 把本机登记为 local 节点。\n'
printf '登记并通过计量测试后，再执行：sudo systemctl enable --now sb-subscription.service sb-manager-reconcile.timer sb-sni-monitor.timer\n'
