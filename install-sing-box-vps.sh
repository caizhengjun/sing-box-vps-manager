#!/usr/bin/env bash
# Fresh-server multi-protocol deployment; audited against sing-box 1.14.4.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
DOMAIN=
SUBSCRIPTION_DOMAIN=
SB_VERSION=1.14.4
BASE=/etc/sing-box-vps
BIN=/usr/local/lib/sing-box-vps/sing-box
UNIT=sing-box-vps.service
EMAIL=
FIREWALL=auto
REALITY_HOST=www.microsoft.com
WORK= STAGE= COMMITTED=0
say() { printf '%s\n' "$*"; }
die() { say "错误：$*" >&2; exit 1; }
usage() {
 cat <<'EOF'
用法（Debian 12/13、Ubuntu 22.04/24.04，amd64/arm64，systemd）：
 sudo bash install-sing-box-vps.sh --domain node.example.com --email admin@example.com \
   [--subscription-domain sub.example.com] [--sni www.microsoft.com]
--domain 与 --email 必填。--subscription-domain 仅用于同机安装订阅管理器时申请双域名证书。
默认 REALITY SNI：www.microsoft.com。
运行安装即自动向 Certbot 传入 --agree-tos，同意 Let's Encrypt 服务条款。
仅使用 IPv4。云安全组须自行放行 80/tcp、443/tcp（主服务器订阅）、8443:8447/tcp、
2443:2444/udp、8447/udp、8388/tcp+udp。已启用的 UFW/firewalld 会自动追加规则；
未检测到管理器时不修改主机防火墙，也不表示端口已放行。
不会停止其他服务、激活防火墙、覆盖既有安装或输出密码。
EOF
}
while (($#)); do
 case "$1" in
 --domain|--subscription-domain|--email|--sni)
  (($# >= 2)) || die "参数缺少值：$1"
  case "$1" in --domain) DOMAIN=$2;; --subscription-domain) SUBSCRIPTION_DOMAIN=$2;; --email) EMAIL=$2;; --sni) REALITY_HOST=$2;; esac; shift 2;;
 -h|--help) usage; exit 0;;
 *) die "未知参数：$1";;
 esac
done
[[ $EUID == 0 ]] || die '请使用 sudo/root。'
[[ $(uname -s) == Linux ]] || die '仅支持 Linux VPS。'
[[ -n $DOMAIN && -n $EMAIL ]] || die '--domain 与 --email 为必填参数。'
[[ $EMAIL =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die '证书联系邮箱格式无效。'
# Validate DNS names strictly before writing them into shell configuration.
valid_domain() {
 python3 - "$1" <<'PYDOMAIN'
import re,sys
v=sys.argv[1]
labels=v.split('.')
ok=len(v)<=253 and len(labels)>=2 and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',x) for x in labels) and not labels[-1].isdigit()
raise SystemExit(0 if ok else 1)
PYDOMAIN
}
# python3 is installed below; use a conservative shell check before dependencies.
for host in "$DOMAIN" "$REALITY_HOST" ${SUBSCRIPTION_DOMAIN:+"$SUBSCRIPTION_DOMAIN"}; do
 [[ $host =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && $host == *.* && ${#host} -le 253 ]] || die '域名格式无效。'
done
DOMAIN=${DOMAIN,,}
SUBSCRIPTION_DOMAIN=${SUBSCRIPTION_DOMAIN,,}
REALITY_HOST=${REALITY_HOST,,}
[[ $REALITY_HOST =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && $REALITY_HOST == *.* ]] || die 'REALITY 目标域名无效。'
[[ $REALITY_HOST != "$DOMAIN" ]] || die 'REALITY 目标不能指向本机域名。'
source /etc/os-release
case "$ID:$VERSION_ID" in debian:12|debian:13|ubuntu:22.04|ubuntu:24.04);; *) die '仅支持 Debian 12/13 或 Ubuntu 22.04/24.04。';; esac
case $(uname -m) in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; *) die '仅支持 amd64/arm64。';; esac
[[ -d /run/systemd/system ]] || die '需要运行中的 systemd。'
for p in "$BASE" /usr/local/lib/sing-box-vps /etc/systemd/system/$UNIT /etc/systemd/system/sing-box-vps-renew.service /etc/systemd/system/sing-box-vps-renew.timer; do
 [[ ! -e $p && ! -L $p ]] || die "已有路径 $p；为保护现有配置，停止安装。"
done
getent passwd sb-vps >/dev/null && die '用户 sb-vps 已存在；请检查旧安装。'
getent group sb-vps >/dev/null && die '组 sb-vps 已存在；请检查旧安装。'
exec 9>/run/lock/sing-box-vps-install.lock
flock -n 9 || die '另一个安装正在运行。'
cleanup() {
 local rc=$?
 trap - EXIT
 [[ -z $WORK ]] || rm -rf -- "$WORK"
 [[ -z $STAGE ]] || rm -rf -- "$STAGE"
 if ((rc != 0)); then
  say '安装未完成。不会删除证书、撤销防火墙规则或删除配置；修正问题后按说明处理。' >&2
  if ((COMMITTED)); then
   systemctl stop "$UNIT" >/dev/null 2>&1 || true
   say "诊断：journalctl -u $UNIT -n 80；请勿公开含凭据的配置。" >&2
  fi
 fi
 exit "$rc"
}
trap cleanup EXIT
say '安装发行版依赖……'
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl python3 openssl certbot iproute2 util-linux fail2ban
valid_domain "$DOMAIN" || die '域名格式无效（需有效 DNS 域名）。'
valid_domain "$REALITY_HOST" || die 'SNI 格式无效（需有效 DNS 域名）。'
[[ -z $SUBSCRIPTION_DOMAIN ]] || valid_domain "$SUBSCRIPTION_DOMAIN" || die '订阅域名格式无效。'
[[ -z $SUBSCRIPTION_DOMAIN || $SUBSCRIPTION_DOMAIN != "$DOMAIN" ]] || die '订阅域名必须与节点域名不同。'
# Own ACME directories avoid changing any existing certbot account/renewal lineage.
[[ ! -e $BASE ]] || die '安装路径已出现。'
WORK=$(mktemp -d /tmp/sb-vps.XXXXXXXX)
STAGE=$(mktemp -d /etc/.sb-vps.XXXXXXXX)
chmod 700 "$WORK" "$STAGE"
# Both TCP and UDP are checked independently, including IPv6 wildcard conflicts.
check_ports() {
 local proto port
 for proto in tcp udp; do
  if [[ $proto == tcp ]]; then ports=(80 8447 8443 8444 8445 8446 8388); flag=-ltnH; else ports=(8447 2443 2444 8388); flag=-lunH; fi
  for port in "${ports[@]}"; do
   [[ -z $(ss "$flag" "sport = :$port") ]] || die "$proto/$port 已占用；请自行调整现有服务，本脚本不会停止它。"
  done
 done
}
check_ports
say '核对 DNS（只部署 IPv4；拒绝残留 AAAA）……'
python3 - "$DOMAIN" ${SUBSCRIPTION_DOMAIN:+"$SUBSCRIPTION_DOMAIN"} <<'PY'
import socket,sys
for host in sys.argv[1:]:
 a={r[4][0] for r in socket.getaddrinfo(host,443,socket.AF_INET)}
 try: aaaa={r[4][0] for r in socket.getaddrinfo(host,443,socket.AF_INET6)}
 except socket.gaierror: aaaa=set()
 if not a: raise SystemExit(host+' 缺少 A 记录')
 if aaaa: raise SystemExit(host+' 存在 AAAA；请删除或使用专门的双栈方案')
 print(host+' A 记录：'+', '.join(sorted(a)))
PY
# NAT cannot reliably be inferred from local interface IPs; CA HTTP-01 proves control.
say '请确保以上 A 记录直达当前 VPS，未启用 CDN 代理；HTTP-01 将验证公网可达性。'
ufw_on=0; firewalld_on=0
if command -v ufw >/dev/null; then
 ufw_status=$(LC_ALL=C ufw status)
 if [[ $ufw_status == 'Status: active'* ]]; then ufw_on=1; fi
fi
if systemctl is-active --quiet firewalld; then firewalld_on=1; fi
((ufw_on + firewalld_on < 2)) || die '检测到两个防火墙管理器同时启用，请先整理。'
if [[ $FIREWALL == auto ]]; then
 if ((ufw_on)); then FIREWALL=ufw
 elif ((firewalld_on)); then FIREWALL=firewalld
 else FIREWALL=external; say '未发现已启用的 UFW/firewalld；保留现有防火墙，请自行确认主机和云安全组端口放行。'; fi
fi
TCP_PORTS=(80 8447 8443 8444 8445 8446 8388)
UDP_PORTS=(8447 2443 2444 8388)
case "$FIREWALL" in
 ufw)
  ((ufw_on && !firewalld_on)) || die 'ufw 模式要求仅 UFW 已启用。'
  for p in "${TCP_PORTS[@]}"; do ufw allow "$p/tcp" comment sing-box-vps; done
  for p in "${UDP_PORTS[@]}"; do ufw allow "$p/udp" comment sing-box-vps; done;;
 firewalld)
  ((firewalld_on && !ufw_on)) || die 'firewalld 模式要求仅 firewalld 已启用。'
  # Require one active zone: avoid silently modifying the wrong interface zone.
  mapfile -t zones < <(firewall-cmd --get-active-zones | sed -n '/^[^ ]/p')
  ((${#zones[@]} == 1)) || die 'firewalld 需要恰好一个活动 zone；复杂配置请使用 external。'
  for proto in tcp udp; do
   if [[ $proto == tcp ]]; then ps=("${TCP_PORTS[@]}"); else ps=("${UDP_PORTS[@]}"); fi
   for p in "${ps[@]}"; do
    firewall-cmd --zone="${zones[0]}" --add-port="$p/$proto"
    firewall-cmd --permanent --zone="${zones[0]}" --add-port="$p/$proto"
   done
  done;;
 external) say '未修改主机防火墙；公网可达性尚未验证。';;
esac
say "下载官方 sing-box $SB_VERSION 并核对 GitHub 发布资产 SHA-256……"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
 "https://api.github.com/repos/SagerNet/sing-box/releases/tags/v$SB_VERSION" -o "$WORK/release.json"
python3 - "$WORK" "$SB_VERSION" "$ARCH" <<'PY'
import sys,json,pathlib,urllib.request,hashlib,tarfile
w=pathlib.Path(sys.argv[1]); ver,arch=sys.argv[2:]
r=json.loads((w/'release.json').read_text())
assert r['tag_name']=='v'+ver and not r['prerelease'] and not r['draft']
name=f'sing-box-{ver}-linux-{arch}.tar.gz'
a=next(x for x in r['assets'] if x['name']==name)
digest=a.get('digest','')
if not digest or not digest.startswith('sha256:'): raise SystemExit('官方资产缺少 SHA-256，拒绝不校验下载')
url=a['browser_download_url']
assert url==f'https://github.com/SagerNet/sing-box/releases/download/v{ver}/{name}'
with urllib.request.urlopen(url,timeout=120) as f: data=f.read()
if hashlib.sha256(data).hexdigest()!=digest[7:]:raise SystemExit('SHA-256 不匹配')
(w/name).write_bytes(data)
with tarfile.open(w/name) as t:
 m=t.getmember(f'sing-box-{ver}-linux-{arch}/sing-box')
 assert m.isfile() and m.size < 300_000_000
 with t.extractfile(m) as src: (w/'sing-box').write_bytes(src.read())
(w/'sing-box').chmod(0o700)
(w/'download-sha256.txt').write_text(name+' '+digest+'\n')
PY
SB=$WORK/sing-box
"$SB" version > "$STAGE/version.txt"
"$SB" version | head -n1 | grep -Fx "sing-box version $SB_VERSION" >/dev/null || die '二进制版本不符。'
# Verify chosen REALITY target is a reachable TLS1.3 endpoint with matching certificate.
timeout 25 openssl s_client -connect "$REALITY_HOST:443" -servername "$REALITY_HOST" \
 -tls1_3 -verify_return_error -verify_hostname "$REALITY_HOST" </dev/null > "$WORK/reality-probe.txt" 2>&1 \
 || die 'REALITY 目标 TLS1.3/证书验证失败，请换 --sni。'
# Generate secrets using native commands, never print them to terminal.
"$SB" generate reality-keypair > "$STAGE/reality-keypair.txt"
for name in reality_uuid ws_uuid tuic_uuid; do "$SB" generate uuid > "$STAGE/$name"; done
for name in trojan_password hy2_password tuic_password anytls_password naive_password ss_key; do
 "$SB" generate rand --base64 32 > "$STAGE/$name"
done
"$SB" generate rand --hex 8 > "$STAGE/short_id"
"$SB" generate rand --hex 12 > "$STAGE/ws_token"
"$SB" generate rand --hex 12 > "$STAGE/grpc_token"
# Embedded renderer also used by the local verification harness.
python3 - "$STAGE" "$DOMAIN" "$REALITY_HOST" "$BASE" <<'PYCONFIG'
import sys,pathlib,json,re,base64,uuid
from urllib.parse import quote
s=pathlib.Path(sys.argv[1]); domain,target,base=sys.argv[2:]
def read(n): return (s/n).read_text().strip()
keys=dict(line.split(':',1) for line in read('reality-keypair.txt').splitlines())
private,public=keys['PrivateKey'].strip(),keys['PublicKey'].strip()
assert re.fullmatch(r'[A-Za-z0-9_-]{43}',private) and re.fullmatch(r'[A-Za-z0-9_-]{43}',public)
for k in ['reality_uuid','ws_uuid','tuic_uuid']: uuid.UUID(read(k))
assert re.fullmatch('[0-9a-f]{16}',read('short_id'))
assert len(base64.b64decode(read('ss_key'),validate=True))==32
ws='/'+read('ws_token'); grpc='grpc'+read('grpc_token')
cert=f'{base}/tls/current'
def tls(alpn=None):
 t={'enabled':True,'server_name':domain,'min_version':'1.3','certificate_path':cert+'/fullchain.pem','key_path':cert+'/privkey.pem'}
 if alpn:t['alpn']=alpn
 return t
def inbound(kind,port,**kw):return dict(type=kind,tag=kw.pop('tag',kind),listen='0.0.0.0',listen_port=port,**kw)
def user(k):return [{'name':'default','password':read(k)}]
reality={'enabled':True,'server_name':target,'reality':{'enabled':True,'handshake':{'server':target,'server_port':443},'private_key':private,'short_id':[read('short_id')]}}
ins=[
 inbound('naive',8447,users=[{'username':'default','password':read('naive_password')}],tls=tls()),
 inbound('vless',8443,tag='vless-reality',users=[{'name':'default','uuid':read('reality_uuid'),'flow':'xtls-rprx-vision'}],tls=reality),
 inbound('vless',8444,tag='vless-ws',users=[{'name':'default','uuid':read('ws_uuid')}],tls=tls(['http/1.1']),transport={'type':'ws','path':ws}),
 inbound('trojan',8445,users=user('trojan_password'),tls=tls(['h2']),transport={'type':'grpc','service_name':grpc}),
 inbound('hysteria2',2443,users=user('hy2_password'),tls=tls(['h3'])),
 inbound('tuic',2444,users=[{'name':'default','uuid':read('tuic_uuid'),'password':read('tuic_password')}],congestion_control='cubic',zero_rtt_handshake=False,tls=tls(['h3'])),
 inbound('anytls',8446,users=user('anytls_password'),tls=tls()),
 inbound('shadowsocks',8388,method='2022-blake3-aes-256-gcm',password=read('ss_key'))]
# Deny access to local/private networks to reduce misuse of an authenticated proxy.
config={'dns':{'servers':[{'type':'local','tag':'system'}]},'log':{'level':'warn','timestamp':True},'inbounds':ins,'outbounds':[{'type':'direct','tag':'direct'}],
 'route':{'default_domain_resolver':{'server':'system','strategy':'ipv4_only'},'rules':[{'action':'resolve'},{'ip_is_private':True,'action':'reject'}],'final':'direct'}}
(s/'config.json').write_text(json.dumps(config,indent=2)+'\n')
outs=[]
for i in ins:
 o={k:v for k,v in i.items() if k in ('type','tag','transport','method','congestion_control','zero_rtt_handshake')}
 o.update(server=domain,server_port=i['listen_port'])
 if i['type']=='shadowsocks':o['password']=read('ss_key')
 else:
  u=i['users'][0]
  o.update({k:v for k,v in u.items() if k!='name'})
  o['tls']={'enabled':True,'server_name':domain,'min_version':'1.3'}
  if i['tls'].get('alpn'):o['tls']['alpn']=i['tls']['alpn']
  if i['tag']=='vless-reality':
   o['tls'].update(server_name=target,utls={'enabled':True,'fingerprint':'chrome'},reality={'enabled':True,'public_key':public,'short_id':read('short_id')})
 if i['type']=='naive':
  o['tls'].pop('min_version',None) # Cronet outbound accepts only server_name/certificate/ECH.
  o['quic']=False; o['tag']='naive-h2'; outs.append(o)
  o=json.loads(json.dumps(o));o['tag']='naive-h3';o['quic']=True
 outs.append(o)
(s/'client-outbounds.json').write_text(json.dumps({'outbounds':outs},indent=2)+'\n')
(s/'naive-client-h2.json').write_text(json.dumps({'listen':'socks://127.0.0.1:1080','proxy':f'https://default:{quote(read("naive_password"),safe="")}@{domain}:8447'},indent=2)+'\n')
(s/'naive-client-h3.json').write_text(json.dumps({'listen':'socks://127.0.0.1:1080','proxy':f'quic://default:{quote(read("naive_password"),safe="")}@{domain}:8447'},indent=2)+'\n')
# Remove intermediate individual key files. Server config retains private key;
# client-outbounds contains only public REALITY key and client credentials.
for p in list(s.iterdir()):
 if p.name not in ('config.json','client-outbounds.json','naive-client-h2.json','naive-client-h3.json','version.txt'):p.unlink()
PYCONFIG
# Isolated certbot state; no interaction with preexisting site renewal jobs.
mkdir -p "$STAGE/acme" "$STAGE/acme-work" "$STAGE/acme-logs" "$STAGE/tls"
# Commit metadata only after key generation succeeds. Failure remains recoverable, not rerun-overwritten.
useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin sb-vps
install -d -m 755 /usr/local/lib/sing-box-vps
install -m 755 "$SB" "$BIN"
cp "$WORK/download-sha256.txt" "$STAGE/"
mv "$STAGE" "$BASE"; STAGE=
COMMITTED=1
chown root:sb-vps "$BASE"
chmod 750 "$BASE"
chmod 600 "$BASE"/*json
chown root:sb-vps "$BASE/config.json"
chmod 640 "$BASE/config.json"
check_ports
say '申请 Let’s Encrypt 证书（80/tcp 必须从公网可达）……'
CERT_DOMAINS=(-d "$DOMAIN")
[[ -z $SUBSCRIPTION_DOMAIN ]] || CERT_DOMAINS+=(-d "$SUBSCRIPTION_DOMAIN")
certbot certonly --standalone --preferred-challenges http --non-interactive --agree-tos \
 --email "$EMAIL" --cert-name "$DOMAIN" "${CERT_DOMAINS[@]}" \
 --config-dir "$BASE/acme" --work-dir "$BASE/acme-work" --logs-dir "$BASE/acme-logs"
printf '%s\n' "$DOMAIN" > "$BASE/domain"
chmod 600 "$BASE/domain"
# Deploy atomically by swapping a directory symlink. Service never reads ACME private directories.
cat > "$BASE/deploy-certificate" <<'HOOK'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
BASE=/etc/sing-box-vps
DOMAIN=$(cat "$BASE/domain")
LINEAGE=$BASE/acme/live/$DOMAIN
[[ ${RENEWED_LINEAGE:-$LINEAGE} == "$LINEAGE" ]] || exit 0
exec 8>"$BASE/tls/deploy.lock"
flock 8
openssl x509 -in "$LINEAGE/fullchain.pem" -checkend 86400 -noout >/dev/null
openssl x509 -in "$LINEAGE/fullchain.pem" -checkhost "$DOMAIN" -noout >/dev/null
c=$(openssl x509 -in "$LINEAGE/fullchain.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)
k=$(openssl pkey -in "$LINEAGE/privkey.pem" -pubout -outform DER | sha256sum | cut -d' ' -f1)
[[ $c == "$k" ]] || { echo 'certificate/key mismatch' >&2; exit 1; }
new=$(mktemp -d "$BASE/tls/cert.XXXXXXXX")
chown root:sb-vps "$new"; chmod 750 "$new"
install -o root -g sb-vps -m 640 "$LINEAGE/fullchain.pem" "$new/fullchain.pem"
install -o root -g sb-vps -m 640 "$LINEAGE/privkey.pem" "$new/privkey.pem"
old=$(readlink "$BASE/tls/current" || true)
ln -s "${new##*/}" "$BASE/tls/current.next"
mv -Tf "$BASE/tls/current.next" "$BASE/tls/current"
rollback() {
 if [[ -n $old ]]; then
  ln -s "$old" "$BASE/tls/current.rollback"
  mv -Tf "$BASE/tls/current.rollback" "$BASE/tls/current"
 fi
}
if ! runuser -u sb-vps -- /usr/local/lib/sing-box-vps/sing-box check -c "$BASE/config.json"; then rollback; exit 1; fi
if systemctl is-active --quiet sing-box-vps.service; then
 if ! systemctl restart sing-box-vps.service; then rollback; systemctl restart sing-box-vps.service || true; exit 1; fi
 sleep 2
 if ! systemctl is-active --quiet sing-box-vps.service; then rollback; systemctl restart sing-box-vps.service || true; exit 1; fi
fi
# Keep current + previous certificate generation for recovery; remove older copies.
for d in "$BASE"/tls/cert.*; do
 [[ -d $d ]] || continue
 [[ ${d##*/} == "${new##*/}" || ${d##*/} == "$old" ]] || rm -rf -- "$d"
done
HOOK
chmod 700 "$BASE/deploy-certificate"
chown root:sb-vps "$BASE/tls"; chmod 750 "$BASE/tls"
"$BASE/deploy-certificate"
"$BIN" check -c "$BASE/config.json"
runuser -u sb-vps -- "$BIN" check -c "$BASE/config.json"
cat > /etc/systemd/system/sing-box-vps.service <<'UNIT'
[Unit]
Description=Isolated sing-box multi-protocol VPS server
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User=sb-vps
Group=sb-vps
ExecStartPre=/usr/local/lib/sing-box-vps/sing-box check -c /etc/sing-box-vps/config.json
ExecStart=/usr/local/lib/sing-box-vps/sing-box run -c /etc/sing-box-vps/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/sing-box-vps-renew.service <<'UNIT'
[Unit]
Description=Renew isolated sing-box VPS certificate
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
UMask=0077
ExecStart=/usr/bin/certbot renew --quiet --non-interactive --config-dir /etc/sing-box-vps/acme --work-dir /etc/sing-box-vps/acme-work --logs-dir /etc/sing-box-vps/acme-logs --deploy-hook /etc/sing-box-vps/deploy-certificate
UNIT
cat > /etc/systemd/system/sing-box-vps-renew.timer <<'UNIT'
[Unit]
Description=Twice daily sing-box certificate renewal check
[Timer]
OnCalendar=*-*-* 03,15:00:00
RandomizedDelaySec=3600
Persistent=true
[Install]
WantedBy=timers.target
UNIT
chmod 644 /etc/systemd/system/sing-box-vps*.service /etc/systemd/system/sing-box-vps-renew.timer
systemctl daemon-reload
systemctl enable --now "$UNIT"
sleep 3
systemctl is-active --quiet "$UNIT" || die '服务未正常启动。'
# Check every expected listener, not just process state.
for p in 8447 8443 8444 8445 8446 8388; do
 [[ -n $(ss -ltnH "sport = :$p") ]] || die "TCP/$p 未监听。"
done
for p in 8447 2443 2444 8388; do
 [[ -n $(ss -lunH "sport = :$p") ]] || die "UDP/$p 未监听。"
done
systemctl enable --now sing-box-vps-renew.timer
cat >/etc/fail2ban/jail.d/sing-box-vps-sshd.local <<'JAIL'
[sshd]
enabled = true
backend = systemd
mode = aggressive
port = ssh
filter = sshd
maxretry = 10
findtime = 2h
bantime = 2h
ignoreip = 127.0.0.1/8 ::1
JAIL
fail2ban-client -t
systemctl enable --now fail2ban.service
systemctl restart fail2ban.service
say '部署完成。密码未显示在终端；请安全取回 /etc/sing-box-vps/client-outbounds.json。'
say 'Naive 独立客户端配置：/etc/sing-box-vps/naive-client-h2.json 和 naive-client-h3.json。'
say '务必按说明执行续期演练并从外网逐协议测试；本机监听成功不代表云安全组可达。'
