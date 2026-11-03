#!/usr/bin/env bash
# Fixed official source version, Go checksum database enabled. Server-only build.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
[[ $EUID == 0 && $(uname -s) == Linux ]] || { echo '需要 Linux root。' >&2; exit 1; }
case $(uname -m) in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; *) exit 1;; esac
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-grpcio ca-certificates curl git openssl util-linux
CACHE=/var/cache/sb-manager-build
install -d -m 700 "$CACHE"
exec 9>"$CACHE/lock"
flock 9
python3 - "$CACHE" "$ARCH" <<'PY'
import hashlib,json,pathlib,sys,tarfile,urllib.request
cache=pathlib.Path(sys.argv[1]);arch=sys.argv[2];version='go1.26.10'
manifest=json.load(urllib.request.urlopen('https://go.dev/dl/?mode=json&include=all',timeout=60))
release=next((r for r in manifest if r['version']==version),None)
if release is None:raise SystemExit('官方 Go 工具链版本不可用，停止构建')
a=next(x for x in release['files'] if x['os']=='linux' and x['arch']==arch and x['kind']=='archive')
archive=cache/a['filename']
if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest()!=a['sha256']:
 with urllib.request.urlopen('https://go.dev/dl/'+a['filename'],timeout=120) as r:data=r.read()
 if hashlib.sha256(data).hexdigest()!=a['sha256']:raise SystemExit('Go SHA-256 不匹配')
 archive.write_bytes(data)
with tarfile.open(archive) as t:
 for m in t.getmembers():
  target=(cache/m.name).resolve()
  if not target.is_relative_to(cache.resolve()) or m.issym() or m.islnk() or not(m.isfile() or m.isdir()):raise SystemExit('Go 归档路径无效')
 t.extractall(cache)
PY
export GOPATH="$CACHE/gopath" GOMODCACHE="$CACHE/modules" GOCACHE="$CACHE/cache"
export GOTOOLCHAIN=local GOENV=off CGO_ENABLED=0 GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
export GOBIN="$CACHE/bin"
"$CACHE/go/bin/go" install -trimpath -tags 'with_quic,with_utls,with_v2ray_api,with_grpc' \
 -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.4' \
 github.com/sagernet/sing-box/cmd/sing-box@v1.14.4
"$CACHE/bin/sing-box" version | grep -F with_v2ray_api >/dev/null
install -d -m 755 /usr/local/lib/sing-box-vps
# Do not replace the running binary here. Enrolment performs transactional replacement.
install -m 755 "$CACHE/bin/sing-box" /usr/local/lib/sing-box-vps/sing-box-metered
