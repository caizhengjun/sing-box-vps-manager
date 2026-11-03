# sing-box 多服务器管理套件

面向自有 VPS 的多协议部署与订阅管理工具，固定配套 `sing-box 1.14.4`。支持 Debian 12/13、Ubuntu 22.04/24.04，架构为 amd64 或 arm64。请仅在当地法律和服务商条款允许的范围内使用。

> 当前状态：单节点 Ubuntu 24.04 实机部署、本机接管、逐用户计量和 HTTPS 订阅已验证；远端 SSH 接管、arm64 和多节点故障恢复仍需更多实机验证。建议先在测试服务器演练。

## 功能与端口

- Naive：8447/TCP+UDP
- VLESS REALITY：8443/TCP
- VLESS WebSocket：8444/TCP
- Trojan gRPC：8445/TCP
- Hysteria2：2443/UDP；TUIC：2444/UDP
- AnyTLS：8446/TCP
- Shadowsocks 2022：8388/TCP+UDP；管理器多用户入口为 8389/TCP+UDP
- HTTPS 订阅：主服务器 443/TCP；Let's Encrypt HTTP-01：80/TCP

脚本仅为已经启用的 UFW 或 firewalld 追加代理端口；云安全组仍需自行配置。安装器保留 root 密码登录的现状，不修改 `sshd_config`。它会安装并启用 Fail2ban：SSH 在 2 小时内失败 10 次后封禁 2 小时。

## 基础安装

准备一个直接指向 VPS IPv4 的 DNS A 记录，不要启用 CDN，并删除该名称的 AAAA 记录：

```bash
sudo bash install-sing-box-vps.sh \
  --domain node.example.com \
  --email admin@example.com \
  --sni www.microsoft.com
```

同机还要安装订阅管理器时，首次签发证书需加入订阅域名：

```bash
sudo bash install-sing-box-vps.sh \
  --domain node.example.com \
  --subscription-domain sub.example.com \
  --email admin@example.com
```

脚本不会覆盖已有安装，也不会把密码打印到终端。客户端材料保存在 root 专用的 `/etc/sing-box-vps/`。部署后必须从外网分别验证 TCP、UDP、DNS 和实际网站访问；本机监听不代表云防火墙已放行。

## 安装管理器

将本目录完整上传到主服务器：

```bash
sudo bash install-manager.sh --domain sub.example.com
sudo /opt/sb-manager/manage-servers.sh add
```

登记本机时，SSH 地址填 `local`。登记成功后启动订阅和对账：

```bash
sudo systemctl enable --now sb-subscription.service sb-manager-reconcile.timer
```

`sb-sni-monitor.timer` 是可选功能，只有另行安装 `/opt/module/Reality-SNI-Check.sh` 后才应启用；本项目不会下载未知第三方检测脚本。SNI 不会无依据地自动更换，也可用节点 `sni` 命令显式更新。

新增远端服务器时，向导会要求 SSH 地址、独立核对的 SHA256 主机指纹、客户端域名、证书邮箱、REALITY SNI 和标签。选择“全新安装”即可把基础脚本部署到日本或其他地区的新 VPS；前提是系统、DNS、端口和证书条件满足。节点名由管理员输入，例如 `🇯🇵 JP-TYO`，不会自动加入服务商名称。

## 管理和订阅

```bash
sudo /opt/sb-manager/manage-servers.sh
sudo /opt/sb-manager/manage-plans.sh
sudo /opt/sb-manager/manage-users.sh
sudo /opt/sb-manager/manage.sh
```

数据库位于 `/var/lib/sb-manager/manager.sqlite`，只能由 root 读取；订阅服务只读取去除明文令牌的发布快照。普通用户路径为 `/sub/<令牌>`，管理员路径为 `/admin/<令牌>`，格式包括 `singbox`、`mihomo`、`base64` 和 `links`。

`format=singbox` 是兼容版，只输出 VLESS（REALITY/WS）、Trojan、Hysteria2、TUIC 和 SS2022，不输出 AnyTLS、Naive。`format=karing` 是全量版，输出所有已授权协议，包括 AnyTLS 和 Naive H2/H3；能否运行仍取决于客户端版本和构建能力，不保证所有旧版 Karing 都支持。两种格式均可生成独立二维码。Mihomo 和通用链接不输出 Naive。

管理器约每 30 秒同步流量和授权，不承诺字节级硬限额；断线或异常退出附近可能有少量遗漏。停用或删除用户会撤销协议凭据，只更换订阅令牌不会撤销客户端已取得的旧凭据。

## 安全、备份与验证

- 密钥、数据库、订阅令牌和备份都不得提交到 Git。
- 建议使用 SQLite 在线备份；直接复制 WAL 模式主文件可能丢数据。
- 同时备份节点的 `/etc/sing-box-vps`、`/var/lib/sb-node/node.sqlite` 和 `/var/lib/sb-node/state.json`。
- Fail2ban 不能替代 SSH 密钥、强 root 密码、云防火墙和系统更新。
- 安装器固定下载官方 release，并验证发布资产的 SHA-256。

```bash
bash -n ./*.sh
python3 -m py_compile lib/*.py
python3 -m unittest discover -s tests -v
```

订阅 HTTP 测试需要 `aiohttp`，缺少时会跳过。实现依据包括 [sing-box v1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4)、[V2Ray API 统计](https://sing-box.sagernet.org/configuration/experimental/v2ray-api/)、[SS2022 多用户](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/) 和 [Certbot 续期钩子](https://eff-certbot.readthedocs.io/en/stable/using.html)。
