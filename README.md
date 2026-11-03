# sing-box VPS Manager

中文说明见 [README-管理套件.md](README-管理套件.md)。

这是固定配套 sing-box 1.14.4 的多协议 VPS 部署与订阅管理项目。支持 Debian 12/13、Ubuntu 22.04/24.04（amd64/arm64）。项目仍需要部署者自行测试和审计，请勿提交真实密钥、数据库、订阅令牌或服务器备份。

响应式网页管理后台位于 [console/](console/README.md)，采用 Cloudflare Access 与独立密码/TOTP 认证。后台需要单独安装和配置；不应在认证完成前公开入口。新节点的完整初始化流程仍需在可丢弃服务器上做端到端验收。

```bash
sudo bash install-sing-box-vps.sh --domain node.example.com --email admin@example.com
```
