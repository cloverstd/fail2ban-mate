# 验证范围

## 自动检查

- Cloudflare Workers 测试运行在本地 workerd，使用真实 D1、Durable Objects、RSA JWT 签名与验证；仅 JWKS 下载使用测试密钥响应。
- 覆盖无效/过期身份、错误 AUD、非管理员邮箱、跨站写入、单次安装凭据、token 哈希和撤销、跨节点命令隔离。
- 覆盖 WebSocket 升级、休眠后恢复、配置推送、撤销后的断连，以及重复事件、旧消息重试、全量快照、读取失败 jail 保留、消失 jail 清理、命令重试/结果/过期、全局规则跨节点传播及 IPv4/IPv6 脱敏。
- Go race tests 覆盖采集对账、本地队列与权限、跨进程重启后的命令去重、白名单归属、原有 IP/CIDR 保留、断网到期、fail2ban 重启及新 jail 继承、传输降级状态机，并使用真实 HTTP/WebSocket 测试连续拒连后的 HTTP 降级和在线切换。
- 浏览器检查在真实 Chromium 中执行，覆盖地图与筛选、桌面/手机布局、节点创建、安装命令，以及封禁/解封/加白的界面输入。数据为测试专用合成数据，未作为生产数据写入。
- 安装脚本在隔离临时目录中模拟 Debian/Ubuntu 的 apt、RHEL 系的 dnf/yum 与 systemd；实际验证解包、SHA-256、文件权限、升级、卸载和注册失败回滚。
- Go 发布流程交叉编译 Linux amd64 / arm64，生成并校验发布文件；本机直接运行验证 amd64 版本命令。arm64 实机运行属于上线后的验收项。

## 上线环境验收

本地自动检查不等同于以下真实环境验证。这些项目需部署凭据或用户节点：

1. Cloudflare 生产账号中的 D1 迁移、Durable Objects 绑定、Workers 域名和 GitHub Access 登录。
2. Debian/Ubuntu、Rocky/AlmaLinux 实机的 systemd 启动、发行版包仓库、jail/防火墙规则以及重启后的行为。
3. arm64 Linux 实机安装与运行。
4. 两台实际节点上产生封禁，确认城市、地图连线、远程控制和跨节点全局规则；阻断节点 WSS 出站但保留 HTTPS，确认自动降级和恢复。

推荐使用独立测试 IP 与测试 jail 验证控制，避免把自己的管理来源误加入封禁。记录测试节点、发行版、fail2ban 版本及客户端版本，以便复现。
