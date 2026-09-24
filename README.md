# LazyCat 单端口多出口（Alpine LXC 试运行版）

这个项目从 LazyCat 当前 `proxy` 菜单读取节点，逐个采集真实 SOCKS 上游，部署一个 sing-box Shadowsocks 2022 多用户入口。所有出口共用 LXC 的 `12000` 端口；每个节点有自己的客户端密钥。LXC 内同时监听 TCP/UDP，但当前 LazyCat NAT 只支持 TCP 映射，所以外网接入按 TCP 使用。以后执行 `lazycat-sync` 可重新扫描菜单并处理节点增删或上游变化。

**状态：已通过合成测试，仍需根据你的 LXC 实机结果迭代。** 安装器会在 LXC 内实测每个 SOCKS 上游和用户路由；单个新节点不可用时会标为 `SKIPPED`，旧节点重新抓取失败但旧凭据仍可用时会标为 `STALE`。至少一个出口通过验证才会启动新配置。若已有本项目服务，切换失败会恢复上一版。真实的 LazyCat 菜单、`proxy` 进程和网络路由仍可能与已有样本不同，以 `lazycat-status` 的结果为准。

## 一条命令开始安装

在 **Alpine LXC 的 root SSH** 中粘贴这一行：

```sh
apk add --no-cache git && (git -C /root/lazycat-multi pull --ff-only || git clone https://github.com/Misukaclaw/111111.git /root/lazycat-multi) && sh /root/lazycat-multi/install.sh
```

这条命令安装依赖、检查 sing-box 是否接受双用户配置，然后启动独立后台任务。扫描时 LazyCat 可能切换默认路由，SSH 可能短暂断开；后台任务会继续，超时看门狗会尝试停止 LazyCat TUN 并恢复扫描前的默认路由及策略规则。重新连接后运行：

```sh
lazycat-status
```

看到 `ok` 或 `partial: LXC 本机服务已启动`，并且 `OpenRC: running`，才表示 LXC 本机已有可用出口。`partial` 表示有节点被跳过，用 `lazycat-list` 查看具体名称。看到 `failed` 时，把 `lazycat-status` 的完整输出发来排查；**不要发送** `/etc/lazycat-multi/` 下的 JSON、原始 trace 或带密钥的链接。

安装器要求：Alpine Linux、root、现存 `/usr/local/bin/proxy`、一条未指向 `cat0` 的 IPv4 默认路由、可用的 `apk` 源。若不满足条件，会停止而不开始节点扫描。首次通过 SSH 自动抓取节点仍有失联风险；看门狗只能按扫描前快照尝试恢复，不能保证处理供应商程序的所有异常行为。

## 安装后使用

```sh
lazycat-list                 # 节点、SOCKS 上游地址和实际出口 IP
lazycat-test                 # 再次实测已启用的每个密钥和出口
lazycat-status               # 后台任务、OpenRC 状态与最近日志
lazycat-sync                 # 节点增删或凭据变化时重新扫描与部署
lazycat-links HK_IP HK_PORT  # 输出客户端 ss:// 链接，含密钥，勿公开
```

LXC 本机启动后，外网连接仍需要两段**一次性**配置；这些设置无法从 LXC 内自动代办。以 LazyCat NAT 公网端口 `32000`、香港机监听端口 `25000` 为例（实际端口自行选择）：

1. LazyCat NAT 面板选择 **TCP**，添加 `公网端口 32000 → 这台 LXC 的内部端口 12000`。若公网端口留空由平台分配，记下实际分配值。
2. 香港机 3x-ui「入站列表 → 添加入站」选 **Tunnel / Dokodemo-door**：监听地址留空或填 `0.0.0.0`，监听端口填 `25000`，`rewriteAddress` 填 LazyCat NAT 的公网地址，`rewritePort` 填其实际公网端口，`allowedNetwork` 选 `TCP`，`followRedirect` 关闭。该入站走 `direct` 出站，并在香港机防火墙放行 `25000/TCP`。一个 Tunnel 入站即可转发所有 SS 用户，香港机不解密 SS。

之后使用 `lazycat-links HK_IP 25000` 生成的链接导入客户端。各链接的 HK 地址与端口相同，密钥不同。不要把 HK 的端口填成 LXC 内部的 `12000`，除非 HK 实际对外监听的就是这个端口。3x-ui 的 Tunnel 入站不会生成这 10 个 SS 用户的订阅链接；链接由 LXC 的 `lazycat-links` 输出。

**TCP 映射的限制：** 普通 SS 客户端发出的原生 UDP 无法穿过这条 NAT 映射，游戏、语音以及某些 DNS/QUIC 功能可能无法使用。`ss://` 链接本身也不会自动启用 UDP over TCP。支持 sing-box UoT 的客户端可另行开启并实测；UoT 属于额外扩展，客户端版本和配置必须匹配。当前 `lazycat-test` 只验证 TCP/HTTPS 出口，不代表 UDP 已可用。

## 实现与边界

- 扫描一次只接受完整、无重复的菜单；每个节点 trace 必须含唯一、完整写入的 SOCKS 配置。单个节点抓取或出口验证失败会跳过该节点；同名旧节点若仍可连接，会暂用旧上游并标为 `STALE`。菜单中没有任何可用出口、菜单中途变化或网络路由恢复失败时，整次同步不切换正式配置。
- 每个上游先通过 SOCKS5 验证 HTTPS 出口 IP；候选 sing-box 在回环地址运行，再用各 SS 用户密钥逐一验证路由。正式 OpenRC 服务启动后会重复用户到出口验证，失败则回滚。
- `proxy` 的节点选择会启动供应商 TUN。扫描任务脱离 SSH 会话运行；每次选择后调用供应商菜单停止 TUN，核对并尝试恢复默认路由与策略规则。看门狗负责处理任务意外退出或长时间无进展。
- 主密钥、SOCKS 凭据、配置及出口清单保存在 LXC 的 `/etc/lazycat-multi/generations/`，目录权限 `0700`、文件 `0600`。GitHub 仓库只含程序和虚构测试样本。备份当前的 `/etc/lazycat-multi/current/master.json`；重装时把其中 `master` 字段的值用于 `LC_MASTER='该字段的值' sh /root/lazycat-multi/install.sh`，即可恢复相同客户端密钥。若已有主密钥，环境值不一致会报错。
- 本机测试只验证 TCP/HTTPS 的出口映射和 OpenRC 监听。UDP 数据、LazyCat NAT、HK 转发及手机客户端导入须在相应环境测试；`sing-box check` 也不能证明这些外部链路可用。
- 如果 `proxy` 修改了本程序无法恢复的网络配置，`lazycat-status` 会显示恢复失败。只有 SSH 访问的机器仍可能需要管理方协助修复网络；请在可接受这项风险的测试 LXC 上试运行。

协议配置依据：[sing-box Shadowsocks 多用户入站](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/)、[按 `auth_user` 匹配的路由规则](https://sing-box.sagernet.org/configuration/route/rule/)、[SOCKS 出站](https://sing-box.sagernet.org/configuration/outbound/socks/)、[UoT 说明](https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/)、[3x-ui Tunnel 表单](https://github.com/MHSanaei/3x-ui/blob/main/frontend/src/pages/inbounds/form/protocols/tunnel.tsx)、[Alpine 安装](https://sing-box.sagernet.org/installation/package-manager/)。

原始脚本的静态缺陷见 [ORIGINAL_SCRIPT_REVIEW.md](ORIGINAL_SCRIPT_REVIEW.md)。离线配置生成器仍可按 `python3 cli.py --help` 使用。运行合成测试：

```sh
python3 -B -m unittest discover -v
```
