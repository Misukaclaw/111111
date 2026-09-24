# LazyCat 多出口单端口配置生成器（离线原型）

这个仓库目前把**已采集的** LazyCat `strace` 文本转换为 sing-box 配置：一个 Shadowsocks 2022 入站端口、每个节点一个用户密钥、每个用户路由到相应的 SOCKS5 上游。不同客户端使用同一地址和端口，通过不同密钥选择出口。sing-box 官方文档提供了 [Shadowsocks 多用户入站](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/)、[`auth_user` 路由规则](https://sing-box.sagernet.org/configuration/route/rule/)和 [SOCKS5 出站](https://sing-box.sagernet.org/configuration/outbound/socks/)的配置依据。

**当前只有离线配置生成能力。** 程序不会驱动 `proxy` 菜单，不会安装软件、启动或重载服务、修改 LXC 路由、配置 NAT/HK 转发，也不会定时扫描节点。要更新节点，须重新提供每个节点的 trace 并再次运行。生成的配置尚未在用户的 LXC、LazyCat 上游和 HK 线路上做端到端实测。

## 本地虚构样本试验

`examples/` 中的清单和两份最小 strace 文本只含 `127.0.0.1` 与 `fake-*` 凭据。打开 PowerShell，进入本仓库目录后可复制运行；私有生成文件会写到仓库目录之外：

```powershell
$privateDir = Join-Path (Split-Path (Get-Location) -Parent) 'lazycat-multi-demo-private'
py -3 -B .\cli.py --manifest .\examples\manifest.json --private-dir $privateDir --dry-run
py -3 -B .\cli.py --manifest .\examples\manifest.json --private-dir $privateDir
py -3 -B -c "import json,sys; c=json.load(open(sys.argv[1],encoding='utf-8')); print('inbounds=%d users=%d outbounds=%d' % (len(c['inbounds']),len(c['inbounds'][0]['users']),len(c['outbounds'])))" (Join-Path $privateDir 'config.json')
```

最后一行应显示 `inbounds=1 users=2 outbounds=2`。本地演示只能验证离线解析和配置生成，**不能代表真实 LXC、LazyCat 上游或 HK 转发可用**。真实 trace 可能包含凭据，不能替换这些样本提交到仓库。

## 前置条件

在 LXC 上可先运行**只读预检**，检查本机 Python 版本及 sing-box 是否能接受由 `core.py` 生成的双用户虚构配置。它只在临时目录写入随机密钥配置并随即删除，不读取真实 trace，不连接 LazyCat、停服务、改路由或驱动 `proxy` 菜单：

```sh
python3 preflight.py
python3 preflight.py --binary /usr/local/bin/sing-box
```

成功输出 `PASS`；Python 低于 3.10、找不到二进制、`version` 或 `check -c` 失败时输出不含配置密钥的 `FAIL`。预检不验证真实节点、上游 SOCKS 连接、端口可达性或 HK 转发；也不会安装或启动 sing-box。

- Alpine Linux 上有 Python **3.10 或更新版本**。`cli.py` 只使用 Python 标准库。
- 独立的 sing-box **1.11 或更新版本**，用于检查及随后由你自行部署配置；此版本要求来自配置所用的 `route.rules[].action` 字段。先运行 `sing-box version` 核对版本。Alpine 可参照[官方包管理器安装说明](https://sing-box.sagernet.org/installation/package-manager/)安装。LazyCat 自带的 `/opt/.lazycat/pproxy` 虽显示为 sing-box，其版本和对本配置的兼容性尚未验证。
- `strace` **仅在你自己采集 trace 时需要**；离线解析现有 trace 不需要它。在 Alpine 可安装 `python3 strace sing-box`，然后核对 `python3 --version` 与 `sing-box version`。
- 每个节点一份独立的 trace，内容必须包含完整成功的 `write(fd, "...", N) = N`，其中写入的 JSON 有唯一一个带 `server`、`server_port`、`username`、`password` 的 SOCKS 出站。解析器会拒绝缺失、截断或多个不同出站的 trace。

`proxy` 选节点时会启动 TUN `cat0` 并改变整台 LXC 的路由，可能中断经 HK 线路建立的远程管理连接。采集 trace 必须在可恢复的本地控制台环境中单独验证；本仓库没有执行这一过程的自动化。

## 输入与生成

在私有位置准备 `manifest.json`。它是**完整的目标节点清单**：缺席于清单的旧节点在下次正式生成时会被移除。下面的路径和名称均为示例；trace 文件本身可能包含真实上游凭据，必须放在仓库之外。

```json
{
  "nodes": [
    {"name": "示例出口甲", "trace": "/root/private-traces/exit-a.trace"},
    {"name": "示例出口乙", "trace": "/root/private-traces/exit-b.trace"}
  ]
}
```

在 Alpine 上，从仓库目录执行：

```sh
install -d -m 700 /etc/lazycat-multi
python3 cli.py --manifest /root/manifest.json --private-dir /etc/lazycat-multi --dry-run
python3 cli.py --manifest /root/manifest.json --private-dir /etc/lazycat-multi
sing-box check -c /etc/lazycat-multi/config.json
```

默认监听 `0.0.0.0:12000`；可以用 `--listen` 和 `--port` 修改生成值。`--dry-run` 只显示 `added`、`updated`、`removed`、`unchanged` 节点名称，既不写文件也不输出 SOCKS 凭据。任何节点的 trace 解析失败，整次生成会在写文件前退出。

首次正式运行会在指定私有目录生成 `master.json`、`state.json`、`config.json`。在 POSIX 系统中，目录必须是 `0700` 或更严格；文件以 `0600` 原子替换写入。三者都含有或可导出敏感密钥，**不要放进 Git 仓库或公开分享**。请单独安全备份 `master.json`；恢复时也可通过 `LC_MASTER` 环境变量提供相同主密钥。主密钥改变会改变客户端密钥。程序不打印主密钥或上游凭据。

`sing-box check` 只能检查配置语法和本机可解析的配置项，不代表上游 SOCKS 可连接、TCP/UDP NAT 映射可用，或 HK 四层转发已正确配置。当前版本不启动服务；验证实际入口和出口仍需在目标环境单独进行。

## 节点身份与风险

- 客户端密钥由主密钥和**节点显示名**推导。若 LazyCat 改了节点显示名，程序会视为删除旧节点并新增节点，客户端密钥随之改变。
- 如果节点被删除后以**相同显示名**重新加入，且沿用同一主密钥，原客户端密钥会复用。若要撤销已泄露的旧客户端密钥，当前版本不能只旋转单个节点；需要更换主密钥并更新所有客户端。
- 菜单编号可能增删或重排。此工具不解析菜单，也不以编号建立稳定身份。manifest 中的显示名必须唯一；重复名会导致生成失败。
- 上游 SOCKS 凭据或端口可能变化。旧 trace 不会自动更新；重新采集、检查并生成之后才能生效。不要把原始 trace、私有目录、`LC_MASTER` 或生成的客户端链接提交到 GitHub。

合成测试运行方式：

```sh
python3 -B -m unittest discover -v
```

测试只使用虚构数据，不连接 LXC、LazyCat、HK 服务器或外部网络。
