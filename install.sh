#!/bin/sh
# Bootstrap from a public checkout on the target Alpine LXC.
# --no-scan: only update the program and commands; keep the running config.
set -eu

NO_SCAN=0
for arg in "$@"; do
    case "$arg" in
        --no-scan) NO_SCAN=1 ;;
        *) echo "未知参数: $arg" >&2; exit 1 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo '请以 root 运行' >&2; exit 1; }
[ -f /etc/alpine-release ] || { echo '当前安装器仅支持 Alpine Linux' >&2; exit 1; }
[ -x /usr/local/bin/proxy ] || { echo '找不到 LazyCat /usr/local/bin/proxy' >&2; exit 1; }

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TARGET_DIR=/usr/local/libexec/lazycat-multi
SERVICE=/etc/init.d/lazycat-multi

echo '[准备] 安装 Alpine 依赖...'
apk add --no-cache python3 strace iproute2 openrc sing-box ca-certificates
python3 -c 'import sys; assert sys.version_info >= (3, 10), "需要 Python 3.10+"'
BINARY=$(command -v sing-box)

if [ -L "$SERVICE" ]; then
    echo '同名 OpenRC 服务是符号链接；停止安装' >&2
    exit 1
fi
if [ -e "$SERVICE" ] && ! grep -q '^# Managed by lazycat-multi$' "$SERVICE"; then
    echo '同名 OpenRC 服务已存在且不是本项目创建；停止安装' >&2
    exit 1
fi

if [ -f /run/lazycat-multi/guard.json ]; then
    echo '已有扫描任务在运行；先用 lazycat-status 查看进度' >&2
    exit 1
fi

install -d -m 0755 "$TARGET_DIR"
for name in core.py trace_parser.py preflight.py online.py cli.py; do
    install -m 0644 "$SOURCE_DIR/$name" "$TARGET_DIR/$name"
done
install -d -m 0700 /etc/lazycat-multi /var/log/lazycat-multi

# Run the gateway from a renamed copy: LazyCat's own stop routine may kill
# processes named "sing-box". Replace by rename so a running copy is untouched.
cp "$BINARY" "$TARGET_DIR/gateway.new"
chmod 0755 "$TARGET_DIR/gateway.new"
mv -f "$TARGET_DIR/gateway.new" "$TARGET_DIR/gateway"
BINARY="$TARGET_DIR/gateway"

cat > "$SERVICE" <<EOF
#!/sbin/openrc-run
# Managed by lazycat-multi
name="LazyCat multi-exit"
description="Single-port Shadowsocks 2022 multi-exit gateway"
command="$BINARY"
command_args="run -c /etc/lazycat-multi/current/config.json"
supervisor=supervise-daemon
respawn_delay=2
respawn_max=0
output_log="/var/log/lazycat-multi/service.log"
error_log="/var/log/lazycat-multi/service.err"
depend() { need net; }
EOF
chmod 0755 "$SERVICE"

for action in sync status list links test export; do
    cat > "/usr/local/bin/lazycat-$action" <<EOF
#!/bin/sh
exec python3 "$TARGET_DIR/online.py" "$action" "\$@"
EOF
    chmod 0755 "/usr/local/bin/lazycat-$action"
done

echo '[预检] 检查 sing-box 多用户配置...'
python3 "$TARGET_DIR/preflight.py" --binary "$BINARY"
if [ "$NO_SCAN" -eq 1 ]; then
    if [ -L /etc/lazycat-multi/current ]; then
        # Pick up the new service definition; also revives a crashed gateway.
        if rc-service lazycat-multi status >/dev/null 2>&1; then
            rc-service lazycat-multi restart >/dev/null 2>&1 || true
        else
            rc-service lazycat-multi zap >/dev/null 2>&1 || true
            pkill -f 'run -c /etc/lazycat-multi/current/config.json' 2>/dev/null || true
            rc-service lazycat-multi start >/dev/null 2>&1 || true
        fi
        sleep 3
        if rc-service lazycat-multi status >/dev/null 2>&1; then
            echo '[完成] 网关已用新程序重新运行'
        else
            echo '[警告] 网关未能启动，请查看 /var/log/lazycat-multi/service.err' >&2
        fi
    fi
    echo '[完成] 程序和命令已更新；未扫描节点，密码不变。'
    exit 0
fi
echo '[开始] 后台扫描与部署；SSH 暂断时任务仍会继续。'
exec python3 "$TARGET_DIR/online.py" install
