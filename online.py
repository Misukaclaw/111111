#!/usr/bin/env python3
"""Alpine LXC discovery and guarded deployment for LazyCat multi-exit.

The public repository contains no node credentials. Live captures and all
derived keys stay in root-only directories on the LXC.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from typing import Any

try:  # Allow pure parser/probe tests on non-Linux development machines.
    import fcntl
    import pty
except ImportError:  # pragma: no cover - the installer only runs on Alpine
    fcntl = None  # type: ignore[assignment]
    pty = None  # type: ignore[assignment]

import core
import preflight
from trace_parser import TraceParseError, extract_socks_outbound


APP = Path("/etc/lazycat-multi")
GENERATIONS = APP / "generations"
CURRENT = APP / "current"
RUNTIME = Path("/run/lazycat-multi")
LOG = Path("/var/log/lazycat-multi/install.log")
GUARD = RUNTIME / "guard.json"
STATUS = RUNTIME / "status.json"
LOCK = RUNTIME / "lock"
PROXY = "/usr/local/bin/proxy"
SERVICE = "lazycat-multi"
SERVICE_FILE = Path("/etc/init.d/lazycat-multi")
PORT = 12000
MAX_NODES = 100
WATCHDOG_SECONDS = 90
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MENU_ENTRY = re.compile(r"^\s*\[(\d+)\]\s*(.*?)\s*$")
INITIAL_PROMPT = re.compile(r"选择[^\r\n]{0,60}[:：]")
NODE_PROMPT = re.compile(r"请输入节点\s*ID[^\r\n]{0,60}[:：]", re.I)


class OnlineError(Exception):
    """Safe error text which must never contain a captured credential."""


def parse_menu(text: str) -> list[tuple[int, str]]:
    """Accept a complete menu only after its node-ID prompt was captured."""
    clean = ANSI.sub("", text).replace("\r", "")
    if not NODE_PROMPT.search(clean):
        raise OnlineError("LazyCat 节点菜单未完整显示")
    entries: list[tuple[int, str]] = []
    ids: set[int] = set()
    names: set[str] = set()
    for line in clean.splitlines():
        match = MENU_ENTRY.match(line)
        if not match:
            continue
        number, name = int(match.group(1)), match.group(2).strip()
        if (number < 1 or not name or number in ids or name in names
                or any(ord(char) < 32 or ord(char) == 127 for char in name)):
            raise OnlineError("LazyCat 菜单含重复编号、重复名称或空名称")
        ids.add(number)
        names.add(name)
        entries.append((number, name))
    if not 1 <= len(entries) <= MAX_NODES:
        raise OnlineError("LazyCat 节点数量不在允许范围内")
    return entries


def _read_until(fd: int, pattern: re.Pattern[str], seconds: float) -> str:
    deadline = time.monotonic() + seconds
    data = bytearray()
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        ready, _, _ = select.select([fd], [], [], max(0, min(remaining, 0.5)))
        if not ready:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError as exc:
            raise OnlineError("LazyCat 菜单进程提前结束") from exc
        if not chunk:
            raise OnlineError("LazyCat 菜单进程提前结束")
        data.extend(chunk)
        if len(data) > 1024 * 1024:
            raise OnlineError("LazyCat 菜单输出异常过长")
        clean = ANSI.sub("", data.decode("utf-8", "replace"))
        if pattern.search(clean):
            return clean
    raise OnlineError("等待 LazyCat 菜单超时")


def _spawn_menu(argv: list[str]) -> tuple[int, int]:
    if pty is None:
        raise OnlineError("节点扫描仅支持 Linux")
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvp(argv[0], argv)
        except OSError:
            os._exit(127)
    return pid, fd


def _terminate_menu(pid: int, fd: int) -> None:
    try:
        os.killpg(pid, signal.SIGINT)
    except ProcessLookupError:
        pass
    for _ in range(10):
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            done = pid
        if done:
            break
        time.sleep(0.1)
    else:
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        for _ in range(10):
            try:
                done, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                done = pid
            if done:
                break
            time.sleep(0.1)
        else:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
    os.close(fd)


def _menu_to_node_prompt(fd: int) -> str:
    _read_until(fd, INITIAL_PROMPT, 20)
    os.write(fd, b"1\n")
    return _read_until(fd, NODE_PROMPT, 30)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    core.save_private_json(path, value)


def _guard_update(**changes: Any) -> None:
    if not GUARD.exists():
        return
    current = json.loads(GUARD.read_text(encoding="utf-8"))
    current.update(changes)
    current["heartbeat"] = time.time()
    _write_json(GUARD, current)


def capture_menu() -> list[tuple[int, str]]:
    pid, fd = _spawn_menu([PROXY])
    _guard_update(scanner_pgid=pid)
    try:
        return parse_menu(_menu_to_node_prompt(fd))
    finally:
        _terminate_menu(pid, fd)
        _guard_update(scanner_pgid=0)


def _extract_traces(prefix: Path) -> dict[str, object]:
    traces = sorted(prefix.parent.glob(prefix.name + ".*"))
    if not traces:
        raise TraceParseError("no trace")
    chunks = []
    total = 0
    for path in traces:
        total += path.stat().st_size
        if total > 32 * 1024 * 1024:
            raise TraceParseError("trace too large")
        chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return extract_socks_outbound("\n".join(chunks))


def scan_one(number: int, name: str, expected_menu: list[tuple[int, str]], work: Path) -> core.Node:
    prefix = work / f"trace-{number}"
    pid, fd = _spawn_menu(["strace", "-ff", "-s", "65535", "-e", "trace=write", "-o", str(prefix), PROXY])
    _guard_update(scanner_pgid=pid)
    try:
        menu = parse_menu(_menu_to_node_prompt(fd))
        if menu != expected_menu:
            raise OnlineError("扫描期间 LazyCat 节点菜单发生变化")
        os.write(fd, f"{number}\n".encode("ascii"))
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                data = _extract_traces(prefix)
            except (TraceParseError, OSError):
                time.sleep(0.25)
                continue
            return core.Node(name, str(data["server"]), int(data["server_port"]),
                             str(data["username"]), str(data["password"]))
        raise OnlineError(f"节点 {number} 未抓到唯一完整的 SOCKS 配置")
    finally:
        _terminate_menu(pid, fd)
        _guard_update(scanner_pgid=0)


def stop_vendor() -> None:
    """Use the vendor's own stop menu; never pkill by a broad name pattern."""
    pid, fd = _spawn_menu([PROXY])
    _guard_update(scanner_pgid=pid)
    try:
        _read_until(fd, INITIAL_PROMPT, 15)
        os.write(fd, b"3\n")
        time.sleep(1.5)
    finally:
        _terminate_menu(pid, fd)
        _guard_update(scanner_pgid=0)


def default_route() -> str:
    result = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True,
                            text=True, timeout=5, check=False)
    if result.returncode or len(result.stdout.splitlines()) != 1:
        raise OnlineError("需要恰好一条 IPv4 默认路由，无法安全扫描")
    return result.stdout.strip()


def restore_route(baseline: str) -> None:
    try:
        if default_route() == baseline:
            return
    except OnlineError:
        pass
    # Only remove the temporary LazyCat TUN default route, if present.
    result = subprocess.run(["ip", "-4", "route", "show", "default", "dev", "cat0"],
                            capture_output=True, text=True, timeout=5, check=False)
    for line in result.stdout.splitlines():
        subprocess.run(["ip", "-4", "route", "del", *shlex.split(line)],
                       capture_output=True, timeout=5, check=False)
    subprocess.run(["ip", "-4", "route", "replace", *shlex.split(baseline)],
                   capture_output=True, timeout=5, check=False)
    if default_route() != baseline:
        raise OnlineError("默认路由未恢复，需在 LXC 管理侧检查")


def policy_rules() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for family in ("-4", "-6"):
        check = subprocess.run(["ip", family, "rule", "show"], capture_output=True,
                               text=True, timeout=5, check=False)
        if check.returncode:
            raise OnlineError("无法读取网络策略路由规则")
        result[family] = check.stdout.splitlines()
    return result


def restore_policy_rules(baseline: dict[str, list[str]]) -> None:
    """Remove only new priorities introduced during the scan."""
    current = policy_rules()
    for family in ("-4", "-6"):
        original = set(baseline[family])
        original_priorities = {line.split(":", 1)[0] for line in original}
        if not original.issubset(set(current[family])):
            raise OnlineError("扫描期间原有策略路由规则被删除，需要管理侧检查")
        for line in current[family]:
            if line in original:
                continue
            priority = line.split(":", 1)[0]
            if not priority.isdecimal() or priority in original_priorities:
                raise OnlineError("发现无法安全清理的新增策略路由规则")
            subprocess.run(["ip", family, "rule", "del", "pref", priority],
                           capture_output=True, timeout=5, check=False)
    if policy_rules() != baseline:
        raise OnlineError("策略路由规则未恢复，需要管理侧检查")


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OnlineError("SOCKS 上游提前关闭连接")
        data.extend(chunk)
    return bytes(data)


def probe_socks(host: str, port: int, username: str | None, password: str | None) -> str:
    """SOCKS5 CONNECT + HTTPS IP check; credentials never appear in argv/logs."""
    if (username is None) != (password is None):
        raise OnlineError("SOCKS 用户名与密码必须同时提供")
    for destination in ("api.ipify.org", "icanhazip.com"):
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                sock.settimeout(12)
                method = 2 if username is not None else 0
                sock.sendall(bytes([5, 1, method]))
                if _recv_exact(sock, 2) != bytes([5, method]):
                    raise OnlineError("SOCKS 身份验证方式不匹配")
                if method == 2:
                    user = username.encode("utf-8")  # type: ignore[union-attr]
                    secret = password.encode("utf-8")  # type: ignore[union-attr]
                    if not 1 <= len(user) <= 255 or not 1 <= len(secret) <= 255:
                        raise OnlineError("SOCKS 凭据长度不合规")
                    sock.sendall(bytes([1, len(user)]) + user + bytes([len(secret)]) + secret)
                    if _recv_exact(sock, 2) != b"\x01\x00":
                        raise OnlineError("SOCKS 身份验证失败")
                domain = destination.encode("ascii")
                sock.sendall(b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + b"\x01\xbb")
                reply = _recv_exact(sock, 4)
                if reply[:2] != b"\x05\x00":
                    raise OnlineError("SOCKS 连接出口检测网站失败")
                size = {1: 4, 3: None, 4: 16}.get(reply[3])
                if size is None and reply[3] == 3:
                    size = _recv_exact(sock, 1)[0]
                if size is None:
                    raise OnlineError("SOCKS 响应地址类型无效")
                _recv_exact(sock, size + 2)
                with ssl.create_default_context().wrap_socket(sock, server_hostname=destination) as tls:
                    tls.sendall((f"GET / HTTP/1.1\r\nHost: {destination}\r\nConnection: close\r\n\r\n").encode())
                    response = bytearray()
                    while len(response) < 65536:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        response.extend(chunk)
                header, separator, body = bytes(response).partition(b"\r\n\r\n")
                if not separator or b" 200 " not in header.split(b"\r\n", 1)[0]:
                    raise OnlineError("出口检测网站未返回 HTTP 200")
                if b"transfer-encoding: chunked" in header.lower():
                    length, marker, payload = body.partition(b"\r\n")
                    if not marker:
                        raise OnlineError("出口检测网站的分块响应不完整")
                    body = payload[:int(length.split(b";", 1)[0], 16)]
                return str(ipaddress.IPv4Address(body.decode("ascii").strip()))
        except (OSError, UnicodeError, ValueError, OnlineError):
            continue
    raise OnlineError("SOCKS 上游出口 IP 验证失败")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_tcp(port: int, process: subprocess.Popen[bytes]) -> None:
    for _ in range(50):
        if process.poll() is not None:
            break
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise OnlineError("候选 sing-box 未启动或未监听")


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)


def _verify_routes(binary: str, state: dict[str, Any], expected_ips: dict[str, str],
                   work: Path, server_port: int) -> None:
    for name in sorted(expected_ips):
        client_port = _free_port()
        client_config = {
            "inbounds": [{"type": "socks", "tag": "test-in", "listen": "127.0.0.1",
                          "listen_port": client_port}],
            "outbounds": [core.client_config(state, name, "127.0.0.1", server_port)],
        }
        client_path = work / "test-client.json"
        core.save_private_config(client_path, client_config)
        client = subprocess.Popen([binary, "run", "-c", str(client_path)],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        try:
            _wait_tcp(client_port, client)
            actual = probe_socks("127.0.0.1", client_port, None, None)
            print(f"[验证] {name}: {actual}", flush=True)
            if actual != expected_ips[name]:
                print(f"[提示] {name} 的公网 IP 在两次连接之间变化；"
                      "动态出口可出现这种情况", flush=True)
            _guard_update()
        finally:
            _terminate_process(client)


def verify_candidate(binary: str, state: dict[str, Any], expected_ips: dict[str, str],
                     work: Path) -> None:
    # For each user, make every *other* upstream unreachable. A successful
    # request then proves auth_user selected that user's own SOCKS outbound,
    # even if a dynamic exit's public IPv4 changes between connections.
    for name in sorted(expected_ips):
        server_port = _free_port()
        candidate = core.build_config(state, listen="127.0.0.1", listen_port=server_port)
        try:
            tag = next(rule["outbound"] for rule in candidate["route"]["rules"]
                       if rule.get("auth_user") == [name])
        except StopIteration as exc:
            raise OnlineError(f"节点 {name} 没有对应的用户路由规则") from exc
        for outbound in candidate["outbounds"]:
            if outbound["tag"] != tag:
                outbound["server"] = "127.0.0.1"
                outbound["server_port"] = 1
        server_path = work / "test-server.json"
        core.save_private_config(server_path, candidate)
        checked = subprocess.run([binary, "check", "-c", str(server_path)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 timeout=15, check=False)
        if checked.returncode:
            raise OnlineError("sing-box 拒绝候选配置")
        server = subprocess.Popen([binary, "run", "-c", str(server_path)],
                                  stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            _wait_tcp(server_port, server)
            _verify_routes(binary, state, {name: expected_ips[name]}, work, server_port)
        finally:
            _terminate_process(server)


def _load_previous() -> tuple[str, dict[str, Any] | None]:
    if not CURRENT.is_symlink():
        if CURRENT.exists():
            raise OnlineError("现有 current 不是符号链接")
        return core.generate_master(), None
    target = CURRENT.resolve(strict=True)
    if GENERATIONS not in target.parents:
        raise OnlineError("现有配置路径不在受管目录")
    state = core.load_private_state(target / "state.json")
    master = json.loads((target / "master.json").read_text(encoding="utf-8"))["master"]
    if os.environ.get("LC_MASTER") and os.environ["LC_MASTER"] != master:
        raise OnlineError("LC_MASTER 与已安装的恢复密钥不一致")
    return master, state


def _stage(state: dict[str, Any], master: str, binary: str,
           menu: list[tuple[int, str]], ips: dict[str, str]) -> Path:
    GENERATIONS.mkdir(mode=0o700, parents=True, exist_ok=True)
    generation = Path(tempfile.mkdtemp(prefix="generation-", dir=GENERATIONS))
    try:
        core.save_private_json(generation / "master.json", {"master": master})
        core.save_private_state(generation / "state.json", state)
        core.save_private_config(generation / "config.json",
                                 core.build_config(state, listen="0.0.0.0", listen_port=PORT))
        core.save_private_json(generation / "meta.json", {
            "nodes": [{"id": number, "name": name, "exit_ip": ips[name]}
                      for number, name in menu],
        })
        check = subprocess.run([binary, "check", "-c", str(generation / "config.json")],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=15, check=False)
        if check.returncode:
            raise OnlineError("sing-box 拒绝正式配置")
        return generation
    except Exception:
        shutil.rmtree(generation)
        raise


def _switch(target: Path | None) -> None:
    temporary = APP / ".current-next"
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    if target is None:
        if CURRENT.is_symlink():
            CURRENT.unlink()
        return
    temporary.symlink_to(target, target_is_directory=True)
    os.replace(temporary, CURRENT)


def _service(command: str) -> None:
    result = subprocess.run(["rc-service", SERVICE, command], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=25, check=False)
    if result.returncode:
        raise OnlineError(f"OpenRC {command} 失败")


def _deploy(generation: Path, binary: str, state: dict[str, Any],
            expected_ips: dict[str, str], work: Path) -> None:
    previous = CURRENT.resolve(strict=True) if CURRENT.is_symlink() else None
    was_running = subprocess.run(["rc-service", SERVICE, "status"], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=8, check=False).returncode == 0
    try:
        _switch(generation)
        _service("restart" if was_running else "start")
        with socket.create_connection(("127.0.0.1", PORT), timeout=4):
            pass
        _verify_routes(binary, state, expected_ips, work, PORT)
        add = subprocess.run(["rc-update", "add", SERVICE, "default"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             timeout=10, check=False)
        if add.returncode:
            raise OnlineError("OpenRC 开机自启设置失败")
    except Exception:
        _switch(previous)
        try:
            _service("restart" if was_running else "stop")
        except OnlineError:
            pass
        raise


def _status(value: str, message: str, **fields: Any) -> None:
    _write_json(STATUS, {"state": value, "message": message, "time": time.time(), **fields})


def _worker(operation: str) -> int:
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    if fcntl is None:
        raise OnlineError("安装器仅支持 Linux")
    with LOCK.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _status("failed", "已有安装或同步任务在运行")
            return 1
        try:
            baseline = default_route()
            if "cat0" in baseline:
                raise OnlineError("当前默认路由已指向 cat0，无法通过 SSH 安全恢复")
            baseline_rules = policy_rules()
        except (OnlineError, OSError, subprocess.TimeoutExpired) as exc:
            _status("failed", str(exc) if isinstance(exc, OnlineError) else "无法读取网络基线")
            return 1
        _write_json(GUARD, {"worker_pid": os.getpid(), "scanner_pgid": 0,
                            "scanning_started": False,
                            "heartbeat": time.time(), "default_route": baseline,
                            "policy_rules": baseline_rules})
        try:
            watcher = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "_watchdog"],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError:
            GUARD.unlink(missing_ok=True)
            _status("failed", "无法启动路由恢复看门狗")
            return 1
        _status("running", "开始检查 LXC 环境")
        try:
            if not Path(PROXY).is_file() or not os.access(PROXY, os.X_OK):
                raise OnlineError("找不到 LazyCat proxy 程序")
            if not SERVICE_FILE.is_file():
                raise OnlineError("OpenRC 服务文件未安装")
            binary = preflight.run("sing-box")
            previous_master, previous = _load_previous()
            master = os.environ.get("LC_MASTER") or previous_master
            core.derive_server_key(master)
            with tempfile.TemporaryDirectory(prefix="scan-", dir=RUNTIME) as directory:
                work = Path(directory)
                _status("running", "正在读取 LazyCat 节点菜单")
                menu = capture_menu()
                print(f"[扫描] 菜单中有 {len(menu)} 个节点", flush=True)
                records: list[core.Node] = []
                ips: dict[str, str] = {}
                for position, (number, name) in enumerate(menu, 1):
                    _status("running", f"正在扫描 {position}/{len(menu)}: {name}")
                    _guard_update(scanning_started=True)
                    try:
                        record = scan_one(number, name, menu, work)
                    finally:
                        try:
                            stop_vendor()
                        finally:
                            restore_route(baseline)
                            restore_policy_rules(baseline_rules)
                            _guard_update(scanning_started=False)
                    exit_ip = probe_socks(record.server, record.server_port,
                                          record.username, record.password)
                    print(f"[上游] {name}: {exit_ip}", flush=True)
                    records.append(record)
                    ips[name] = exit_ip
                    _guard_update()
                if len(records) != len(menu):
                    raise OnlineError("扫描结果与完整菜单数量不一致")
                state = core.reconcile_nodes(records, previous, master=master)
                _status("running", "逐一验证 Shadowsocks 用户到出口的映射")
                verify_candidate(binary, state, ips, work)
                generation = _stage(state, master, binary, menu, ips)
                _status("running", "正在启动 OpenRC 服务")
                _deploy(generation, binary, state, ips, work)
                print(f"[完成] {len(menu)} 个出口，LXC TCP/UDP 端口 {PORT}", flush=True)
                _status("ok", "LXC 本机服务已启动", nodes=len(menu), port=PORT)
                return 0
        except (OnlineError, preflight.PreflightError, OSError, ValueError,
                subprocess.TimeoutExpired) as exc:
            # Never include raw subprocess output or trace data in user-visible errors.
            safe = str(exc) if isinstance(exc, OnlineError) else type(exc).__name__
            print(f"[失败] {safe}", flush=True)
            _status("failed", safe)
            return 1
        finally:
            recovered = False
            try:
                try:
                    if GUARD.exists() and json.loads(GUARD.read_text(encoding="utf-8")).get("scanning_started"):
                        stop_vendor()
                finally:
                    restore_route(baseline)
                    restore_policy_rules(baseline_rules)
                recovered = True
            except (OnlineError, OSError) as exc:
                print(f"[恢复] {exc}", flush=True)
                _status("failed", "默认路由恢复需要人工检查")
            if recovered:
                GUARD.unlink(missing_ok=True)
                try:
                    watcher.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    pass


def _watchdog() -> int:
    recovery_failures = 0
    while GUARD.exists():
        try:
            data = json.loads(GUARD.read_text(encoding="utf-8"))
            worker = int(data["worker_pid"])
            stale = time.time() - float(data["heartbeat"]) > WATCHDOG_SECONDS
            try:
                os.kill(worker, 0)
                alive = True
            except ProcessLookupError:
                alive = False
            if stale or not alive:
                scanner = int(data.get("scanner_pgid", 0))
                if scanner:
                    try:
                        os.killpg(scanner, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                if alive:
                    try:
                        os.killpg(worker, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                try:
                    try:
                        if data.get("scanning_started"):
                            stop_vendor()
                    finally:
                        restore_route(str(data["default_route"]))
                    restore_policy_rules(data["policy_rules"])
                    _status("failed", "扫描超时；看门狗已恢复默认路由")
                    GUARD.unlink(missing_ok=True)
                    return 0
                except (OnlineError, OSError):
                    recovery_failures += 1
                    _status("failed", "扫描超时；看门狗正在重试恢复网络")
                    if recovery_failures >= 3:
                        _status("failed", "默认路由恢复失败，需要管理侧检查")
                        GUARD.unlink(missing_ok=True)
                        return 1
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(5)
    return 0


def _launch(operation: str) -> int:
    if os.geteuid() != 0:
        raise OnlineError("请以 root 运行")
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    if GUARD.exists():
        raise OnlineError("已有扫描任务在运行；请先查看 lazycat-status")
    LOG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _status("queued", "扫描任务已排队启动")
    with LOG.open("ab") as log:
        os.chmod(LOG, 0o600)
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "_worker", operation],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    print(f"后台任务已启动 (PID {process.pid})。查看进度: lazycat-status")
    print("扫描时 SSH 可能短暂断开；任务和路由恢复看门狗会继续运行。")
    return 0


def _show_status() -> int:
    if STATUS.exists():
        value = json.loads(STATUS.read_text(encoding="utf-8"))
        print(f"{value.get('state', '?')}: {value.get('message', '')}")
    else:
        print("尚未运行安装或同步")
    if CURRENT.is_symlink():
        result = subprocess.run(["rc-service", SERVICE, "status"], capture_output=True,
                                text=True, check=False)
        print("OpenRC: running" if result.returncode == 0 else "OpenRC: stopped")
    if LOG.exists():
        print("最近日志:")
        for line in LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-12:]:
            print(line)
    return 0


def _list() -> int:
    if not CURRENT.is_symlink():
        raise OnlineError("尚未安装")
    state = core.load_private_state(CURRENT / "state.json")
    meta = json.loads((CURRENT / "meta.json").read_text(encoding="utf-8"))
    by_name = {entry["name"]: entry for entry in meta["nodes"]}
    print("ID\tNAME\tUPSTREAM\tEXIT_IP")
    for name, node in sorted(state["nodes"].items()):
        entry = by_name.get(name, {})
        print(f"{entry.get('id', '-')}\t{name}\t{node['server']}:{node['server_port']}"
              f"\t{entry.get('exit_ip', '-')}")
    return 0


def _test() -> int:
    if not CURRENT.is_symlink():
        raise OnlineError("尚未安装")
    binary = preflight.run("sing-box")
    state = core.load_private_state(CURRENT / "state.json")
    expected: dict[str, str] = {}
    for name, node in state["nodes"].items():
        expected[name] = probe_socks(node["server"], node["server_port"],
                                     node["username"], node["password"])
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="test-", dir=RUNTIME) as directory:
        _verify_routes(binary, state, expected, Path(directory), PORT)
    print(f"PASS: {len(expected)} 个用户均到达预期出口")
    return 0


def _links(host: str, port: int) -> int:
    if not CURRENT.is_symlink():
        raise OnlineError("尚未安装")
    state = core.load_private_state(CURRENT / "state.json")
    for name in sorted(state["nodes"]):
        print(name)
        print(core.client_link(state, name, host, port))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["install", "sync", "status", "list", "links", "test",
                                            "_worker", "_watchdog"])
    parser.add_argument("extra", nargs="*")
    args = parser.parse_args(argv)
    try:
        if args.command in ("install", "sync"):
            return _launch(args.command)
        if args.command == "_worker":
            return _worker(args.extra[0] if args.extra else "install")
        if args.command == "_watchdog":
            return _watchdog()
        if args.command == "status":
            return _show_status()
        if args.command == "list":
            return _list()
        if args.command == "test":
            return _test()
        if len(args.extra) != 2:
            raise OnlineError("用法: lazycat-links HK_HOST HK_PORT")
        return _links(args.extra[0], int(args.extra[1]))
    except (OnlineError, OSError, ValueError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
