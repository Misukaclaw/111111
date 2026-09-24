"""Pure Python core for a single-port sing-box Shadowsocks 2022 gateway.

No discovery, package installation, or service management happens here.  The
caller supplies already discovered SOCKS5 endpoints.  State and generated
configuration contain credentials and must stay outside a Git repository.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
from typing import Any, Iterable, Mapping
from urllib.parse import quote


METHOD = "2022-blake3-aes-128-gcm"
STATE_VERSION = 2
INBOUND_TAG = "ss-in"
KEY_BYTES = 16


@dataclass(frozen=True)
class Node:
    """One already discovered SOCKS5 endpoint."""

    name: str
    server: str
    server_port: int
    username: str | None = None
    password: str | None = None


def generate_master() -> str:
    """Return a new 32-byte master seed as canonical base64."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _master_bytes(master: str) -> bytes:
    if not isinstance(master, str):
        raise ValueError("LC_MASTER must be canonical base64 of at least 32 random bytes")
    try:
        raw = base64.b64decode(master, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("LC_MASTER must be canonical base64 of at least 32 random bytes") from exc
    if len(raw) < 32 or base64.b64encode(raw).decode("ascii") != master:
        raise ValueError("LC_MASTER must be canonical base64 of at least 32 random bytes")
    return raw


def _derived_key(master: bytes, purpose: bytes) -> str:
    raw = hmac.digest(master, b"lazycat-multi/ss2022/v1/" + purpose, "sha256")[:KEY_BYTES]
    return base64.b64encode(raw).decode("ascii")


def derive_server_key(master: str) -> str:
    return _derived_key(_master_bytes(master), b"server")


def derive_user_key(master: str, name: str) -> str:
    name = _check_name(name)
    return _derived_key(_master_bytes(master), b"user\x00" + name.encode("utf-8"))


def _check_key(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a base64 key")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{field} must be a base64 key") from exc
    if len(raw) != KEY_BYTES or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError(f"{field} must encode exactly {KEY_BYTES} bytes")
    return value


def _check_name(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("node name must be a non-empty, unpadded string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("node name contains a control character")
    return value


def _check_host(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a non-empty host")
    if any(char.isspace() or char in "/?#@[]" for char in value):
        raise ValueError(f"{field} contains an invalid character")
    if ":" in value:
        try:
            ipaddress.IPv6Address(value)
        except ValueError as exc:
            raise ValueError(f"{field} must be a bare IPv6 address") from exc
    return value


def _check_port(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError(f"{field} must be an integer from 1 to 65535")
    return value


def _node(record: Node | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(record, Node):
        record = asdict(record)
    if not isinstance(record, Mapping):
        raise ValueError("each node must be a mapping")
    name = _check_name(record.get("name"))
    server = _check_host(record.get("server"), "SOCKS server")
    port = _check_port(record.get("server_port"), "SOCKS port")
    username = record.get("username")
    password = record.get("password")
    if (username is None) != (password is None):
        raise ValueError(f"node {name!r} needs both SOCKS username and password")
    if username is not None and (
        not isinstance(username, str)
        or not username
        or not isinstance(password, str)
        or not password
    ):
        raise ValueError(f"node {name!r} has invalid SOCKS credentials")
    return {
        "name": name,
        "server": server,
        "server_port": port,
        "username": username,
        "password": password,
    }


def _state(state: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate and copy untrusted persisted state without rotating keys."""
    if state is None:
        raise ValueError("state is required")
    if not isinstance(state, Mapping) or state.get("version") != STATE_VERSION:
        raise ValueError("unsupported state version")
    server_key = _check_key(state.get("server_key"), "server_key")
    master_id = state.get("master_id")
    if (
        not isinstance(master_id, str)
        or len(master_id) != 64
        or any(char not in "0123456789abcdef" for char in master_id)
    ):
        raise ValueError("invalid master_id")
    nodes = state.get("nodes")
    if not isinstance(nodes, Mapping):
        raise ValueError("state nodes must be a mapping")
    copied: dict[str, dict[str, Any]] = {}
    for name, value in nodes.items():
        _check_name(name)
        if not isinstance(value, Mapping):
            raise ValueError(f"state entry {name!r} must be a mapping")
        entry = _node({**value, "name": name})
        entry["user_key"] = _check_key(value.get("user_key"), "user_key")
        copied[name] = entry
    return {
        "version": STATE_VERSION,
        "master_id": master_id,
        "server_key": server_key,
        "nodes": copied,
    }


def _state_for_master(state: Mapping[str, Any] | None, master: str) -> dict[str, Any]:
    raw = _master_bytes(master)
    expected_id = hashlib.sha256(raw).hexdigest()
    server_key = _derived_key(raw, b"server")
    if state is None:
        return {
            "version": STATE_VERSION,
            "master_id": expected_id,
            "server_key": server_key,
            "nodes": {},
        }
    current = _state(state)
    if current["master_id"] != expected_id or current["server_key"] != server_key:
        raise ValueError("LC_MASTER does not match existing state")
    for name, node in current["nodes"].items():
        if node["user_key"] != _derived_key(raw, b"user\x00" + name.encode("utf-8")):
            raise ValueError(f"state key does not match LC_MASTER for node {name!r}")
    return current


def reconcile_nodes(
    records: Iterable[Node | Mapping[str, Any]],
    state: Mapping[str, Any] | None = None,
    *,
    master: str,
) -> dict[str, Any]:
    """Replace the discovered set, retaining keys for unchanged names.

    A record removed from the input disappears from the resulting state.  A
    record with an existing name updates its SOCKS endpoint but keeps its key.
    Duplicate names fail before any result is returned.
    """
    previous = _state_for_master(state, master)
    master_raw = _master_bytes(master)
    new_nodes: dict[str, dict[str, Any]] = {}
    for record in records:
        node = _node(record)
        name = node["name"]
        if name in new_nodes:
            raise ValueError(f"duplicate node name: {name!r}")
        node["user_key"] = _derived_key(master_raw, b"user\x00" + name.encode("utf-8"))
        new_nodes[name] = node
    previous["nodes"] = new_nodes
    return previous


def upsert_node(
    state: Mapping[str, Any] | None, record: Node | Mapping[str, Any], *, master: str
) -> dict[str, Any]:
    """Add or update one node by name while preserving all other nodes."""
    result = _state_for_master(state, master)
    node = _node(record)
    node["user_key"] = derive_user_key(master, node["name"])
    result["nodes"][node["name"]] = node
    return result


def remove_node(state: Mapping[str, Any], name: str) -> dict[str, Any]:
    """Remove one node by exact name; fail on a typo."""
    result = _state(state)
    name = _check_name(name)
    if name not in result["nodes"]:
        raise KeyError(name)
    del result["nodes"][name]
    return result


def _outbound_tag(name: str) -> str:
    return "socks-" + hashlib.sha256(name.encode("utf-8")).hexdigest()


def build_config(
    state: Mapping[str, Any], *, listen: str = "::", listen_port: int = 8388
) -> dict[str, Any]:
    """Build a sing-box >=1.11 config with a rejecting fallback rule."""
    current = _state(state)
    _check_host(listen, "listen")
    _check_port(listen_port, "listen_port")
    if not current["nodes"]:
        raise ValueError("at least one node is required")
    users = []
    outbounds = []
    rules = []
    for name in sorted(current["nodes"]):
        node = current["nodes"][name]
        tag = _outbound_tag(name)
        users.append({"name": name, "password": node["user_key"]})
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": node["server"],
            "server_port": node["server_port"],
            "version": "5",
        }
        if node["username"] is not None:
            outbound["username"] = node["username"]
            outbound["password"] = node["password"]
        outbounds.append(outbound)
        rules.append(
            {
                "inbound": [INBOUND_TAG],
                "auth_user": [name],
                "action": "route",
                "outbound": tag,
            }
        )
    rules.append({"inbound": [INBOUND_TAG], "action": "reject"})
    return {
        "inbounds": [
            {
                "type": "shadowsocks",
                "tag": INBOUND_TAG,
                "listen": listen,
                "listen_port": listen_port,
                "method": METHOD,
                "password": current["server_key"],
                "users": users,
            }
        ],
        "outbounds": outbounds,
        "route": {"rules": rules},
    }


def _client_details(
    state: Mapping[str, Any], name: str, host: str, port: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    current = _state(state)
    name = _check_name(name)
    host = _check_host(host, "client server")
    port = _check_port(port, "client port")
    try:
        node = current["nodes"][name]
    except KeyError as exc:
        raise KeyError(f"unknown node: {name!r}") from exc
    return current, {"node": node, "host": host, "port": port, "name": name}


def client_config(state: Mapping[str, Any], name: str, host: str, port: int) -> dict[str, Any]:
    """Build the corresponding sing-box client Shadowsocks outbound."""
    current, details = _client_details(state, name, host, port)
    return {
        "type": "shadowsocks",
        "tag": name,
        "server": details["host"],
        "server_port": details["port"],
        "method": METHOD,
        "password": current["server_key"] + ":" + details["node"]["user_key"],
    }


def client_link(state: Mapping[str, Any], name: str, host: str, port: int) -> str:
    """Return SIP002 URI for AEAD-2022 (plain, percent-encoded userinfo)."""
    current, details = _client_details(state, name, host, port)
    host = details["host"]
    if ":" in host:
        host = "[" + host + "]"
    else:
        host = host.encode("idna").decode("ascii")
    password = current["server_key"] + ":" + details["node"]["user_key"]
    return (
        f"ss://{METHOD}:{quote(password, safe='')}@{host}:{port}"
        f"#{quote(name, safe='')}"
    )


def _check_private_parent(parent: Path) -> None:
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix" and stat.S_IMODE(parent.stat().st_mode) & 0o022:
        raise PermissionError(f"private directory is writable by group/other: {parent}")


def save_private_json(path: str | os.PathLike[str], data: Mapping[str, Any]) -> None:
    """Atomically save sensitive JSON with mode 0600 on POSIX.

    The parent directory must not be writable by group/other on POSIX.  The
    caller should use a dedicated runtime directory outside the source checkout.
    """
    target = Path(path)
    _check_private_parent(target.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".tmp-", dir=target.parent)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        if os.name == "posix":
            target.chmod(0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_private_state(path: str | os.PathLike[str], state: Mapping[str, Any]) -> None:
    save_private_json(path, _state(state))


def load_private_state(path: str | os.PathLike[str]) -> dict[str, Any]:
    target = Path(path)
    if os.name == "posix" and stat.S_IMODE(target.stat().st_mode) & 0o077:
        raise PermissionError(f"state file has group/other access: {target}")
    with target.open("r", encoding="utf-8") as stream:
        return _state(json.load(stream))


def save_private_config(path: str | os.PathLike[str], config: Mapping[str, Any]) -> None:
    save_private_json(path, config)
