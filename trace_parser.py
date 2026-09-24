"""Extract one authenticated SOCKS outbound from a local strace capture.

Only a completed ``write(fd, "...", N) = N`` syscall is considered.  The
second argument is decoded as a C byte string before JSON parsing; strace's
rendered text is never evaluated as Python code.  Callers should capture one
menu selection per trace so that a trace cannot ambiguously identify nodes.
"""

from __future__ import annotations

import json
import re
from typing import Any


class TraceParseError(ValueError):
    """The trace has no unique, complete authenticated SOCKS outbound."""


_WRITE_START = re.compile(r"(?:^|\s)write\(\s*\d+\s*,\s*\"")
_WRITE_END = re.compile(r"\s*,\s*(\d+)\s*\)\s*=\s*(\d+)(?:\s|$)")
_SIMPLE_ESCAPES = {
    "a": 0x07,
    "b": 0x08,
    "f": 0x0C,
    "n": 0x0A,
    "r": 0x0D,
    "t": 0x09,
    "v": 0x0B,
    "\\": 0x5C,
    '"': 0x22,
    "'": 0x27,
    "?": 0x3F,
}


def _decode_c_argument(line: str, start: int) -> tuple[bytes, int] | None:
    """Decode a strace C string, returning its bytes and closing quote offset."""
    data = bytearray()
    i = start
    while i < len(line):
        char = line[i]
        if char == '"':
            return bytes(data), i + 1
        if char != "\\":
            data.extend(char.encode("utf-8"))
            i += 1
            continue

        i += 1
        if i >= len(line):
            return None
        escape = line[i]
        if escape in _SIMPLE_ESCAPES:
            data.append(_SIMPLE_ESCAPES[escape])
            i += 1
        elif escape in "01234567":
            digits = escape
            i += 1
            while i < len(line) and len(digits) < 3 and line[i] in "01234567":
                digits += line[i]
                i += 1
            value = int(digits, 8)
            if value > 255:
                return None
            data.append(value)
        elif escape == "x":
            digits = line[i + 1 : i + 3]
            if len(digits) != 2 or not all(c in "0123456789abcdefABCDEF" for c in digits):
                return None
            data.append(int(digits, 16))
            i += 3
        else:
            return None
    return None


def _written_payload(line: str) -> bytes | None:
    match = _WRITE_START.search(line)
    if match is None:
        return None
    decoded = _decode_c_argument(line, match.end())
    if decoded is None:
        return None
    payload, end = decoded
    tail = _WRITE_END.match(line, end)
    if tail is None:
        return None
    requested, written = map(int, tail.groups())
    if requested != written or len(payload) != requested:
        return None
    return payload


def _socks_outbounds(document: Any) -> list[dict[str, object]]:
    if not isinstance(document, dict) or not isinstance(document.get("outbounds"), list):
        return []
    found: list[dict[str, object]] = []
    for outbound in document["outbounds"]:
        if not isinstance(outbound, dict) or outbound.get("type") != "socks":
            continue
        server = outbound.get("server")
        port = outbound.get("server_port")
        username = outbound.get("username")
        password = outbound.get("password")
        if not isinstance(server, str) or not server or any(c.isspace() for c in server):
            continue
        if type(port) is not int or not 1 <= port <= 65535:
            continue
        if not isinstance(username, str) or not username:
            continue
        if not isinstance(password, str) or not password:
            continue
        found.append({
            "server": server,
            "server_port": port,
            "username": username,
            "password": password,
        })
    return found


def extract_socks_outbound(trace_text: str) -> dict[str, object]:
    """Return the unique authenticated SOCKS outbound in a strace text.

    Duplicate writes of the same configuration are harmless.  Distinct valid
    outbounds are rejected so a caller cannot silently attach the wrong exit
    to a menu node.  Exceptions deliberately contain no trace data or secrets.
    """
    unique: dict[tuple[str, int, str, str], dict[str, object]] = {}
    for line in trace_text.splitlines():
        payload = _written_payload(line)
        if payload is None:
            continue
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        for outbound in _socks_outbounds(document):
            key = (
                str(outbound["server"]),
                int(outbound["server_port"]),
                str(outbound["username"]),
                str(outbound["password"]),
            )
            unique[key] = outbound
    if not unique:
        raise TraceParseError("No complete authenticated SOCKS outbound found")
    if len(unique) != 1:
        raise TraceParseError("Trace contains multiple distinct SOCKS outbounds")
    return next(iter(unique.values()))
