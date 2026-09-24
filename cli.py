"""Offline assembly of a private sing-box configuration from captured traces.

This program never runs the LazyCat menu, changes routes, or starts a service.
The input manifest is an exhaustive list of desired nodes.  Each trace must
come from one node selection and contain one unambiguous SOCKS outbound.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
from pathlib import Path
import stat
import sys
from typing import Sequence

import core
from trace_parser import TraceParseError, extract_socks_outbound


_PROJECT_DIR = Path(__file__).resolve().parent
_MAX_TRACE_BYTES = 32 * 1024 * 1024


def _private_directory(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("--private-dir must be an absolute path")
    resolved = path.resolve()
    if resolved == _PROJECT_DIR or _PROJECT_DIR in resolved.parents:
        raise ValueError("--private-dir must be outside the source directory")
    if resolved.exists() and not resolved.is_dir():
        raise ValueError("--private-dir must be a directory")
    if resolved.exists() and os.name == "posix":
        if stat.S_IMODE(resolved.stat().st_mode) & 0o077:
            raise PermissionError("private directory must have mode 0700 or stricter")
    return resolved


def _manifest_records(manifest_path: Path) -> list[dict[str, object]]:
    with manifest_path.open("r", encoding="utf-8") as stream:
        manifest = json.load(stream)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("nodes"), list):
        raise ValueError("manifest must contain a nodes array")
    if not manifest["nodes"]:
        raise ValueError("manifest must contain at least one node")

    records: list[dict[str, object]] = []
    for index, entry in enumerate(manifest["nodes"], 1):
        if not isinstance(entry, dict):
            raise ValueError(f"manifest node {index} must be an object")
        name, trace_name = entry.get("name"), entry.get("trace")
        if not isinstance(name, str) or not name:
            raise ValueError(f"manifest node {index} needs a name")
        if not isinstance(trace_name, str) or not trace_name:
            raise ValueError(f"manifest node {index} needs a trace path")
        trace_path = Path(trace_name)
        if not trace_path.is_absolute():
            trace_path = manifest_path.parent / trace_path
        try:
            if trace_path.stat().st_size > _MAX_TRACE_BYTES:
                raise ValueError("trace exceeds the 32 MiB size limit")
            trace_text = trace_path.read_text(encoding="utf-8")
            outbound = extract_socks_outbound(trace_text)
        except (OSError, UnicodeError, TraceParseError, ValueError) as exc:
            # In particular, never include raw trace or authentication fields.
            raise ValueError(f"could not read a unique SOCKS outbound for manifest node {index}") from exc
        records.append({"name": name, **outbound})
    return records


def _read_master(path: Path, *, has_state: bool) -> tuple[str, bool]:
    from_environment = os.environ.get("LC_MASTER") or None
    if path.exists():
        if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise PermissionError("master file has group or other access")
        with path.open("r", encoding="utf-8") as stream:
            data = json.load(stream)
        if not isinstance(data, dict) or not isinstance(data.get("master"), str):
            raise ValueError("master file is invalid")
        stored = data["master"]
        if from_environment and not hmac.compare_digest(stored, from_environment):
            raise ValueError("LC_MASTER differs from the stored master")
        return stored, False
    if from_environment:
        return from_environment, True
    if has_state:
        raise ValueError("existing state needs its master file or LC_MASTER")
    return core.generate_master(), True


def _change_summary(previous: dict | None, current: dict) -> dict[str, object]:
    before = previous["nodes"] if previous is not None else {}
    after = current["nodes"]
    prior_names, next_names = set(before), set(after)
    fields = ("server", "server_port", "username", "password")
    updated = sorted(
        name for name in prior_names & next_names
        if any(before[name][field] != after[name][field] for field in fields)
    )
    return {
        "added": sorted(next_names - prior_names),
        "updated": updated,
        "removed": sorted(prior_names - next_names),
        "unchanged": sorted((prior_names & next_names) - set(updated)),
    }


def run(
    manifest: Path,
    private_dir: Path,
    *,
    dry_run: bool = False,
    listen: str = "0.0.0.0",
    port: int = 12000,
) -> dict[str, object]:
    """Validate all input before touching any private output file."""
    private_dir = _private_directory(private_dir)
    manifest = manifest.resolve()
    records = _manifest_records(manifest)
    state_path = private_dir / "state.json"
    config_path = private_dir / "config.json"
    master_path = private_dir / "master.json"
    previous = core.load_private_state(state_path) if state_path.exists() else None
    master, needs_save = _read_master(master_path, has_state=previous is not None)
    current = core.reconcile_nodes(records, previous, master=master)
    config = core.build_config(current, listen=listen, listen_port=port)
    summary = _change_summary(previous, current)
    if not dry_run:
        if needs_save:
            core.save_private_json(master_path, {"master": master})
        core.save_private_state(state_path, current)
        core.save_private_config(config_path, config)
    return {"dry_run": dry_run, **summary}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True,
                        help="JSON object with an exhaustive nodes array of name/trace pairs")
    parser.add_argument("--private-dir", type=Path, required=True,
                        help="absolute private output directory outside this source tree")
    parser.add_argument("--dry-run", action="store_true",
                        help="show the change summary without creating or modifying files")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=12000)
    args = parser.parse_args(argv)
    try:
        summary = run(args.manifest, args.private_dir, dry_run=args.dry_run,
                      listen=args.listen, port=args.port)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
