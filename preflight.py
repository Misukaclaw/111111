#!/usr/bin/env python3
"""Check a local sing-box binary against a disposable, synthetic config.

This entry point neither reads real traces nor changes any service or route.
Keep this file parseable by older Python so it can report the 3.10 requirement.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


MIN_PYTHON = (3, 10)
COMMAND_TIMEOUT_SECONDS = 15


class PreflightError(Exception):
    """A safe, credential-free message for the command-line user."""


def _run_command(argv):
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PreflightError("sing-box command timed out after 15 seconds") from exc
    except OSError as exc:
        raise PreflightError("could not execute the selected sing-box binary") from exc


def run(binary="sing-box"):
    """Return the executable location after both read-only checks pass."""
    if sys.version_info < MIN_PYTHON:
        raise PreflightError("Python 3.10 or newer is required")

    # Delay import: core.py itself requires the Python 3.10 parser.
    import core

    resolved = shutil.which(binary)
    if resolved is None:
        raise PreflightError("sing-box binary not found or not executable; use --binary PATH")
    resolved = os.path.abspath(resolved)

    version = _run_command([resolved, "version"])
    if version.returncode != 0:
        raise PreflightError("sing-box version command failed (exit %d)" % version.returncode)

    # Fresh, random keys and loopback-only placeholder SOCKS endpoints. The
    # temporary directory and config are deleted even when check fails.
    master = core.generate_master()
    nodes = [
        core.Node("synthetic-a", "127.0.0.1", 11001, "fake-a", "fake-password-a"),
        core.Node("synthetic-b", "127.0.0.1", 11002, "fake-b", "fake-password-b"),
    ]
    state = core.reconcile_nodes(nodes, master=master)
    config = core.build_config(state, listen="127.0.0.1", listen_port=12000)
    try:
        with tempfile.TemporaryDirectory(prefix="lazycat-preflight-") as temporary:
            config_path = Path(temporary) / "config.json"
            core.save_private_config(config_path, config)
            result = _run_command([resolved, "check", "-c", str(config_path)])
            if result.returncode != 0:
                # Do not print raw subprocess output: it could contain config keys.
                raise PreflightError("sing-box rejected the synthetic config (exit %d)" % result.returncode)
    except OSError as exc:
        raise PreflightError("could not create or remove the temporary config") from exc

    return resolved


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="sing-box", help="sing-box executable name or path")
    args = parser.parse_args(argv)
    try:
        run(args.binary)
    except PreflightError as exc:
        print("FAIL: %s" % exc, file=sys.stderr)
        return 1
    print("PASS: sing-box version and synthetic two-user config check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
