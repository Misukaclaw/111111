"""End-to-end offline CLI tests with invented traces and credentials."""

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import cli


def synthetic_trace(path: Path, *, port: int, password: str = "fake-secret") -> None:
    document = {
        "inbounds": [{"type": "tun", "interface_name": "cat0"}],
        "outbounds": [{"type": "socks", "server": "192.0.2.10",
                       "server_port": port, "username": "fake-user",
                       "password": password}],
    }
    payload = json.dumps(document, separators=(",", ":"))
    path.write_text(
        f"write(9, {json.dumps(payload)}, {len(payload.encode('utf-8'))}) = "
        f"{len(payload.encode('utf-8'))}\n",
        encoding="utf-8",
    )


def manifest(path: Path, nodes: list[tuple[str, Path]]) -> None:
    path.write_text(json.dumps({"nodes": [
        {"name": name, "trace": str(trace)} for name, trace in nodes
    ]}), encoding="utf-8")


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.private = self.folder / "private"
        self.manifest = self.folder / "manifest.json"
        self.first = self.folder / "first.trace"
        self.second = self.folder / "second.trace"
        synthetic_trace(self.first, port=5009)
        synthetic_trace(self.second, port=5004)
        manifest(self.manifest, [("Exit A", self.first), ("Exit B", self.second)])
        env = patch.dict(os.environ, {"LC_MASTER": ""})
        env.start()
        self.addCleanup(env.stop)

    def invoke(self, *extra):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main([
                "--manifest", str(self.manifest),
                "--private-dir", str(self.private), *extra,
            ])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_first_dry_run_never_creates_private_files(self):
        code, output, errors = self.invoke("--dry-run")
        self.assertEqual((code, errors), (0, ""))
        self.assertFalse(self.private.exists())
        summary = json.loads(output)
        self.assertTrue(summary["dry_run"])
        self.assertEqual(summary["added"], ["Exit A", "Exit B"])
        self.assertNotIn("fake-secret", output)

    def test_sync_creates_private_state_config_and_stable_keys(self):
        code, output, errors = self.invoke()
        self.assertEqual((code, errors), (0, ""))
        self.assertNotIn("fake-secret", output)
        state_path = self.private / "state.json"
        config_path = self.private / "config.json"
        master_path = self.private / "master.json"
        for path in (state_path, config_path, master_path):
            self.assertTrue(path.is_file())
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        before = json.loads(state_path.read_text(encoding="utf-8"))
        config = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(len(config["inbounds"]), 1)
        self.assertEqual(len(config["outbounds"]), 2)
        self.assertEqual({x["server_port"] for x in config["outbounds"]}, {5009, 5004})

        synthetic_trace(self.first, port=5010, password="changed-fake-secret")
        manifest(self.manifest, [("Exit A", self.first)])
        code, output, errors = self.invoke("--dry-run")
        self.assertEqual((code, errors), (0, ""))
        summary = json.loads(output)
        self.assertEqual(summary["updated"], ["Exit A"])
        self.assertEqual(summary["removed"], ["Exit B"])
        self.assertNotIn("changed-fake-secret", output)
        self.assertEqual(json.loads(state_path.read_text(encoding="utf-8")), before)

        code, output, errors = self.invoke()
        self.assertEqual((code, errors), (0, ""))
        after = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(after["server_key"], before["server_key"])
        self.assertEqual(after["nodes"]["Exit A"]["user_key"],
                         before["nodes"]["Exit A"]["user_key"])
        self.assertNotIn("Exit B", after["nodes"])

    def test_bad_trace_causes_no_writes(self):
        self.assertEqual(self.invoke()[0], 0)
        saved = {path.name: path.read_bytes() for path in self.private.iterdir()}
        self.second.write_text("write(9, \"bad\", 3) = 3\n", encoding="utf-8")
        code, output, errors = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("manifest node 2", errors)
        self.assertNotIn("fake-secret", errors)
        self.assertEqual(saved,
                         {path.name: path.read_bytes() for path in self.private.iterdir()})

    def test_private_directory_inside_source_is_rejected(self):
        inside = Path(cli.__file__).resolve().parent / "secrets"
        with self.assertRaisesRegex(ValueError, "outside"):
            cli.run(self.manifest, inside, dry_run=True)
        self.assertFalse(inside.exists())


if __name__ == "__main__":
    unittest.main()
