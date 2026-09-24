"""Synthetic checks for the local-only LXC preflight entry point."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import preflight


class PreflightTests(unittest.TestCase):
    def test_python_too_old_has_clear_error_before_binary_lookup(self):
        with mock.patch.object(preflight.sys, "version_info", (3, 9, 18)):
            with mock.patch.object(preflight.shutil, "which") as which:
                with self.assertRaisesRegex(preflight.PreflightError, "Python 3.10"):
                    preflight.run()
        which.assert_not_called()

    def test_missing_binary_has_clear_error(self):
        with mock.patch.object(preflight.shutil, "which", return_value=None):
            with mock.patch.object(preflight.subprocess, "run") as command:
                with self.assertRaisesRegex(preflight.PreflightError, "binary not found"):
                    preflight.run("missing-sing-box")
        command.assert_not_called()

    def test_version_failure_stops_before_config_check(self):
        response = SimpleNamespace(returncode=2, stdout="", stderr="private output")
        with mock.patch.object(preflight.shutil, "which", return_value="sing-box"):
            with mock.patch.object(preflight.subprocess, "run", return_value=response) as command:
                with self.assertRaisesRegex(preflight.PreflightError, "version command failed"):
                    preflight.run()
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[0][1:], ["version"])

    def test_two_user_config_is_checked_and_deleted(self):
        checked = {}

        def fake_command(argv, **kwargs):
            self.assertFalse(kwargs.get("shell", False))
            self.assertEqual(kwargs["timeout"], preflight.COMMAND_TIMEOUT_SECONDS)
            if argv[1] == "version":
                return SimpleNamespace(returncode=0, stdout="sing-box version 1.12.0", stderr="")
            self.assertEqual(argv[1:3], ["check", "-c"])
            path = Path(argv[3])
            checked["path"] = path
            config = json.loads(path.read_text(encoding="utf-8"))
            inbound = config["inbounds"][0]
            self.assertEqual(inbound["listen"], "127.0.0.1")
            self.assertEqual(len(inbound["users"]), 2)
            self.assertEqual(len(config["outbounds"]), 2)
            self.assertEqual({entry["server"] for entry in config["outbounds"]}, {"127.0.0.1"})
            self.assertEqual(config["route"]["rules"][-1]["action"], "reject")
            checked["secret"] = inbound["password"]
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(preflight.shutil, "which", return_value="sing-box"):
            with mock.patch.object(preflight.subprocess, "run", side_effect=fake_command) as command:
                output = io.StringIO()
                with redirect_stdout(output):
                    status = preflight.main([])
        self.assertEqual(status, 0)
        self.assertEqual(command.call_count, 2)
        self.assertFalse(checked["path"].exists())
        self.assertIn("PASS", output.getvalue())
        self.assertNotIn(checked["secret"], output.getvalue())

    def test_check_failure_hides_subprocess_output_and_cleans_temp_file(self):
        checked = {}

        def fake_command(argv, **kwargs):
            if argv[1] == "version":
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            checked["path"] = Path(argv[3])
            checked["secret"] = json.loads(checked["path"].read_text())["inbounds"][0]["password"]
            return SimpleNamespace(returncode=1, stdout=checked["secret"], stderr="sensitive diagnostic")

        with mock.patch.object(preflight.shutil, "which", return_value="sing-box"):
            with mock.patch.object(preflight.subprocess, "run", side_effect=fake_command):
                output = io.StringIO()
                with redirect_stderr(output):
                    status = preflight.main([])
        self.assertEqual(status, 1)
        self.assertFalse(checked["path"].exists())
        self.assertIn("FAIL", output.getvalue())
        self.assertNotIn(checked["secret"], output.getvalue())
        self.assertNotIn("sensitive diagnostic", output.getvalue())


if __name__ == "__main__":
    unittest.main()
