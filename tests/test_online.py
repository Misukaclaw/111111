"""Checks for online discovery boundaries and deployment rollback."""

from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

import core
import online


MENU = """选择: 1
------ 切换节点 ------
[1] Frontier-US动态
[2] HKT-动态家宽
请输入节点ID进行切换（输入0取消）:
"""


class OnlineTests(unittest.TestCase):
    def test_bad_upstream_skips_one_node_and_scans_remaining_nodes(self):
        menu = [(1, "a"), (2, "b"), (3, "c")]
        nodes = [core.Node(name, "192.0.2.1", 5000 + number, "user", "secret")
                 for number, name in menu]

        def probe(host, port, username, password):
            if port == 5002:
                raise online.OnlineError("SOCKS 上游出口 IP 验证失败")
            return "192.0.2.10"

        with patch.object(online, "scan_one", side_effect=nodes) as scan, \
             patch.object(online, "probe_socks", side_effect=probe), \
             patch.object(online, "stop_vendor"), \
             patch.object(online, "restore_route"), \
             patch.object(online, "restore_policy_rules"), \
             patch.object(online, "_guard_update"), \
             patch.object(online, "_status"):
            records, ips, statuses, skipped = online._collect_nodes(
                menu, None, Path("/tmp"), "default via 192.0.2.1 dev eth0",
                {"-4": [], "-6": []})
        self.assertEqual(scan.call_count, 3)
        self.assertEqual([node.name for node in records], ["a", "c"])
        self.assertEqual(set(ips), {"a", "c"})
        self.assertEqual(statuses, {"a": "OK", "b": "SKIPPED", "c": "OK"})
        self.assertEqual(skipped, ["b"])

    def test_failed_new_credentials_keep_working_old_endpoint(self):
        prior = core.reconcile_nodes([core.Node("a", "192.0.2.1", 5001, "old", "old-pass")],
                                     master=core.generate_master())
        fresh = core.Node("a", "192.0.2.2", 5002, "new", "new-pass")

        def probe(host, port, username, password):
            if port == 5002:
                raise online.OnlineError("SOCKS 上游出口 IP 验证失败")
            return "192.0.2.10"

        with patch.object(online, "scan_one", return_value=fresh), \
             patch.object(online, "probe_socks", side_effect=probe), \
             patch.object(online, "stop_vendor"), \
             patch.object(online, "restore_route"), \
             patch.object(online, "restore_policy_rules"), \
             patch.object(online, "_guard_update"), \
             patch.object(online, "_status"):
            records, ips, statuses, skipped = online._collect_nodes(
                [(1, "a")], prior, Path("/tmp"), "default via 192.0.2.1 dev eth0",
                {"-4": [], "-6": []})
        self.assertEqual(records[0].server_port, 5001)
        self.assertEqual(records[0].username, "old")
        self.assertEqual(ips, {"a": "192.0.2.10"})
        self.assertEqual(statuses, {"a": "STALE"})
        self.assertEqual(skipped, [])

    def test_changed_menu_aborts_even_when_other_nodes_could_work(self):
        with patch.object(online, "scan_one", side_effect=online.MenuChangedError("changed")), \
             patch.object(online, "stop_vendor") as stop, \
             patch.object(online, "restore_route"), \
             patch.object(online, "restore_policy_rules"), \
             patch.object(online, "_guard_update"), \
             patch.object(online, "_status"):
            with self.assertRaises(online.MenuChangedError):
                online._collect_nodes([(1, "a")], None, Path("/tmp"),
                                      "default via 192.0.2.1 dev eth0",
                                      {"-4": [], "-6": []})
        stop.assert_called_once()

    def test_all_failed_nodes_do_not_produce_empty_deployment(self):
        with patch.object(online, "scan_one", return_value=core.Node(
                "a", "192.0.2.1", 5001, "user", "secret")), \
             patch.object(online, "probe_socks", side_effect=online.OnlineError("unavailable")), \
             patch.object(online, "stop_vendor"), \
             patch.object(online, "restore_route"), \
             patch.object(online, "restore_policy_rules"), \
             patch.object(online, "_guard_update"), \
             patch.object(online, "_status"):
            with self.assertRaisesRegex(online.OnlineError, "没有任何可验证"):
                online._collect_nodes([(1, "a")], None, Path("/tmp"),
                                      "default via 192.0.2.1 dev eth0",
                                      {"-4": [], "-6": []})

    def test_complete_menu_and_ansi_codes(self):
        marked = MENU.replace("[2]", "\x1b[32m[2]\x1b[0m")
        self.assertEqual(online.parse_menu(marked),
                         [(1, "Frontier-US动态"), (2, "HKT-动态家宽")])

    def test_missing_prompt_or_duplicate_menu_rejected(self):
        with self.assertRaisesRegex(online.OnlineError, "未完整"):
            online.parse_menu(MENU.split("请输入")[0])
        with self.assertRaisesRegex(online.OnlineError, "重复"):
            online.parse_menu(MENU.replace("[2]", "[1]"))
        with self.assertRaisesRegex(online.OnlineError, "重复"):
            online.parse_menu(MENU.replace("HKT-动态家宽", "Frontier-US动态"))

    def test_route_recovery_only_removes_cat0_default(self):
        baseline = "default via 192.0.2.1 dev eth0"
        commands = []

        def run(argv, **kwargs):
            commands.append(argv)
            return subprocess.CompletedProcess(argv, 0, "default dev cat0\n", "")

        with patch.object(online, "default_route", side_effect=["default dev cat0", baseline]), \
             patch.object(online.subprocess, "run", side_effect=run):
            online.restore_route(baseline)
        self.assertIn(["ip", "-4", "route", "del", "default", "dev", "cat0"], commands)
        self.assertIn(["ip", "-4", "route", "replace", "default", "via", "192.0.2.1",
                       "dev", "eth0"], commands)

    def test_deploy_reverts_symlink_when_openrc_start_fails(self):
        current = Mock()
        current.is_symlink.return_value = True
        current.resolve.return_value = Path("/etc/lazycat-multi/generations/previous")
        service = Mock(side_effect=[online.OnlineError("start failed"), None])
        with patch.object(online, "CURRENT", current), \
             patch.object(online, "_switch") as switch, \
             patch.object(online, "_service", service), \
             patch.object(online.subprocess, "run", return_value=Mock(returncode=0)):
            with self.assertRaises(online.OnlineError):
                online._deploy(Path("/etc/lazycat-multi/generations/new"), "sing-box",
                               {}, {}, Path("/tmp"))
        self.assertEqual(switch.call_args_list[0].args[0],
                         Path("/etc/lazycat-multi/generations/new"))
        self.assertEqual(switch.call_args_list[1].args[0],
                         Path("/etc/lazycat-multi/generations/previous"))

    def test_new_policy_rule_is_removed_without_touching_old_rules(self):
        baseline = {
            "-4": ["0: from all lookup local", "32766: from all lookup main"],
            "-6": ["0: from all lookup local"],
        }
        current = {"-4": [*baseline["-4"], "9000: from all lookup 2022"],
                   "-6": baseline["-6"]}
        with patch.object(online, "policy_rules", side_effect=[current, baseline]), \
             patch.object(online.subprocess, "run", return_value=Mock(returncode=0)) as run:
            online.restore_policy_rules(baseline)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0],
                         ["ip", "-4", "rule", "del", "pref", "9000"])

    def test_deploy_reverts_after_live_user_route_check_fails(self):
        current = Mock()
        current.is_symlink.return_value = True
        current.resolve.return_value = Path("/etc/lazycat-multi/generations/previous")
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=None)
        with patch.object(online, "CURRENT", current), \
             patch.object(online, "_switch") as switch, \
             patch.object(online, "_service"), \
             patch.object(online.socket, "create_connection", return_value=connection), \
             patch.object(online, "_verify_routes", side_effect=online.OnlineError("wrong exit")), \
             patch.object(online.subprocess, "run", return_value=Mock(returncode=0)):
            with self.assertRaisesRegex(online.OnlineError, "wrong exit"):
                online._deploy(Path("/etc/lazycat-multi/generations/new"), "sing-box",
                               {}, {"test": "192.0.2.5"}, Path("/tmp"))
        self.assertEqual(switch.call_count, 2)
        self.assertEqual(switch.call_args_list[-1].args[0],
                         Path("/etc/lazycat-multi/generations/previous"))

    def test_candidate_disables_other_upstreams_per_user(self):
        master = core.generate_master()
        state = core.reconcile_nodes([
            core.Node("a", "192.0.2.1", 5001, "u-a", "p-a"),
            core.Node("b", "192.0.2.2", 5002, "u-b", "p-b"),
        ], master=master)
        configs = []

        def capture(path, config):
            configs.append(config)

        with patch.object(online, "_free_port", side_effect=[10001, 10002]), \
             patch.object(online.core, "save_private_config", side_effect=capture), \
             patch.object(online.subprocess, "run", return_value=Mock(returncode=0)), \
             patch.object(online.subprocess, "Popen", return_value=Mock()), \
             patch.object(online, "_wait_tcp"), \
             patch.object(online, "_verify_routes"), \
             patch.object(online, "_terminate_process"):
            online.verify_candidate("sing-box", state, {"a": "192.0.2.10", "b": "192.0.2.11"},
                                    Path("/tmp"))
        self.assertEqual(len(configs), 2)
        routes_a = configs[0]["route"]["rules"]
        tag_a = next(rule["outbound"] for rule in routes_a if rule.get("auth_user") == ["a"])
        for config, wanted_tag in ((configs[0], tag_a),
                                   (configs[1], next(rule["outbound"]
                                                     for rule in configs[1]["route"]["rules"]
                                                     if rule.get("auth_user") == ["b"]))):
            for outbound in config["outbounds"]:
                if outbound["tag"] == wanted_tag:
                    self.assertNotEqual(outbound["server_port"], 1)
                else:
                    self.assertEqual((outbound["server"], outbound["server_port"]),
                                     ("127.0.0.1", 1))


if __name__ == "__main__":
    unittest.main()
