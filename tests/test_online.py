"""Checks for online discovery boundaries and deployment rollback."""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
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
             patch.object(online, "_wait_service_port"), \
             patch.object(online.subprocess, "run", return_value=Mock(returncode=0)):
            with self.assertRaises(online.OnlineError):
                online._deploy(Path("/etc/lazycat-multi/generations/new"), "sing-box",
                               {}, {}, Path("/tmp"))
        self.assertEqual(switch.call_args_list[0].args[0],
                         Path("/etc/lazycat-multi/generations/new"))
        self.assertEqual(switch.call_args_list[1].args[0],
                         Path("/etc/lazycat-multi/generations/previous"))

    def test_first_install_stops_service_before_removing_config(self):
        current = Mock()
        current.is_symlink.return_value = False
        events = []
        generation = Path("/etc/lazycat-multi/generations/new")

        def switch(target):
            events.append(("switch", target))

        def service(command):
            events.append(("service", command))

        with patch.object(online, "CURRENT", current), \
             patch.object(online, "_switch", side_effect=switch), \
             patch.object(online, "_service", side_effect=service), \
             patch.object(online, "_wait_service_port",
                          side_effect=online.OnlineError("port unavailable")), \
             patch.object(online.subprocess, "run", return_value=Mock(returncode=1)):
            with self.assertRaisesRegex(online.OnlineError, "port unavailable"):
                online._deploy(generation, "sing-box", {}, {}, Path("/tmp"))
        self.assertEqual(events, [("switch", generation), ("service", "start"),
                                  ("service", "stop"), ("switch", None)])

    def test_rollback_revives_previous_config_when_gateway_was_already_down(self):
        # The reported failure: the gateway died during the scan, the new
        # config would not start, and the rollback left everything stopped.
        current = Mock()
        current.is_symlink.return_value = True
        current.resolve.return_value = Path("/etc/lazycat-multi/generations/previous")
        events = []
        commands = []

        def run(argv, **kwargs):
            commands.append(argv)
            return Mock(returncode=1)  # OpenRC reports "crashed"/stopped

        with patch.object(online, "CURRENT", current), \
             patch.object(online, "_switch", side_effect=lambda t: events.append(("switch", t))), \
             patch.object(online, "_service", side_effect=lambda c: events.append(("service", c))), \
             patch.object(online, "_wait_service_port",
                          side_effect=[online.OnlineError("服务启动后退出"), None]), \
             patch.object(online.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(online.OnlineError, "启动后退出"):
                online._deploy(Path("/etc/lazycat-multi/generations/new"), "sing-box",
                               {}, {}, Path("/tmp"))
        self.assertEqual(events, [
            ("switch", Path("/etc/lazycat-multi/generations/new")), ("service", "start"),
            ("switch", Path("/etc/lazycat-multi/generations/previous")), ("service", "start")])
        self.assertEqual(commands.count(["rc-service", online.SERVICE, "zap"]), 2)

    def test_start_service_clears_crashed_state_and_orphan_first(self):
        commands = []

        def run(argv, **kwargs):
            commands.append(argv)
            return Mock(returncode=1)

        with patch.object(online.subprocess, "run", side_effect=run), \
             patch.object(online, "_service") as service:
            online._start_service()
        self.assertIn(["rc-service", online.SERVICE, "zap"], commands)
        self.assertIn(["pkill", "-f", f"run -c {online.CURRENT}/config.json"], commands)
        service.assert_called_once_with("start")

    def test_start_service_restarts_a_running_gateway(self):
        with patch.object(online.subprocess, "run", return_value=Mock(returncode=0)) as run, \
             patch.object(online, "_service") as service:
            online._start_service()
        service.assert_called_once_with("restart")
        self.assertEqual(run.call_count, 1)

    def test_sync_end_revives_a_stopped_gateway(self):
        current = Mock()
        current.is_symlink.return_value = True
        with patch.object(online, "CURRENT", current), \
             patch.object(online, "_service_running", return_value=False), \
             patch.object(online, "_start_service") as start, \
             patch.object(online, "_wait_service_port") as wait:
            online._ensure_running()
        start.assert_called_once()
        wait.assert_called_once()

    def test_sync_end_leaves_a_running_gateway_alone(self):
        current = Mock()
        current.is_symlink.return_value = True
        with patch.object(online, "CURRENT", current), \
             patch.object(online, "_service_running", return_value=True), \
             patch.object(online, "_start_service") as start:
            online._ensure_running()
        start.assert_not_called()

    def test_service_exit_message_includes_last_gateway_error(self):
        with tempfile.TemporaryDirectory() as directory:
            err = Path(directory) / "service.err"
            err.write_text("old line\nFATAL start inbound: listen tcp 0.0.0.0:12000: "
                           "bind: address already in use\n", encoding="utf-8")
            with patch.object(online, "SERVICE_ERR", err), \
                 patch.object(online.socket, "create_connection",
                              side_effect=ConnectionRefusedError()), \
                 patch.object(online.time, "sleep"), \
                 patch.object(online.subprocess, "run", return_value=Mock(returncode=1)):
                with self.assertRaisesRegex(online.OnlineError, "address already in use"):
                    online._wait_service_port()

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

    def test_openrc_port_check_waits_for_listener(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=None)
        with patch.object(online.socket, "create_connection",
                          side_effect=[ConnectionRefusedError(), ConnectionRefusedError(),
                                       connection]) as connect, \
             patch.object(online.time, "sleep") as sleep:
            online._wait_service_port()
        self.assertEqual(connect.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_openrc_port_check_reports_service_exit(self):
        with patch.object(online.socket, "create_connection",
                          side_effect=ConnectionRefusedError()), \
             patch.object(online.time, "sleep"), \
             patch.object(online.subprocess, "run", return_value=Mock(returncode=1)):
            with self.assertRaisesRegex(online.OnlineError, "服务启动后退出"):
                online._wait_service_port()

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
             patch.object(online, "_verify_routes", return_value=[]), \
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


class MasterKeyTests(unittest.TestCase):
    """Client passwords must survive a lost `current` link and every sync."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, value in (("APP", self.root),
                            ("GENERATIONS", self.root / "generations"),
                            ("CURRENT", self.root / "current"),
                            ("MASTER_FILE", self.root / "master.json")):
            patcher = patch.object(online, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("LC_MASTER", None)

    def _generation(self, name, master, mtime):
        path = self.root / "generations" / name
        path.mkdir(parents=True)
        (path / "master.json").write_text(json.dumps({"master": master}), encoding="utf-8")
        os.utime(path / "master.json", (mtime, mtime))

    def test_fresh_install_generates_a_master(self):
        master, state = online._load_previous()
        self.assertIsNone(state)
        core.derive_server_key(master)

    def test_lost_current_reuses_saved_master(self):
        saved = core.generate_master()
        (self.root / "master.json").write_text(json.dumps({"master": saved}), encoding="utf-8")
        self.assertEqual(online._load_previous(), (saved, None))

    def test_lost_current_recovers_newest_generation_master(self):
        old, new = core.generate_master(), core.generate_master()
        self._generation("generation-old", old, 1_000_000)
        self._generation("generation-new", new, 2_000_000)
        self.assertEqual(online._load_previous()[0], new)

    def test_recovered_keys_match_previous_passwords(self):
        master = core.generate_master()
        before = core.reconcile_nodes([core.Node("a", "192.0.2.1", 5001, "u", "p")], master=master)
        self._generation("generation-x", master, 1_000_000)
        recovered, previous = online._load_previous()
        after = core.reconcile_nodes([core.Node("a", "192.0.2.9", 6001, "u2", "p2")],
                                     previous, master=recovered)
        self.assertEqual(after["server_key"], before["server_key"])
        self.assertEqual(after["nodes"]["a"]["user_key"], before["nodes"]["a"]["user_key"])

    def test_lc_master_cannot_silently_replace_recovered_master(self):
        self._generation("generation-x", core.generate_master(), 1_000_000)
        os.environ["LC_MASTER"] = core.generate_master()
        with self.assertRaisesRegex(online.OnlineError, "LC_MASTER"):
            online._load_previous()

    def test_lc_master_restores_keys_on_a_reinstalled_box(self):
        master = core.generate_master()
        os.environ["LC_MASTER"] = master
        self.assertEqual(online._load_previous(), (master, None))

    def test_persisted_master_refuses_rotation(self):
        first, second = core.generate_master(), core.generate_master()
        online._persist_master(first)
        online._persist_master(first)
        with self.assertRaisesRegex(online.OnlineError, "不一致"):
            online._persist_master(second)
        saved = json.loads((self.root / "master.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["master"], first)


class ExportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.master = core.generate_master()
        self.state = core.reconcile_nodes([
            core.Node("HKT", "192.0.2.1", 5001, "u1", "p1"),
            core.Node("KDDI", "192.0.2.2", 5002, "u2", "p2"),
        ], master=self.master)
        core.save_private_state(self.base / "state.json", self.state)
        core.save_private_json(self.base / "master.json", {"master": self.master})
        core.save_private_json(self.base / "meta.json", {"nodes": [
            {"id": 1, "name": "KDDI", "exit_ip": "192.0.2.10", "status": "OK"},
            {"id": 2, "name": "Bell", "exit_ip": "", "status": "SKIPPED"},
            {"id": 3, "name": "HKT", "exit_ip": "192.0.2.11", "status": "STALE"},
        ]})

    def password(self, name):
        return self.state["server_key"] + ":" + self.state["nodes"][name]["user_key"]

    def test_tsv_lists_enabled_nodes_in_menu_order(self):
        self.assertEqual(online.export_lines(self.base, tsv=True),
                         [f"KDDI\t{self.password('KDDI')}", f"HKT\t{self.password('HKT')}"])

    def test_readable_export_marks_status_and_skipped_nodes(self):
        text = "\n".join(online.export_lines(self.base))
        self.assertIn("加密: 2022-blake3-aes-128-gcm", text)
        self.assertIn(f"主密钥指纹: {self.state['master_id'][:12]}", text)
        self.assertIn("节点: HKT  [STALE]", text)
        self.assertIn(f"密码: {self.password('KDDI')}", text)
        self.assertIn("未启用: Bell", text)
        self.assertNotIn(self.master, text)

    def test_backup_adds_recovery_code(self):
        self.assertIn(self.master, online.export_lines(self.base, backup=True))

    def test_sync_result_marks_new_and_gone_nodes(self):
        lines = online.export_lines(self.base, previous={"KDDI", "Bell", "Old"})
        self.assertIn("节点: HKT  [STALE] 新增", lines)
        self.assertIn("节点: KDDI  [OK]", lines)
        self.assertIn("新增节点（需在面板添加出站）: HKT", lines)
        # Bell is still in the menu (skipped), so only Old counts as gone.
        self.assertIn("菜单里已没有、已停用: Old", lines)

    def test_plain_export_marks_nothing_new(self):
        self.assertFalse(any("新增" in line for line in online.export_lines(self.base)))

    def test_sync_result_prints_passwords_and_failed_notice(self):
        status = self.base / "status.json"
        core.save_private_json(status, {"state": "failed", "message": "OpenRC 服务启动后退出"})
        out = io.StringIO()
        with patch.object(online, "CURRENT", _Link(self.base)), \
             patch.object(online, "STATUS", status), \
             patch.object(online, "_service_running", return_value=True), \
             contextlib.redirect_stdout(out):
            online._print_result({"KDDI", "HKT"})
        text = out.getvalue()
        self.assertIn("本次同步没有生效", text)
        self.assertIn(f"密码: {self.password('KDDI')}", text)
        self.assertNotIn("新增", text)
        self.assertNotIn("[警告]", text)
        self.assertNotIn(self.master, text)

    def test_sync_result_warns_when_gateway_is_down(self):
        status = self.base / "status.json"
        core.save_private_json(status, {"state": "ok", "message": "done"})
        out = io.StringIO()
        with patch.object(online, "CURRENT", _Link(self.base)), \
             patch.object(online, "STATUS", status), \
             patch.object(online, "_service_running", return_value=False), \
             contextlib.redirect_stdout(out):
            online._print_result(None)
        self.assertIn("OpenRC: stopped", out.getvalue())
        self.assertIn("install.sh --no-scan", out.getvalue())

    def test_status_points_to_export_without_showing_keys(self):
        status = self.base / "status.json"
        core.save_private_json(status, {"state": "partial", "message": "2/3"})
        log = self.base / "install.log"
        log.write_text("[完成] 2/3 个出口可用\n", encoding="utf-8")
        out = io.StringIO()
        with patch.object(online, "CURRENT", _Link(self.base)), \
             patch.object(online, "STATUS", status), \
             patch.object(online, "LOG", log), \
             patch.object(online.subprocess, "run", return_value=Mock(returncode=0)), \
             contextlib.redirect_stdout(out):
            online._show_status()
        text = out.getvalue()
        self.assertIn("各节点密码: lazycat-export", text)
        self.assertIn("程序版本:", text)
        self.assertNotIn(self.state["server_key"], text)


MENU_V18 = """选择: 1

------ 切换节点 ------
正在获取节点列表...

-------------- 日本 --------------
  [1] 日本SoftBank-动态家宽
  [2] 日本Biglobe动态家宽

-------------- 美国 --------------
  [3] 美国-Pavlov动态家宽

------------- 菲律宾 -------------
  [4] 菲律宾-DITO动态家宽

请输入节点序号进行切换 (输入0取消): """


class VendorV18Tests(unittest.TestCase):
    def test_v18_menu_with_regions_and_serial_prompt_is_parsed(self):
        self.assertEqual(online.parse_menu(MENU_V18),
                         [(1, "日本SoftBank-动态家宽"), (2, "日本Biglobe动态家宽"),
                          (3, "美国-Pavlov动态家宽"), (4, "菲律宾-DITO动态家宽")])

    def test_exit_ip_accepts_ipv4_and_ipv6_and_rejects_pages(self):
        self.assertEqual(online._exit_ip(b"192.0.2.7\n"), "192.0.2.7")
        self.assertEqual(online._exit_ip(b"2001:db8::1\n"), "2001:db8::1")
        with self.assertRaises(ValueError):
            online._exit_ip(b"<html>please register</html>")

    def test_ip_echo_prefers_ipv4_only_hosts(self):
        self.assertEqual(online.IP_ECHO_HOSTS[:2], ("api4.ipify.org", "ipv4.icanhazip.com"))


class PartialVerificationTests(unittest.TestCase):
    """One flaky exit must not throw away a sync where the others work."""

    def test_route_check_retries_and_reports_only_persistent_failures(self):
        calls = []

        def verify(binary, state, name, work, port):
            calls.append(name)
            if name == "b" or calls.count("a") == 1:
                raise online.OnlineError("SSLEOFError")
            return "192.0.2.1"

        with patch.object(online, "_verify_one", side_effect=verify), \
             patch.object(online, "_guard_update"), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            failed = online._verify_routes("sing-box", {}, {"a": "192.0.2.1", "b": "192.0.2.2"},
                                           Path("/tmp"), 12000)
        self.assertEqual(failed, ["b"])
        self.assertEqual(calls, ["a", "a", "b", "b"])
        self.assertIn("[未验证] b", out.getvalue())

    def _candidate(self, failing):
        master = core.generate_master()
        state = core.reconcile_nodes([core.Node("a", "192.0.2.1", 5001, "u", "p"),
                                      core.Node("b", "192.0.2.2", 5002, "u", "p")], master=master)
        with patch.object(online, "_free_port", side_effect=[10001, 10002]), \
             patch.object(online.core, "save_private_config"), \
             patch.object(online.subprocess, "run", return_value=Mock(returncode=0)), \
             patch.object(online.subprocess, "Popen", return_value=Mock()), \
             patch.object(online, "_wait_tcp"), \
             patch.object(online, "_verify_routes",
                          side_effect=lambda b, s, exp, w, p: [n for n in exp if n in failing]), \
             patch.object(online, "_terminate_process"):
            return online.verify_candidate("sing-box", state, {"a": "x", "b": "y"}, Path("/tmp"))

    def test_candidate_returns_the_users_that_did_not_verify(self):
        self.assertEqual(self._candidate({"b"}), ["b"])

    def test_candidate_fails_when_no_user_verifies(self):
        with self.assertRaisesRegex(online.OnlineError, "没有任何出口"):
            self._candidate({"a", "b"})

    def _deploy(self, failing):
        current = Mock()
        current.is_symlink.return_value = True
        current.resolve.return_value = Path("/etc/lazycat-multi/generations/previous")
        with patch.object(online, "CURRENT", current), \
             patch.object(online, "_switch") as switch, \
             patch.object(online, "_start_service"), \
             patch.object(online, "_wait_service_port"), \
             patch.object(online, "_verify_routes", return_value=sorted(failing)), \
             patch.object(online.subprocess, "run", return_value=Mock(returncode=0)), \
             contextlib.redirect_stdout(io.StringIO()):
            try:
                return online._deploy(Path("/etc/lazycat-multi/generations/new"), "sing-box",
                                      {}, {"a": "x", "b": "y"}, Path("/tmp")), switch
            except online.OnlineError as exc:
                return exc, switch

    def test_deploy_keeps_new_config_when_some_users_fail(self):
        result, switch = self._deploy({"b"})
        self.assertEqual(result, ["b"])
        self.assertEqual(switch.call_count, 1)

    def test_deploy_rolls_back_when_no_user_reaches_an_exit(self):
        result, switch = self._deploy({"a", "b"})
        self.assertIsInstance(result, online.OnlineError)
        self.assertEqual(switch.call_args_list[-1].args[0],
                         Path("/etc/lazycat-multi/generations/previous"))


class ReinstallKeyTests(unittest.TestCase):
    """Typing the same code or passphrase on a reinstalled box restores passwords."""

    def test_recovery_code_is_used_as_is(self):
        master = core.generate_master()
        self.assertEqual(core.master_from_secret(f"  {master}\n"), master)

    def test_same_passphrase_gives_same_passwords(self):
        first = core.master_from_secret("my cat likes tea")
        self.assertEqual(core.master_from_secret("my cat likes tea"), first)
        self.assertNotEqual(core.master_from_secret("my cat likes TEA"), first)
        core.derive_server_key(first)  # a valid master seed

    def test_short_passphrase_is_rejected(self):
        with self.assertRaises(ValueError):
            core.master_from_secret("short")

    def test_install_helper_prints_master_and_fingerprint(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(online.sys, "stdin", io.StringIO("my cat likes tea\n")), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(online.main(["_master"]), 0)
        master = out.getvalue().strip()
        self.assertEqual(master, core.master_from_secret("my cat likes tea"))
        state = core.reconcile_nodes([], master=master)
        self.assertIn(state["master_id"][:12], err.getvalue())

    def test_install_helper_rejects_short_text(self):
        with patch.object(online.sys, "stdin", io.StringIO("short\n")), \
             contextlib.redirect_stdout(io.StringIO()) as out, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(online.main(["_master"]), 1)
        self.assertEqual(out.getvalue(), "")

    def test_saved_master_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(online, "MASTER_FILE", root / "master.json"), \
                 patch.object(online, "GENERATIONS", root / "generations"):
                self.assertFalse(online._has_saved_master())
                (root / "generations" / "generation-x").mkdir(parents=True)
                (root / "generations" / "generation-x" / "master.json").write_text("{}")
                self.assertTrue(online._has_saved_master())


class _Link(type(Path())):
    """A real directory that reports itself as the `current` symlink."""

    def is_symlink(self):
        return True


class FollowTests(unittest.TestCase):
    def test_follow_shows_only_new_log_until_worker_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "install.log"
            log.write_bytes("旧日志\n".encode("utf-8"))
            offset = log.stat().st_size
            line = "[上游] 韩国: 192.0.2.7\n".encode("utf-8")
            # The worker writes a line split inside a UTF-8 character, then exits.
            pieces = [line[:3], line[3:], "[完成] 1/1\n".encode("utf-8")]

            def poll():
                with log.open("ab") as stream:
                    stream.write(pieces.pop(0))
                return 0 if not pieces else None

            process = Mock()
            process.poll.side_effect = poll
            out = io.StringIO()
            with patch.object(online, "LOG", log), patch.object(online.time, "sleep"), \
                 contextlib.redirect_stdout(out):
                self.assertTrue(online._follow(process, offset))
        self.assertEqual(out.getvalue(), "[上游] 韩国: 192.0.2.7\n[完成] 1/1\n")

    def test_ctrl_c_only_stops_the_display(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "install.log"
            log.write_bytes(b"")
            process = Mock()
            process.poll.return_value = None
            out = io.StringIO()
            with patch.object(online, "LOG", log), \
                 patch.object(online.time, "sleep", side_effect=KeyboardInterrupt), \
                 contextlib.redirect_stdout(out):
                self.assertFalse(online._follow(process, 0))
        self.assertIn("仍在后台运行", out.getvalue())
        process.terminate.assert_not_called()
        process.kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
