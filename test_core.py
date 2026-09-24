"""Synthetic tests for the single-port SS2022 configuration core."""

import base64
import os
from pathlib import Path
import stat
import tempfile
import unittest
from urllib.parse import unquote, urlsplit

import core


def fake_nodes():
    return [
        core.Node("alpha", "127.0.0.1", 11001, "alice", "sample-a"),
        core.Node("beta", "127.0.0.1", 11002, "bob", "sample-b"),
    ]


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.master = core.generate_master()

    def test_master_and_deterministic_rebuild(self):
        self.assertGreaterEqual(len(base64.b64decode(self.master)), 32)
        first = core.reconcile_nodes(fake_nodes(), master=self.master)
        rebuilt = core.reconcile_nodes(fake_nodes(), master=self.master)
        self.assertEqual(first, rebuilt)
        self.assertEqual(first["server_key"], core.derive_server_key(self.master))
        self.assertEqual(
            first["nodes"]["alpha"]["user_key"],
            core.derive_user_key(self.master, "alpha"),
        )
        with self.assertRaisesRegex(ValueError, "LC_MASTER"):
            core.reconcile_nodes(fake_nodes(), first, master=core.generate_master())
        with self.assertRaisesRegex(ValueError, "LC_MASTER"):
            core.reconcile_nodes(fake_nodes(), master=base64.b64encode(b"short").decode())

    def test_reconcile_add_update_remove_and_duplicates(self):
        initial = core.reconcile_nodes(fake_nodes(), master=self.master)
        changed = core.reconcile_nodes(
            [
                {"name": "alpha", "server": "::1", "server_port": 12001,
                 "username": "new-user", "password": "new-sample"},
                core.Node("gamma", "127.0.0.1", 11003),
            ],
            initial,
            master=self.master,
        )
        self.assertEqual(changed["nodes"]["alpha"]["user_key"], initial["nodes"]["alpha"]["user_key"])
        self.assertEqual(changed["server_key"], initial["server_key"])
        self.assertEqual(changed["nodes"]["alpha"]["server_port"], 12001)
        self.assertNotIn("beta", changed["nodes"])
        self.assertIn("gamma", changed["nodes"])
        with self.assertRaisesRegex(ValueError, "duplicate node name"):
            core.reconcile_nodes([fake_nodes()[0], fake_nodes()[0]], master=self.master)
        removed = core.remove_node(changed, "alpha")
        self.assertNotIn("alpha", removed["nodes"])
        with self.assertRaises(KeyError):
            core.remove_node(removed, "alpha")
        added = core.upsert_node(removed, fake_nodes()[0], master=self.master)
        self.assertEqual(added["nodes"]["alpha"]["user_key"], initial["nodes"]["alpha"]["user_key"])

    def test_config_single_inbound_routes_every_user_and_rejects_fallback(self):
        state = core.reconcile_nodes(fake_nodes(), master=self.master)
        config = core.build_config(state, listen="::", listen_port=8388)
        self.assertEqual(len(config["inbounds"]), 1)
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["type"], "shadowsocks")
        self.assertEqual(inbound["method"], core.METHOD)
        self.assertEqual(inbound["listen_port"], 8388)
        self.assertEqual({u["name"] for u in inbound["users"]}, {"alpha", "beta"})
        routes = config["route"]["rules"]
        self.assertEqual(routes[-1], {"inbound": ["ss-in"], "action": "reject"})
        by_name = {r["auth_user"][0]: r["outbound"] for r in routes[:-1]}
        outbounds = {o["tag"]: o for o in config["outbounds"]}
        self.assertEqual(set(by_name), {"alpha", "beta"})
        self.assertEqual(set(by_name.values()), set(outbounds))
        self.assertEqual(outbounds[by_name["alpha"]]["server_port"], 11001)
        self.assertEqual(outbounds[by_name["beta"]]["username"], "bob")
        self.assertNotIn("final", config["route"])

    def test_client_credentials_and_sip002_2022_uri(self):
        state = core.reconcile_nodes(fake_nodes(), master=self.master)
        client = core.client_config(state, "alpha", "2001:db8::1", 8388)
        self.assertEqual(client["password"], state["server_key"] + ":" + state["nodes"]["alpha"]["user_key"])
        link = core.client_link(state, "alpha", "2001:db8::1", 8388)
        split = urlsplit(link)
        self.assertEqual(split.hostname, "2001:db8::1")
        self.assertEqual(split.port, 8388)
        self.assertEqual(unquote(split.username), core.METHOD)
        self.assertEqual(unquote(split.password), client["password"])
        self.assertEqual(unquote(split.fragment), "alpha")
        self.assertIn("%3A", link)
        with self.assertRaises(KeyError):
            core.client_link(state, "missing", "example.org", 8388)

    def test_private_state_round_trip(self):
        state = core.reconcile_nodes(fake_nodes(), master=self.master)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "private" / "state.json"
            core.save_private_state(path, state)
            loaded = core.load_private_state(path)
            self.assertEqual(loaded, state)
            self.assertEqual(core.reconcile_nodes(fake_nodes(), loaded, master=self.master), state)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            config_path = path.parent / "config.json"
            core.save_private_config(config_path, core.build_config(state))
            self.assertTrue(config_path.exists())

    def test_validation_rejects_malformed_record(self):
        with self.assertRaisesRegex(ValueError, "SOCKS port"):
            core.reconcile_nodes([core.Node("a", "127.0.0.1", 0)], master=self.master)
        with self.assertRaisesRegex(ValueError, "SOCKS credentials"):
            core.reconcile_nodes([core.Node("a", "127.0.0.1", 1080, "x", "")], master=self.master)
        with self.assertRaisesRegex(ValueError, "node name"):
            core.reconcile_nodes([core.Node(" alpha ", "127.0.0.1", 1080)], master=self.master)


if __name__ == "__main__":
    unittest.main()
