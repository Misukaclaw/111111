"""Synthetic strace cases; no real LazyCat trace or credentials are used."""

import json
import unittest

from trace_parser import TraceParseError, extract_socks_outbound


def trace_write(document, fd=9, *, written=None, prefix=""):
    payload = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    quoted = "".join(
        '\\"' if byte == 34 else "\\\\" if byte == 92 else chr(byte)
        if 32 <= byte <= 126 else f"\\{byte:03o}"
        for byte in payload
    )
    count = len(payload)
    result = count if written is None else written
    return f'{prefix}write({fd}, "{quoted}", {count}) = {result}'


def config(*, server="192.0.2.10", port=5009, user="example-user", password="example-pass"):
    return {
        "inbounds": [{"type": "tun", "interface_name": "cat0"}],
        "outbounds": [
            {"type": "socks", "server": server, "server_port": port,
             "username": user, "password": password},
            {"type": "direct", "tag": "direct"},
        ],
    }


class TraceParserTests(unittest.TestCase):
    def test_extracts_only_required_fields_from_completed_write(self):
        line = trace_write(config(), prefix="[pid 123] ")
        self.assertEqual(extract_socks_outbound(line), {
            "server": "192.0.2.10",
            "server_port": 5009,
            "username": "example-user",
            "password": "example-pass",
        })

    def test_duplicate_writes_are_accepted(self):
        document = config()
        trace = "\n".join((trace_write(document, 9), trace_write(document, 6)))
        self.assertEqual(extract_socks_outbound(trace)["server_port"], 5009)

    def test_decodes_hex_and_octal_bytes(self):
        document = config(user="café")
        trace = trace_write(document).replace('"{', '"\\x7b', 1)
        self.assertEqual(extract_socks_outbound(trace)["username"], "café")

    def test_ignores_failed_or_short_writes(self):
        trace = "\n".join((trace_write(config(port=5001), written=0),
                           trace_write(config(port=5002), written=8),
                           trace_write(config(port=5009))))
        self.assertEqual(extract_socks_outbound(trace)["server_port"], 5009)

    def test_rejects_ambiguous_distinct_outbounds_without_disclosing_credentials(self):
        trace = "\n".join((trace_write(config(port=5009)),
                           trace_write(config(port=5004, password="another-example-pass"))))
        with self.assertRaises(TraceParseError) as raised:
            extract_socks_outbound(trace)
        self.assertNotIn("another-example-pass", str(raised.exception))

    def test_rejects_missing_authentication_and_non_socks_data(self):
        trace = "\n".join((trace_write({"outbounds": [{"type": "direct"}]}),
                           trace_write(config(user=""))))
        with self.assertRaisesRegex(TraceParseError, "No complete"):
            extract_socks_outbound(trace)

    def test_ignores_truncated_strace_argument(self):
        trace = 'write(9, "{\\"outbounds\\":...", 933) = 933'
        with self.assertRaisesRegex(TraceParseError, "No complete"):
            extract_socks_outbound(trace)

    def test_rejects_non_numeric_port(self):
        with self.assertRaisesRegex(TraceParseError, "No complete"):
            extract_socks_outbound(trace_write(config(port="5009")))


if __name__ == "__main__":
    unittest.main()
