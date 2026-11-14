#!/usr/bin/python3
"""Tests for the Chrome native messaging host.

Run from the tool directory with:

    python3 test/test_host.py

The host is exercised as Chrome runs it: a length-prefixed JSON request on
stdin, a length-prefixed JSON reply on stdout.  A fake ryll records the argv
it was launched with, so the tests never open a GUI or touch the network.
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOST = HERE.parent / "native" / "ryll-vv-host.py"


class HostTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()

        self.vv = Path(self.tmp.name) / "console.vv"
        self.vv.write_text(
            "[virt-viewer]\nhost=127.0.0.1\nport=5900\ndelete-this-file=1\n",
            encoding="utf-8",
        )

        self.argv_log = Path(self.tmp.name) / "argv.txt"
        self.fake_ryll = Path(self.tmp.name) / "ryll"
        self.fake_ryll.write_text(
            '#!/bin/sh\nprintf "%s\\n" "$@" > "$FAKE_RYLL_LOG"\n',
            encoding="utf-8",
        )
        self.fake_ryll.chmod(0o755)

    def env(self):
        env = os.environ.copy()
        env["HOME"] = str(self.home)
        env["RYLL_BIN"] = str(self.fake_ryll)
        env["FAKE_RYLL_LOG"] = str(self.argv_log)
        return env

    def run_host(self, payload):
        return subprocess.run(
            [sys.executable, str(HOST)],
            input=payload,
            capture_output=True,
            env=self.env(),
            timeout=15,
        )

    @staticmethod
    def frame(value):
        body = json.dumps(value).encode("utf-8")
        return struct.pack("=I", len(body)) + body

    def parse_reply(self, result):
        self.assertGreaterEqual(len(result.stdout), 4, result.stderr.decode())
        (size,) = struct.unpack("=I", result.stdout[:4])
        return json.loads(result.stdout[4 : 4 + size])

    def assert_ok(self, payload):
        result = self.run_host(self.frame(payload))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        reply = self.parse_reply(result)
        self.assertTrue(reply["ok"], reply)
        return reply

    def assert_error(self, payload, message):
        result = self.run_host(self.frame(payload))
        self.assertNotEqual(result.returncode, 0)
        reply = self.parse_reply(result)
        self.assertFalse(reply["ok"], reply)
        self.assertIn(message, reply["error"])
        return reply

    def wait_for_argv(self):
        deadline = time.time() + 5
        while not self.argv_log.exists() and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(self.argv_log.exists(), "ryll was not launched")

    def test_launches_ryll_with_file_argument(self):
        reply = self.assert_ok({"path": str(self.vv)})
        self.assertGreater(reply["pid"], 0)
        self.wait_for_argv()
        self.assertEqual(
            self.argv_log.read_text(encoding="utf-8").splitlines(),
            ["--file", str(self.vv)],
        )

    def test_rejects_relative_path(self):
        self.assert_error({"path": "console.vv"}, "not absolute")

    def test_rejects_non_vv_file(self):
        other = Path(self.tmp.name) / "console.txt"
        other.write_text("not a connection descriptor\n", encoding="utf-8")
        self.assert_error({"path": str(other)}, "non-.vv")

    def test_rejects_missing_file(self):
        self.assert_error(
            {"path": str(Path(self.tmp.name) / "gone.vv")}, "cannot stat"
        )

    def test_rejects_directory(self):
        directory = Path(self.tmp.name) / "directory.vv"
        directory.mkdir()
        self.assert_error({"path": str(directory)}, "not a regular file")

    def test_rejects_oversized_file(self):
        oversized = Path(self.tmp.name) / "oversized.vv"
        oversized.write_bytes(b"x" * ((1 << 20) + 1))
        self.assert_error({"path": str(oversized)}, "too large")

    def test_rejects_malformed_json(self):
        body = b"not json"
        result = self.run_host(struct.pack("=I", len(body)) + body)
        self.assertNotEqual(result.returncode, 0)
        reply = self.parse_reply(result)
        self.assertFalse(reply["ok"], reply)
        self.assertIn("invalid JSON", reply["error"])

    def test_rejects_truncated_request(self):
        result = self.run_host(b"\x01")
        self.assertNotEqual(result.returncode, 0)
        reply = self.parse_reply(result)
        self.assertFalse(reply["ok"], reply)
        self.assertIn("truncated", reply["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
