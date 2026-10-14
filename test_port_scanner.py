"""Tests for the port scanner. Run:  python -m unittest -v"""

import argparse
import csv
import http.server
import json
import os
import socket
import tempfile
import threading
import unittest
from unittest import mock

import port_scanner as ps


class BannerServer:
    """Tiny local TCP server that sends a banner (like ssh/ftp do)."""

    def __init__(self, banner=b"SSH-2.0-TestServer_1.0\r\n"):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.banner = banner
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.sendall(self.banner)
            except OSError:
                pass
            conn.close()

    def close(self):
        self.running = False
        self.sock.close()


def free_closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ParsingTests(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(ps.parse_ports("80"), [80])
        self.assertEqual(ps.parse_ports("20-23"), [20, 21, 22, 23])
        self.assertEqual(ps.parse_ports("443, 22,80,22"), [22, 80, 443])

    def test_parse_ports_bad(self):
        for bad in ("100-20", "0", "70000", "abc", "", "1-"):
            with self.assertRaises(argparse.ArgumentTypeError):
                ps.parse_ports(bad)

    def test_expand_targets(self):
        self.assertEqual(ps.expand_targets("example.com"), ["example.com"])
        self.assertEqual(len(ps.expand_targets("192.168.1.0/24")), 254)
        self.assertEqual(ps.expand_targets("10.0.0.5/32"), ["10.0.0.5"])
        with self.assertRaises(ps.ScanError):
            ps.expand_targets("10.0.0.0/16")
        with self.assertRaises(ps.ScanError):
            ps.expand_targets("999.1.1.1/24")

    def test_top_ports_valid(self):
        self.assertEqual(len(set(ps.TOP_PORTS)), len(ps.TOP_PORTS))
        self.assertTrue(all(1 <= p <= 65535 for p in ps.TOP_PORTS))


class SafetyTests(unittest.TestCase):
    def test_local_vs_public(self):
        self.assertTrue(ps.is_local_address("127.0.0.1"))
        self.assertTrue(ps.is_local_address("192.168.1.10"))
        self.assertTrue(ps.is_local_address("10.1.2.3"))
        self.assertFalse(ps.is_local_address("8.8.8.8"))

    def test_permission_gate(self):
        public = [("scanme", "8.8.8.8")]
        with self.assertRaises(ps.ScanError):
            ps.check_permission(public, confirmed=False)
        ps.check_permission(public, confirmed=True)  # allowed
        ps.check_permission([("lo", "127.0.0.1")], confirmed=False)  # local is fine


class ScanTests(unittest.TestCase):
    def test_open_port_and_banner(self):
        srv = BannerServer()
        try:
            r = ps.scan_port("127.0.0.1", srv.port, timeout=1.0, banner=True)
        finally:
            srv.close()
        self.assertEqual(r["status"], ps.OPEN)
        self.assertEqual(r["banner"], "SSH-2.0-TestServer_1.0")

    def test_open_port_without_banner_option(self):
        srv = BannerServer()
        try:
            r = ps.scan_port("127.0.0.1", srv.port, timeout=1.0)
        finally:
            srv.close()
        self.assertEqual((r["status"], r["banner"]), (ps.OPEN, ""))

    def test_closed_port(self):
        r = ps.scan_port("127.0.0.1", free_closed_port(), timeout=1.0)
        self.assertEqual(r["status"], ps.CLOSED)

    def test_http_banner_uses_server_header(self):
        httpd = http.server.HTTPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            r = ps.scan_port("127.0.0.1", httpd.server_address[1], timeout=1.0, banner=True)
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(r["status"], ps.OPEN)
        self.assertIn("Python", r["banner"])

    def test_timeout_is_reported(self):
        fake = mock.MagicMock()
        fake.connect_ex.side_effect = socket.timeout()
        with mock.patch("port_scanner.socket.socket", return_value=fake):
            r = ps.scan_port("10.255.255.1", 80, timeout=0.1)
        self.assertEqual(r["status"], ps.TIMEOUT)

    def test_timeout_errno_code(self):
        fake = mock.MagicMock()
        fake.connect_ex.return_value = 11  # EAGAIN: what connect_ex returns on timeout
        with mock.patch("port_scanner.socket.socket", return_value=fake):
            r = ps.scan_port("10.255.255.1", 80, timeout=0.1)
        self.assertEqual(r["status"], ps.TIMEOUT)

    def test_other_os_error_is_reported(self):
        fake = mock.MagicMock()
        fake.connect_ex.side_effect = OSError("Network is unreachable")
        with mock.patch("port_scanner.socket.socket", return_value=fake):
            r = ps.scan_port("10.255.255.1", 80, timeout=0.1)
        self.assertEqual(r["status"], ps.ERROR)
        self.assertIn("unreachable", r["detail"])

    def test_run_scan_finds_only_the_open_port(self):
        srv = BannerServer()
        closed = free_closed_port()
        try:
            res, interrupted = ps.run_scan(
                [("localhost", "127.0.0.1")], [srv.port, closed], timeout=1.0, out=lambda *_: None
            )
        finally:
            srv.close()
        by_port = {r["port"]: r["status"] for r in res}
        self.assertEqual(by_port[srv.port], ps.OPEN)
        self.assertEqual(by_port[closed], ps.CLOSED)
        self.assertFalse(interrupted)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.lines = []

    def tearDown(self):
        self.dir.cleanup()

    def path(self, name):
        return os.path.join(self.dir.name, name)

    def test_json_and_csv_export(self):
        srv = BannerServer()
        try:
            code = ps.main(
                [
                    "127.0.0.1",
                    "-p",
                    str(srv.port),
                    "-b",
                    "-l",
                    self.path("s.log"),
                    "--json",
                    self.path("r.json"),
                    "--csv",
                    self.path("r.csv"),
                ],
                out=self.lines.append,
            )
        finally:
            srv.close()
        self.assertEqual(code, 0)
        with open(self.path("r.json"), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["scan"]["counts"]["OPEN"], 1)
        self.assertEqual(data["results"][0]["banner"], "SSH-2.0-TestServer_1.0")
        with open(self.path("r.csv"), newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(rows[0]["status"], "OPEN")
        self.assertTrue(os.path.getsize(self.path("s.log")) > 0)
        ps.setup_logging(os.devnull)  # release the log file (needed on Windows)

    def test_bad_host_returns_error(self):
        code = ps.main(
            ["no-such-host.invalid", "-p", "80", "-l", self.path("s.log")], out=self.lines.append
        )
        self.assertEqual(code, 1)
        ps.setup_logging(os.devnull)

    def test_public_target_needs_permission(self):
        code = ps.main(["8.8.8.8", "-p", "53", "-l", self.path("s.log")], out=self.lines.append)
        self.assertEqual(code, 1)
        ps.setup_logging(os.devnull)

    def test_cidr_scan_of_loopback(self):
        srv = BannerServer()
        try:
            code = ps.main(
                ["127.0.0.1/32", "-p", str(srv.port), "-l", self.path("s.log")],
                out=self.lines.append,
            )
        finally:
            srv.close()
        self.assertEqual(code, 0)
        self.assertTrue(any("1 open" in line for line in self.lines))
        ps.setup_logging(os.devnull)

    def test_ports_and_top_ports_are_exclusive(self):
        with self.assertRaises(SystemExit):
            ps.main(["127.0.0.1", "-p", "80", "--top-ports"], out=self.lines.append)


if __name__ == "__main__":
    unittest.main()
