"""离线测试：只用本地 HTTP 服务器，不依赖外网。

跑法：python3 -m unittest discover -s tests -v
"""
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import site_doctor


def serve(ip, port, handler):
    server = HTTPServer((ip, port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def make_handler(status, headers=None, body=b"ok"):
    headers = headers or {}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    return H


class TestSiteDoctor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        serve("127.0.0.1", 8771, make_handler(200))
        serve("127.0.0.1", 8772, make_handler(502))
        serve("127.0.0.2", 8772, make_handler(200))
        serve("127.0.0.1", 8773, make_handler(301, {"Location": "http://127.0.0.1:8771/"}))
        serve("127.0.0.1", 8774, make_handler(521, {"cf-ray": "test-ray", "Server": "cloudflare"}))

    def test_up(self):
        r = site_doctor.diagnose("http://127.0.0.1:8771/")
        self.assertEqual(r["verdict"], "UP")
        self.assertEqual(r["main"]["status"], 200)

    def test_origin_5xx_without_origin(self):
        r = site_doctor.diagnose("http://127.0.0.1:8772/")
        self.assertEqual(r["verdict"], "ORIGIN_5XX")

    def test_cdn_fail_with_origin(self):
        r = site_doctor.diagnose("http://127.0.0.1:8772/", origin_ip="127.0.0.2")
        self.assertEqual(r["verdict"], "CDN_FAIL")

    def test_redirect_followed(self):
        r = site_doctor.diagnose("http://127.0.0.1:8773/")
        self.assertEqual(r["verdict"], "UP")
        self.assertEqual(len(r["redirect_chain"]), 1)
        self.assertEqual(r["main"]["status"], 200)

    def test_cloudflare_521_without_origin(self):
        r = site_doctor.diagnose("http://127.0.0.1:8774/")
        self.assertEqual(r["verdict"], "ORIGIN_DEAD")

    def test_dns_fail_mocked(self):
        with mock.patch("socket.getaddrinfo", side_effect=OSError("Name or service not known")):
            r = site_doctor.diagnose("https://no-such-host-xyz.invalid")
        self.assertEqual(r["verdict"], "DNS_FAIL")

    def test_tcp_fail(self):
        r = site_doctor.diagnose("http://127.0.0.1:8999/")
        self.assertEqual(r["verdict"], "TCP_FAIL")

    def test_exit_code_down(self):
        self.assertEqual(site_doctor.main(["http://127.0.0.1:8772/", "--no-color"]), 1)

    def test_exit_code_up(self):
        self.assertEqual(site_doctor.main(["http://127.0.0.1:8771/", "--no-color"]), 0)


if __name__ == "__main__":
    unittest.main()
