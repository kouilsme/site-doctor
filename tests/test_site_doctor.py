"""离线回归测试：临时本地端口 + 模拟解析，不访问外网。"""
import contextlib
import io
import json
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import site_doctor


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            '/bad': (502, {}),
            '/cf': (521, {'cf-ray': 'test-ray'}),
            '/redirect': (302, {'Location': '/'}),
            '/loop-a': (302, {'Location': '/loop-b'}),
            '/loop-b': (302, {'Location': '/loop-a'}),
            '/fragment': (302, {'Location': '/fragment#again'}),
            '/invalid': (302, {'Location': 'http://[broken'}),
            '/ftp': (302, {'Location': 'ftp://example.test/file'}),
            '/missing': (404, {}),
        }
        status, headers = routes.get(self.path, (200, {}))
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header('X-Received-Host', self.headers['Host'])
        self.send_header('X-Received-Path', self.path)
        self.end_headers()
        # 不发正文；HTTP 诊断不应等待正文到达。

    def log_message(self, *args):
        pass


def result(status=200, **kwargs):
    value = dict(ip='192.0.2.1', tcp_ms=1, tcp_error='', tls_ms=None,
                 cert_days=None, tls_error='', status=status, headers={},
                 ttfb_ms=1, http_error='')
    value.update(kwargs)
    return value


class TestSiteDoctor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = 'http://127.0.0.1:{}'.format(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.dig = mock.patch.object(site_doctor, 'dig_cname', return_value=[])
        self.dig.start()
        self.addCleanup(self.dig.stop)

    def test_up(self):
        self.assertEqual(site_doctor.diagnose(self.base)['verdict'], 'UP')

    def test_origin_5xx_without_origin(self):
        self.assertEqual(site_doctor.diagnose(self.base + '/bad')['verdict'], 'ORIGIN_5XX')

    def test_cdn_fail_with_origin(self):
        with mock.patch.object(site_doctor, 'check_via', side_effect=[result(502), result(200)]):
            r = site_doctor.diagnose(self.base, origin_ip='192.0.2.2')
        self.assertEqual(r['verdict'], 'CDN_FAIL')

    def test_redirect_followed(self):
        r = site_doctor.diagnose(self.base + '/redirect')
        self.assertEqual(r['verdict'], 'UP')
        self.assertEqual(len(r['redirect_chain']), 1)
        self.assertEqual(r['url'], self.base + '/redirect')
        self.assertEqual(r['final_url'], self.base + '/')

    def test_cloudflare_521_without_origin(self):
        self.assertEqual(site_doctor.diagnose(self.base + '/cf')['verdict'], 'ORIGIN_DEAD')

    def test_dns_fail(self):
        with mock.patch('socket.getaddrinfo', side_effect=OSError('DNS failed')):
            r = site_doctor.diagnose('https://example.invalid')
        self.assertEqual(r['verdict'], 'DNS_FAIL')
        self.assertNotIn('main', r)

    def test_tcp_fail(self):
        with mock.patch.object(site_doctor, 'tcp_connect', return_value=(None, 1, 'refused')):
            r = site_doctor.diagnose(self.base)
        self.assertEqual(r['verdict'], 'TCP_FAIL')

    def test_exit_codes_and_json(self):
        for path, code in [('/', 0), ('/bad', 1), ('/missing', 0), ('/loop-a', 1)]:
            with self.subTest(path=path), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(site_doctor.main([self.base + path, '--json']), code)
                self.assertIn('verdict', json.loads(output.getvalue()))

    def test_redirect_loops(self):
        for path in ['/loop-a', '/fragment']:
            with self.subTest(path=path):
                r = site_doctor.diagnose(self.base + path)
                self.assertEqual(r['verdict'], 'REDIRECT_LOOP')
                with contextlib.redirect_stdout(io.StringIO()):
                    site_doctor.print_human(r, False)

    def test_redirect_limit(self):
        self.assertEqual(site_doctor.diagnose(self.base + '/redirect', max_redirects=0)['verdict'],
                         'REDIRECT_LOOP')
        self.assertEqual(site_doctor.diagnose(self.base + '/redirect', max_redirects=1)['verdict'], 'UP')
        self.assertEqual(site_doctor.diagnose(self.base, max_redirects=0)['verdict'], 'UP')

    def test_invalid_redirect(self):
        for path in ['/invalid', '/ftp']:
            with self.subTest(path=path):
                r = site_doctor.diagnose(self.base + path)
                self.assertEqual(r['verdict'], 'URL_INVALID')
                self.assertEqual(r['url'], self.base + path)
                self.assertEqual(len(r['redirect_chain']), 1)

    def test_bad_urls(self):
        for url in ['http://[broken', 'http://x:bad', 'http://x:65536', 'http://x:0',
                    'ftp://example.test', 'https://', '', 'http://user:secret@example.test',
                    'http://exa mple.test', 'http://example.test/a\nb']:
            with self.subTest(url=url):
                self.assertEqual(site_doctor.diagnose(url)['verdict'], 'URL_INVALID')

    def test_multiple_urls_continue_after_invalid(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = site_doctor.main(['http://x:bad', self.base, '--json'])
        self.assertEqual(code, 1)
        self.assertEqual([r['verdict'] for r in json.loads(output.getvalue())], ['URL_INVALID', 'UP'])

    def test_host_header_includes_port(self):
        r = site_doctor.diagnose(self.base)
        self.assertEqual(r['main']['headers']['X-Received-Host'],
                         '127.0.0.1:{}'.format(self.server.server_port))

    def test_unicode_path_and_params(self):
        r = site_doctor.diagnose(self.base + '/中文;参数?q=空 格')
        self.assertEqual(r['verdict'], 'UP')
        self.assertEqual(r['main']['headers']['X-Received-Path'],
                         '/%E4%B8%AD%E6%96%87;%E5%8F%82%E6%95%B0?q=%E7%A9%BA%20%E6%A0%BC')

    def test_url_normalization(self):
        self.assertEqual(site_doctor.normalize_url('例子.测试/中文#fragment'),
                         'https://xn--fsqu00a.xn--0zwm56d/%E4%B8%AD%E6%96%87')
        self.assertEqual(site_doctor.normalize_url('http://[::1]:80'), 'http://[::1]/')
        self.assertEqual(site_doctor.normalize_url('example.test/?next=https://other.test'),
                         'https://example.test/?next=https://other.test')

    def test_schemeless_redirect_and_origin(self):
        redirect = result(302, headers={'Location': '/end'})
        with mock.patch.object(site_doctor, 'resolve', return_value=(['192.0.2.1'], 1, '')), \
             mock.patch.object(site_doctor, 'check_via', side_effect=[redirect, result(), result()]) as check:
            r = site_doctor.diagnose('example.test/start', origin_ip='192.0.2.2')
        self.assertEqual(r['final_url'], 'https://example.test/end')
        self.assertIn('origin', r)
        self.assertEqual(check.call_args.args[:2], ('192.0.2.2', 'example.test'))

    def test_cross_host_redirect_skips_origin(self):
        with mock.patch.object(site_doctor, 'resolve', return_value=(['192.0.2.1'], 1, '')), \
             mock.patch.object(site_doctor, 'check_via', side_effect=[
                 result(302, headers={'Location': 'https://other.test/'}), result()]) as check:
            r = site_doctor.diagnose('example.test', origin_ip='192.0.2.2')
        self.assertNotIn('origin', r)
        self.assertEqual(check.call_count, 2)

    def test_ip_fallback_retains_evidence(self):
        with mock.patch.object(site_doctor, 'resolve', return_value=(['::1', '127.0.0.1'], 1, '')), \
             mock.patch.object(site_doctor, 'check_via', side_effect=[
                 result(None, tcp_error='unreachable', ip='::1'), result(ip='127.0.0.1')]):
            r = site_doctor.diagnose(self.base)
        self.assertEqual(r['verdict'], 'UP_WITH_WARNING')
        self.assertEqual(r['main']['ip'], '127.0.0.1')
        self.assertEqual(r['attempts'][0]['tcp_error'], 'unreachable')

    def test_no_fallback_on_http_error_status(self):
        with mock.patch.object(site_doctor, 'resolve', return_value=(['::1', '127.0.0.1'], 1, '')), \
             mock.patch.object(site_doctor, 'check_via', return_value=result(502)) as check:
            r = site_doctor.diagnose(self.base)
        self.assertEqual(r['verdict'], 'ORIGIN_5XX')
        self.assertEqual(check.call_count, 1)

    def test_all_addresses_fail(self):
        with mock.patch.object(site_doctor, 'resolve', return_value=(['::1', '127.0.0.1'], 1, '')), \
             mock.patch.object(site_doctor, 'check_via', return_value=result(None, tcp_error='refused')):
            r = site_doctor.diagnose(self.base)
        self.assertEqual(r['verdict'], 'TCP_FAIL')
        self.assertEqual(len(r['attempts']), 2)

    def test_origin_500_does_not_mean_healthy(self):
        for failure in [result(None, tcp_error='refused'), result(None, http_error='closed')]:
            with self.subTest(failure=failure), \
                 mock.patch.object(site_doctor, 'check_via', side_effect=[failure, result(500)]):
                r = site_doctor.diagnose(self.base, origin_ip='192.0.2.2')
            self.assertNotEqual(r['verdict'], 'CDN_FAIL')

    def test_invalid_cli_options(self):
        for option, values in [('--timeout', ['0', '-1', 'nan', 'inf']),
                               ('--max-redirects', ['-1']), ('--cert-warn-days', ['-1']),
                               ('--origin-ip', ['example.test'])]:
            for value in values:
                with self.subTest(option=option, value=value), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        site_doctor.main([self.base, option + '=' + value])
                    self.assertEqual(raised.exception.code, 2)


class TestNetworkHelpers(unittest.TestCase):
    def test_streaming_body_does_not_delay_headers(self):
        release = threading.Event()
        finished = threading.Event()

        class SlowBody(Handler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '10000')
                self.end_headers()
                self.wfile.flush()
                release.wait(2)

        server = ThreadingHTTPServer(('127.0.0.1', 0), SlowBody)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        values = []

        def check():
            try:
                values.append(site_doctor.check_via('127.0.0.1', '127.0.0.1',
                              server.server_port, '/', False, 5))
            finally:
                finished.set()

        client_thread = threading.Thread(target=check, daemon=True)
        client_thread.start()
        try:
            self.assertTrue(finished.wait(1), '诊断应在服务器发送正文前完成')
            self.assertEqual(values[0]['status'], 200)
        finally:
            release.set()
            client_thread.join(timeout=3)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

    def test_cname_skips_ip_literals(self):
        with mock.patch('subprocess.run') as run:
            self.assertEqual(site_doctor.dig_cname('127.0.0.1'), [])
            self.assertEqual(site_doctor.dig_cname('::1'), [])
        run.assert_not_called()

    def test_dns_timeout_without_global_socket_changes(self):
        release = threading.Event()
        finished = threading.Event()

        def blocked(*args, **kwargs):
            try:
                release.wait(2)
                return []
            finally:
                finished.set()

        try:
            with mock.patch('socket.getaddrinfo', side_effect=blocked), \
                 mock.patch('socket.setdefaulttimeout') as global_timeout:
                ips, _, error = site_doctor.resolve('example.test', .02)
                self.assertEqual(ips, [])
                self.assertIn('超过', error)
                global_timeout.assert_not_called()
        finally:
            release.set()
            self.assertTrue(finished.wait(2))

    def test_dns_preserves_address_order(self):
        infos = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 0, 0, 0)),
                 (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))]
        with mock.patch('socket.getaddrinfo', return_value=infos + infos):
            self.assertEqual(site_doctor.resolve('example.test', 1)[0], ['::1', '127.0.0.1'])

    def test_headers_only_and_ipv6_host(self):
        for host, port, tls, expected in [('::1', 8080, False, '[::1]:8080'),
                                         ('::1', 443, True, '[::1]'),
                                         ('example.test', 80, False, 'example.test')]:
            with self.subTest(host=host, port=port):
                sock, conn, resp = mock.Mock(), mock.Mock(), mock.Mock()
                resp.status = 200
                resp.getheaders.return_value = [('Server', 'test')]
                conn.getresponse.return_value = resp
                name = 'http.client.HTTPSConnection' if tls else 'http.client.HTTPConnection'
                with mock.patch(name, return_value=conn):
                    status, headers, _, error = site_doctor.http_get(sock, host, port, '/', tls, 1)
                self.assertEqual((status, error), (200, ''))
                conn.putheader.assert_any_call('Host', expected)
                resp.read.assert_not_called()
                resp.close.assert_called_once()
                conn.close.assert_called_once()

    def test_http_exception_closes_connection(self):
        conn = mock.Mock()
        conn.getresponse.side_effect = OSError('closed')
        with mock.patch('http.client.HTTPConnection', return_value=conn):
            status, _, _, error = site_doctor.http_get(mock.Mock(), 'example.test', 80, '/', False, 1)
        self.assertIsNone(status)
        self.assertEqual(error, 'closed')
        conn.close.assert_called_once()

    def test_tls_failure_closes_socket(self):
        sock = mock.Mock()
        ctx = mock.Mock()
        ctx.wrap_socket.side_effect = OSError('handshake failed')
        with mock.patch('ssl.create_default_context', return_value=ctx):
            wrapped, _, _, error = site_doctor.tls_info(sock, 'example.test', 1)
        self.assertIsNone(wrapped)
        self.assertEqual(error, 'handshake failed')
        sock.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
