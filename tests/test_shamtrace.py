import argparse
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from shamtrace.checks import validate_target, inspect_cookies, assess_headers
from shamtrace.scanner import scan


class ChecksTests(unittest.TestCase):
    def test_default_https_and_explicit_port(self):
        target, parsed = validate_target(' example.test:8443/path ')
        self.assertEqual(target, 'https://example.test:8443/path')
        self.assertEqual(parsed.port, 8443)

    def test_invalid_targets(self):
        for target in ['', 'ftp://example.test', 'https://u:p@example.test',
                       'https://example.test/#fragment', 'https://example.test:99999']:
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_target(target)

    def test_cookie_values_excluded_and_flags_case_insensitive(self):
        cookies = inspect_cookies(httpx.Headers([
            ('set-cookie', 'session=TOP_SECRET; Secure; HttpOnly; SameSite=Lax'),
            ('set-cookie', 'theme=dark; secure'),
            ('set-cookie', 'malformed'),
        ]))
        self.assertEqual(len(cookies), 2)
        self.assertTrue(cookies[0]['httponly'])
        self.assertTrue(cookies[1]['secure'])
        self.assertNotIn('TOP_SECRET', json.dumps(cookies))

    def test_header_states_and_https_only_hsts(self):
        headers = httpx.Headers({'content-security-policy': ' ', 'referrer-policy': 'no-referrer'})
        results = {r['header']: r['state'] for r in assess_headers(headers, True)}
        self.assertEqual(results['content-security-policy'], 'empty')
        self.assertEqual(results['referrer-policy'], 'present')
        self.assertEqual(results['x-content-type-options'], 'missing')
        self.assertNotIn('strict-transport-security',
                         {r['header'] for r in assess_headers(headers, False)})


class ScanTests(unittest.TestCase):
    def test_scan_exports_evidence_without_following_redirect(self):
        requests = []
        def handle(request):
            requests.append(request)
            return httpx.Response(302, headers={
                'location': 'https://other.test/',
                'set-cookie': 'session=TOP_SECRET; HttpOnly',
                'server': 'test|server',
            })
        real_client = httpx.Client
        with tempfile.TemporaryDirectory() as directory:
            with patch('shamtrace.scanner.socket.getaddrinfo', return_value=[
                (2, 1, 6, '', ('127.0.0.1', 80))
            ]), patch('shamtrace.scanner.httpx.Client', side_effect=lambda **kw:
                     real_client(transport=httpx.MockTransport(handle), **kw)):
                scan(argparse.Namespace(url='http://example.test', timeout=2, output=directory))
            self.assertEqual(len(requests), 1)
            report = json.loads(next(Path(directory).glob('*.json')).read_text())
            self.assertEqual(report['http_status'], 302)
            self.assertEqual(report['redirect_location'], 'https://other.test/')
            self.assertEqual(report['resolved_ips'], ['127.0.0.1'])
            for file in Path(directory).iterdir():
                self.assertNotIn('TOP_SECRET', file.read_text())
            self.assertIn(r'test\|server', next(Path(directory).glob('*.md')).read_text())

    def test_invalid_timeouts_fail_before_network(self):
        for timeout in [0, -1, 121, float('nan')]:
            with self.subTest(timeout=timeout), patch('shamtrace.scanner.socket.getaddrinfo') as dns:
                with self.assertRaises(ValueError):
                    scan(argparse.Namespace(url='example.test', timeout=timeout, output='unused'))
                dns.assert_not_called()


class CliTests(unittest.TestCase):
    def test_help_version_and_invalid_arguments(self):
        for args, code, expected in [(['-h'], 0, 'scan'), (['--version'], 0, '0.2.0'),
                                      (['scan'], 2, 'required')]:
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, '-m', 'shamtrace', *args],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, code)
                self.assertIn(expected, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
