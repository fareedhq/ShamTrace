import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import httpx
from shamtrace.scanner import scan
from shamtrace.policies import policy_findings
from shamtrace.crawl import inspect_pages


class AuditTests(unittest.TestCase):
    def test_require_proxy_stops_before_dns(self):
        with patch('shamtrace.scanner.socket.getaddrinfo') as dns, patch('shamtrace.scanner.inspect_dns') as typed:
            with self.assertRaisesRegex(ValueError, 'No network requests'):
                scan(argparse.Namespace(url='example.test', timeout=5, require_proxy=True))
            dns.assert_not_called()
            typed.assert_not_called()

    def test_policy_evidence(self):
        report = {'target': 'https://example.test', 'cookies': [],
                  'content': {'html': {'forms': [{'action': 'http://example.test/submit'}]}}}
        headers = httpx.Headers({'content-type': 'text/html', 'strict-transport-security': 'max-age=0',
                                 'content-security-policy': "script-src 'unsafe-eval'"})
        ids = {f['id'] for f in policy_findings(headers, report)}
        self.assertTrue({'hsts-disabled-or-ambiguous', 'csp-unsafe-eval', 'form-http-downgrade', 'framing-policy-not-observed'} <= ids)
        report['edge'] = {'skip_followup': True}
        self.assertEqual(policy_findings(headers, report), [])

    def test_crawl_budget_origin_queries_and_challenge(self):
        seen = []
        def handle(request):
            seen.append(str(request.url))
            return httpx.Response(403)
        with httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=False) as client:
            result = inspect_pages(client, 'https://example.test/', {'html': {'links': [
                'https://other.test/', 'https://example.test/?action=delete', 'https://example.test/a', 'https://example.test/b']}}, 3)
        self.assertEqual(seen, ['https://example.test/a'])
        self.assertEqual(result['skipped'], 2)
        self.assertEqual(result['results'][0]['state'], 'restricted')

    def test_report_escapes_target_content_and_is_private(self):
        real_client = httpx.Client
        def handle(request):
            return httpx.Response(200, headers={'server': '<script>alert(1)</script>'}, text='fixture')
        with tempfile.TemporaryDirectory() as directory:
            with patch('shamtrace.scanner.socket.getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 80))]), \
                 patch('shamtrace.scanner.httpx.Client', side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw)), \
                 patch('shamtrace.scanner.show_report'), patch('shamtrace.scanner.console'):
                scan(argparse.Namespace(url='https://example.test', timeout=3, output=directory))
            page = next(Path(directory).glob('*.html')).read_text()
            self.assertNotIn('<script>', page)
            self.assertIn('&lt;script&gt;', page)
            self.assertIn('Content-Security-Policy', page)
            for path in Path(directory).iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_crawl_deduplicates_and_enforces_budget_with_per_page_findings(self):
        seen = []
        def handle(request):
            seen.append(str(request.url))
            return httpx.Response(200, headers={'content-type': 'text/html'}, text='<a href="/third">next</a>')
        with httpx.Client(transport=httpx.MockTransport(handle)) as client:
            result = inspect_pages(client, 'https://example.test', {'html': {'links': [
                'https://example.test/', 'https://example.test/second', 'https://example.test/second']}}, 2)
        self.assertEqual(seen, ['https://example.test/second'])
        self.assertTrue(result['results'][0]['findings'])
        self.assertTrue(all(f['affected_url'] == seen[0] for f in result['results'][0]['findings']))

    def test_proxy_client_is_also_used_for_advisory_requests(self):
        real_client = httpx.Client
        requests = []
        def handle(request):
            requests.append(request)
            if request.url.host == 'api.osv.dev':
                return httpx.Response(200, json={'vulns': []})
            return httpx.Response(200, headers={'content-type': 'text/html'},
                                  text='<script src="https://unpkg.com/jquery@1.2.3/x.js"></script>')
        def make_client(**kwargs):
            self.assertEqual(kwargs.pop('proxy'), 'socks5://127.0.0.1:9050')
            return real_client(transport=httpx.MockTransport(handle), **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            with patch('shamtrace.scanner.httpx.Client', side_effect=make_client), \
                 patch('shamtrace.scanner.socket.getaddrinfo', side_effect=AssertionError('No local target DNS')), \
                 patch('shamtrace.scanner.show_report'), patch('shamtrace.scanner.console'):
                scan(argparse.Namespace(url='https://example.test', timeout=3, output=directory,
                                        proxy='socks5://127.0.0.1:9050', require_proxy=True, cve=True))
            report = json.loads(next(Path(directory).glob('*.json')).read_text())
            self.assertEqual(report['advisories']['status'], 'complete')
            self.assertEqual(report['advisories']['requests'], 1)
            self.assertEqual([r.url.host for r in requests], ['example.test', 'api.osv.dev'])
