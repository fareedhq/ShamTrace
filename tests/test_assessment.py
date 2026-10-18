import unittest
import httpx
from shamtrace.discovery import inspect_metadata, inspect_scripts
from shamtrace.assessment import assess


class AssessmentTests(unittest.TestCase):
    def metadata(self, body, mime='text/plain', baseline=None):
        def handle(request):
            return httpx.Response(200, headers={'content-type': mime}, content=body)
        with httpx.Client(transport=httpx.MockTransport(handle)) as client:
            return inspect_metadata(client, 'https://example.test', baseline)

    def test_html_200_is_not_valid_metadata(self):
        results = self.metadata('<html><title>App</title></html>', 'text/html')
        self.assertTrue(all(r['validation']['state'] == 'invalid' for r in results))

    def test_identical_page_is_reported_as_fallback(self):
        import hashlib
        body = b'<html>Application fallback</html>'
        results = self.metadata(body, 'text/html', hashlib.sha256(body).hexdigest())
        self.assertTrue(all(r['validation']['state'] == 'fallback' for r in results))

    def test_recognizes_specific_formats(self):
        self.assertEqual(self.metadata('User-agent: *\nDisallow: /private')[0]['validation']['state'], 'recognized')
        sitemap = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.test/</loc></url></urlset>'
        result = self.metadata(sitemap, 'application/xml')[1]['validation']
        self.assertEqual(result['state'], 'recognized')
        self.assertEqual(result['location_count'], 1)
        security = 'Contact: mailto:security@example.test\nExpires: 2099-01-01T00:00:00Z'
        self.assertEqual(self.metadata(security)[2]['validation']['state'], 'recognized')

    def test_invalid_xml_expired_security_and_truncation(self):
        self.assertEqual(self.metadata('<urlset>')[1]['validation']['state'], 'invalid')
        security = 'Contact: mailto:a@example.test\nExpires: 2000-01-01T00:00:00Z'
        self.assertEqual(self.metadata(security)[2]['validation']['state'], 'invalid')
        self.assertEqual(self.metadata('x' * 70000)[0]['validation']['state'], 'inconclusive')
        xml = '<!DOCTYPE urlset [<!ENTITY x "hello">]><urlset/>'
        self.assertEqual(self.metadata(xml)[1]['validation']['state'], 'invalid')

    def test_script_scope_budget_and_no_api_requests(self):
        seen = []
        def handle(request):
            seen.append(str(request.url))
            return httpx.Response(200, headers={'content-type': 'application/javascript'},
                                  text='fetch("/api/users?token=secret");fetch("/v1/items")')
        scripts = ['https://external.test/x.js', 'http://example.test/a.js']
        scripts += [f'https://example.test/{n}.js' for n in range(5)]
        with httpx.Client(transport=httpx.MockTransport(handle)) as client:
            result = inspect_scripts(client, 'https://example.test/', scripts)
        self.assertEqual(len(seen), 3)
        self.assertTrue(all(url.startswith('https://example.test/') for url in seen))
        self.assertEqual(result['results'][0]['api_path_hints'], ['/api/users', '/v1/items'])
        self.assertNotIn('secret', str(result))

    def test_zero_forms_is_not_claimed_to_describe_rendered_application(self):
        report = {'http_status': 200, 'tls': 'TLS verified', 'findings': [],
                  'content': {'truncated': False, 'html': {'scripts': ['app.js'], 'link_count': 0, 'forms': []}}}
        result = assess(report)
        self.assertIn('Client-rendered', ' '.join(result['conclusions']))
        self.assertTrue(result['coverage_gaps'])

    def test_extended_scan_exports_interpretation_and_bounded_requests(self):
        import argparse
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from shamtrace.scanner import scan
        seen = []
        def handle(request):
            seen.append(str(request.url))
            return httpx.Response(200, headers={'content-type': 'text/html'},
                                  text='<html><title>Fixture</title><script src="/app.js"></script></html>')
        real_client = httpx.Client
        with tempfile.TemporaryDirectory() as directory:
            with patch('shamtrace.scanner.inspect_dns', return_value={'queries': []}), \
                 patch('shamtrace.scanner.socket.getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 80))]), \
                 patch('shamtrace.scanner.httpx.Client', side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw)), \
                 patch('shamtrace.scanner.show_report'), patch('shamtrace.scanner.console'):
                scan(argparse.Namespace(url='https://example.test', timeout=2, profile='extended', output=directory))
            report = json.loads(next(Path(directory).glob('*.json')).read_text())
            self.assertEqual(len(seen), 5)
            self.assertEqual(report['summary']['requests'], 5)
            self.assertTrue(all(e['validation']['state'] == 'fallback' for e in report['metadata_endpoints']))
            self.assertEqual(report['scripts']['results'][0]['state'], 'not_analyzed')
            markdown = next(Path(directory).glob('*.md')).read_text()
            self.assertIn('Coverage gaps', markdown)
            self.assertIn('fallback', markdown)
