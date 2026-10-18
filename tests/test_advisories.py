import unittest
import httpx
from shamtrace.advisories import identify_components, lookup_advisories


class AdvisoryTests(unittest.TestCase):
    def test_requires_explicit_version_and_known_cdn(self):
        urls = ['https://cdn.jsdelivr.net/npm/lamejs@1.2.1/lame.min.js',
                'https://unpkg.com/@scope/pkg@2.3.4/a.js',
                'https://cdn.jsdelivr.net/npm/react@latest/a.js',
                'https://evil.test/npm/jquery@1.0.0/a.js', 'https://site.test/assets/index-hash.js']
        found = identify_components(urls)
        self.assertEqual([(c['name'], c['version']) for c in found], [('lamejs', '1.2.1'), ('@scope/pkg', '2.3.4')])

    def test_lookup_only_sends_package_version_and_marks_pagination(self):
        component = identify_components(['https://unpkg.com/jquery@1.2.3/a.js'])[0]
        def handle(request):
            import json
            self.assertEqual(str(request.url), 'https://api.osv.dev/v1/query')
            self.assertEqual(json.loads(request.content), {'package': {'name': 'jquery', 'ecosystem': 'npm'}, 'version': '1.2.3'})
            return httpx.Response(200, json={'vulns': [{'id': 'TEST-1', 'aliases': ['CVE-TEST'], 'summary': 'Fixture'},
                                                      {'id': 'WITHDRAWN', 'withdrawn': '2020-01-01'}], 'next_page_token': 'more'})
        with httpx.Client(transport=httpx.MockTransport(handle)) as client:
            result = lookup_advisories(client, [component], True)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['results'][0]['advisories']), 1)

    def test_disabled_empty_and_failure_are_not_clean_results(self):
        def handle(request):
            raise httpx.ConnectError('offline')
        with httpx.Client(transport=httpx.MockTransport(handle)) as client:
            self.assertEqual(lookup_advisories(client, [], True)['status'], 'not_applicable')
            self.assertEqual(lookup_advisories(client, [], False)['status'], 'disabled')
            component = {'name': 'x', 'version': '1.0.0', 'ecosystem': 'npm'}
            result = lookup_advisories(client, [component], True)
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['results'][0]['status'], 'error')
