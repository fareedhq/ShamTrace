import unittest
import httpx
from shamtrace.content import inspect_document, build_findings


class ContentTests(unittest.TestCase):
    def inspect(self, body, limit=512*1024, content_type='text/html'):
        response = httpx.Response(200, headers={'content-type': content_type}, content=body)
        return inspect_document(response, 'https://example.test/path', limit)

    def test_html_evidence_and_relative_references(self):
        result = self.inspect(b'<title>A &amp; B</title><meta name="generator" content="Example">'
                              b'<form method="post" action="/login"></form><a href="/">home</a>'
                              b'<script src="http://cdn.test/a.js"></script><img src="/logo.png">')
        html = result['html']
        self.assertEqual(html['title'], 'A & B')
        self.assertEqual(html['forms'], [{'method': 'POST', 'action': 'https://example.test/login'}])
        self.assertEqual(html['link_count'], 1)
        self.assertEqual(len(html['http_resources_on_https']), 1)
        self.assertIn('https://example.test', html['resource_origins'])
        findings = build_findings({'target': 'https://example.test', 'headers': [],
                                   'cookies': [], 'content': result})
        self.assertEqual(findings[0]['id'], 'mixed-content-references')

    def test_truncation_and_hash_of_inspected_bytes(self):
        import hashlib
        result = self.inspect(b'abcdefgh', limit=4)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['bytes_inspected'], 4)
        self.assertEqual(result['sha256_inspected_bytes'], hashlib.sha256(b'abcd').hexdigest())
        self.assertFalse(self.inspect(b'abcd', limit=4)['truncated'])

    def test_binary_body_not_parsed_as_html(self):
        self.assertIsNone(self.inspect(b'\x00\xff', content_type='image/png')['html'])

    def test_base_element_resolves_resource_origin(self):
        result = self.inspect(b'<base href="https://cdn.test/"><script src="a.js"></script>')
        self.assertEqual(result['html']['resource_origins'], ['https://cdn.test'])
