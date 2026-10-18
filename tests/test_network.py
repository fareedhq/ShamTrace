import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit
import httpx
from shamtrace.network import network_options
from shamtrace.edge import inspect_edge
from shamtrace.scanner import scan


class NetworkTests(unittest.TestCase):
    def test_onion_requires_proxy_and_proxy_validation(self):
        for proxy in [None, 'http://localhost:9050', 'socks5://localhost', 'socks5://localhost:9050/path']:
            with self.subTest(proxy=proxy), self.assertRaises(ValueError):
                network_options(urlsplit('http://example.onion'), proxy)
        options = network_options(urlsplit('http://example.onion'), 'socks5://127.0.0.1:9050')
        self.assertFalse(options['local_target_dns'])
        self.assertFalse(options['tor_verified'])

    def test_cf_challenge_vs_no_indicators(self):
        result = inspect_edge(httpx.Headers({'cf-ray': 'sample', 'cf-mitigated': 'challenge'}), 403)
        self.assertTrue(result['cloudflare']['challenge'])
        self.assertTrue(result['skip_followup'])
        self.assertEqual(inspect_edge(httpx.Headers({'server': 'Vercel'}), 200)['cloudflare']['state'], 'not_observed')
        self.assertFalse(inspect_edge(httpx.Headers({'server': 'cloudflare'}), 200)['skip_followup'])

    def test_proxy_never_resolves_target_locally_and_challenge_stops_followup(self):
        seen = []
        real_client = httpx.Client
        def client_factory(**kwargs):
            self.assertEqual(kwargs.pop('proxy'), 'socks5://127.0.0.1:9050')
            def handle(request):
                seen.append(str(request.url))
                return httpx.Response(403, headers={'cf-mitigated': 'challenge', 'content-type': 'text/html'}, text='<title>Challenge</title>')
            return real_client(transport=httpx.MockTransport(handle), **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            with patch('shamtrace.scanner.socket.getaddrinfo') as dns, \
                 patch('shamtrace.scanner.inspect_dns') as typed_dns, \
                 patch('shamtrace.scanner.httpx.Client', side_effect=client_factory), \
                 patch('shamtrace.scanner.show_report'), patch('shamtrace.scanner.console'):
                scan(argparse.Namespace(url='http://example.onion', timeout=5, profile='extended',
                                        proxy='socks5://127.0.0.1:9050', output=directory))
                dns.assert_not_called()
                typed_dns.assert_not_called()
            report = json.loads(next(Path(directory).glob('*.json')).read_text())
            self.assertEqual(len(seen), 1)
            self.assertEqual(report['findings'], [])
            self.assertEqual(report['resolved_ips'], [])
            self.assertEqual(report['metadata_endpoints'], [])
            self.assertIn('not assessed', ' '.join(report['assessment']['coverage_gaps']))
            self.assertNotIn('127.0.0.1:9050', json.dumps(report))

    def test_socks_handshake_sends_hostname_instead_of_local_lookup(self):
        from httpcore._sync.socks_proxy import _init_socks5_connection
        class FakeStream:
            def __init__(self):
                self.writes = []
                self.replies = iter([b'\x05\x00', b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50'])
            def write(self, data):
                self.writes.append(data)
            def read(self, max_bytes):
                return next(self.replies)
        stream = FakeStream()
        with patch('socket.getaddrinfo', side_effect=AssertionError('Local DNS forbidden')):
            _init_socks5_connection(stream, host=b'example.onion', port=80)
        request = stream.writes[1]
        self.assertEqual(request[:4], b'\x05\x01\x00\x03')
        self.assertIn(b'example.onion', request)
