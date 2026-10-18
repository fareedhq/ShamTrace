import unittest
from unittest.mock import patch, MagicMock
import httpx
import dns.resolver
import dns.exception
from shamtrace.dns_checks import inspect_dns
from shamtrace.discovery import inspect_metadata
from shamtrace.cli import build_parser


class ExtendedTests(unittest.TestCase):
    def test_ip_literal_skips_dns(self):
        with patch('shamtrace.dns_checks.dns.resolver.Resolver') as resolver:
            self.assertEqual(inspect_dns('::1')['status'], 'skipped')
            resolver.assert_not_called()

    def test_all_types_and_dmarc_have_ttl_and_evidence(self):
        answer = MagicMock()
        answer.__iter__.return_value = iter([])
        record = MagicMock()
        record.to_text.return_value = 'test-record'
        answer.__iter__.side_effect = lambda: iter([record])
        answer.rrset.ttl = 300
        answer.canonical_name.to_text.return_value = 'example.test.'
        with patch('shamtrace.dns_checks.dns.resolver.Resolver') as resolver:
            resolver.return_value.resolve.return_value = answer
            report = inspect_dns('example.test', 2)
        self.assertEqual(len(report['queries']), 9)
        self.assertEqual({q['type'] for q in report['queries']},
                         {'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'})
        self.assertTrue(all(q['ttl'] == 300 for q in report['queries']))
        self.assertEqual(report['queries'][-1]['name'], '_dmarc.example.test')

    def test_dns_errors_remain_distinct(self):
        for error, state in [(dns.resolver.NoAnswer(), 'no_answer'),
                             (dns.resolver.NXDOMAIN(), 'nxdomain'),
                             (dns.exception.Timeout(), 'timeout'),
                             (dns.resolver.NoNameservers(), 'error')]:
            with self.subTest(state=state), patch('shamtrace.dns_checks.dns.resolver.Resolver') as resolver:
                resolver.return_value.resolve.side_effect = error
                self.assertTrue(all(q['status'] == state for q in inspect_dns('example.test')['queries']))

    def test_metadata_stays_on_origin_and_never_follows_redirect(self):
        seen = []
        def handle(request):
            seen.append(str(request.url))
            if request.url.path == '/sitemap.xml':
                raise httpx.ReadTimeout('timeout', request=request)
            return httpx.Response(302, headers={'location': 'https://external.test/'})
        with httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=False) as client:
            results = inspect_metadata(client, 'https://example.test:8443/path?secret=123')
        self.assertEqual(len(seen), 3)
        self.assertTrue(all(url.startswith('https://example.test:8443/') for url in seen))
        self.assertTrue(all('secret' not in url for url in seen))
        self.assertEqual(results[1]['status'], 'error')
        self.assertEqual(results[2]['http_status'], 302)

    def test_profiles(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(['scan', 'example.test']).profile, 'extended')
        self.assertEqual(parser.parse_args(['scan', 'example.test', '--profile', 'extended']).profile, 'extended')
