import socket
import unittest
from unittest.mock import patch
from rich.console import Console
from io import StringIO
from shamtrace.cli import build_parser, main
from shamtrace.display import banner


class ShortcutTests(unittest.TestCase):
    def test_direct_target_defaults_to_extended(self):
        args = build_parser().parse_args(['example.test', '-v'])
        self.assertEqual(args.command, 'scan')
        self.assertEqual(args.profile, 'extended')
        self.assertTrue(args.verbose)

    def test_tor_shortcut(self):
        args = build_parser().parse_args(['http://example.onion', '--tor'])
        self.assertEqual(args.proxy, 'socks5://127.0.0.1:9050')

    def test_tor_proxy_conflict(self):
        with patch('sys.stderr', new=StringIO()), self.assertRaises(SystemExit) as error:
            build_parser().parse_args(['example.test', '--tor', '--proxy', 'socks5://localhost:9150'])
        self.assertEqual(error.exception.code, 2)

    def test_dns_failure_message_and_exit(self):
        output = StringIO()
        with patch('sys.argv', ['shamtrace', 'example.invalid']), \
             patch('shamtrace.cli.scan', side_effect=socket.gaierror(-2, 'Name or service not known')), \
             patch('shamtrace.cli.banner'), \
             patch('shamtrace.cli.console', Console(file=output, width=100)):
            with self.assertRaises(SystemExit) as error:
                main()
        self.assertEqual(error.exception.code, 1)
        self.assertIn('DNS lookup failed', output.getvalue())
        self.assertNotIn('[Errno', output.getvalue())

    def test_banner_on_narrow_terminal(self):
        output = StringIO()
        with patch('shamtrace.display.console', Console(file=output, width=35)):
            banner()
        self.assertIn('SHAMTRACE', output.getvalue())
