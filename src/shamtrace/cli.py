import argparse
import sys
import socket
import httpx
from rich.text import Text
from . import __version__ as VERSION
from .display import banner, console
from .reports import regenerate_reports_from_json
from .scanner import scan


class CommandParser(argparse.ArgumentParser):
    def parse_args(self, args=None, namespace=None):
        values = list(sys.argv[1:] if args is None else args)
        # Allow top-level flags like --no-color before implicit scan target
        non_flag = [v for v in values if v != "--no-color"]
        if non_flag and non_flag[0] not in {"scan", "report", "-h", "--help", "--version"}:
            idx = values.index(non_flag[0])
            values.insert(idx, "scan")
        parsed = super().parse_args(values, namespace)
        if getattr(parsed, "tor", False):
            if parsed.proxy:
                self.error("Use either --tor or --proxy, not both.")
            parsed.proxy = "socks5://127.0.0.1:9050"
        return parsed


class HelpFormatter(argparse.RawDescriptionHelpFormatter):
    pass


def build_parser():
    parser = CommandParser(
        prog="shamtrace",
        description="ShamTrace — evidence-first web security configuration and surface assessment CLI.",
        formatter_class=HelpFormatter,
        epilog="""Examples:
  shamtrace your-site.example
  shamtrace scan http://127.0.0.1:8000 --profile basic
  shamtrace scan your-site.example --pages 5 --rate-limit 2 --retries 1
  shamtrace scan your-site.example --whatweb --nmap-ports 80,443,8080 -o reports
  shamtrace report results/shamtrace-20261018T120000000000Z.json

Scope & Boundaries:
  basic: one URL. extended: typed DNS, three public metadata paths, and up to three same-origin scripts.
  Redirects are followed only if they remain strictly within the authorized target scope.
  Port scans on shared CDN/cloud edge IPs are blocked unless --allow-shared-ip is explicitly supplied.
  Use only on systems you own or have explicit permission to assess.
""",
    )
    parser.add_argument("--version", action="version", version=f"ShamTrace {VERSION}")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output in the terminal.")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan_parser = commands.add_parser(
        "scan",
        help="Inspect DNS, HTTP headers, cookies, CORS, TLS, in-scope links/forms/scripts, and optional tools.",
        description="Inspect an authorized target and export offline HTML, Markdown, and JSON evidence.",
        formatter_class=HelpFormatter,
        epilog="""Examples:
  shamtrace your-site.example
  shamtrace scan your-site.example -o results -t 15 --pages 3
  shamtrace scan your-site.example --whatweb --nmap-ports 80,443
""",
    )
    scan_parser.add_argument("url", help="HTTP/HTTPS URL; defaults to HTTPS.")
    scan_parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=15,
        metavar="SECONDS",
        help="Network operation timeout in seconds (1..120, default: 15).",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        default="results",
        metavar="DIR",
        help="Report directory (default: results).",
    )
    scan_parser.add_argument(
        "--profile",
        choices=("basic", "extended"),
        default="extended",
        help="Default: extended. basic: one HTTP response; extended: typed DNS plus three metadata URLs and up to three same-origin scripts.",
    )
    scan_parser.add_argument(
        "--no-follow-redirects",
        action="store_true",
        help="Do not follow HTTP 3xx redirects even when they stay within the target scope.",
    )
    scan_parser.add_argument(
        "--pages",
        type=int,
        default=1,
        metavar="1..10",
        help="Maximum HTML pages including the target; same-origin link discovery, default 1.",
    )
    scan_parser.add_argument(
        "--retries",
        type=int,
        default=0,
        metavar="0..3",
        help="Bounded retry count for transient network timeouts/errors (default: 0).",
    )
    scan_parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="REQ_S",
        help="Maximum HTTP requests per second (0 = unthrottled, default: 0).",
    )
    scan_parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        metavar="1..16",
        help="Maximum concurrent workers for DNS queries (default: 4).",
    )
    scan_parser.add_argument(
        "--max-requests",
        type=int,
        default=25,
        metavar="1..100",
        help="Maximum target HTTP requests across the scan (default: 25).",
    )
    scan_parser.add_argument(
        "--max-duration",
        type=float,
        default=180.0,
        metavar="SECONDS",
        help="Maximum total scan duration in seconds before saving partial results (default: 180).",
    )
    scan_parser.add_argument(
        "--cve",
        action="store_true",
        help="Query OSV for detected npm package versions (sends package names/versions to OSV via the selected route).",
    )
    scan_parser.add_argument(
        "--whatweb",
        action="store_true",
        help="Run optional WhatWeb passive fingerprinting (aggression 1; skipped when proxy/Tor is active).",
    )
    scan_parser.add_argument(
        "--nmap-ports",
        metavar="PORTS",
        help="Run optional Nmap service scan on user-specified in-scope ports (e.g., 80,443,8080-8085; max 100 ports).",
    )
    scan_parser.add_argument(
        "--allow-shared-ip",
        action="store_true",
        help="Explicitly confirm network scope to allow Nmap port scanning even if target resolves to a shared CDN/edge IP.",
    )
    scan_parser.add_argument(
        "--tor",
        action="store_true",
        help="Use an existing Tor SOCKS service at 127.0.0.1:9050.",
    )
    scan_parser.add_argument(
        "--proxy",
        metavar="SOCKS_URL",
        help="SOCKS proxy; required for .onion. Local target DNS and external tools are disabled.",
    )
    scan_parser.add_argument(
        "--require-proxy",
        action="store_true",
        help="Fail before any network activity unless --tor or --proxy is configured.",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output in the terminal.",
    )
    scan_parser.add_argument(
        "--authorized",
        action="store_true",
        help="Explicitly confirm authorization to assess the target scope (optional flag).",
    )
    scan_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed evidence tables and recommendations in the terminal (and still save reports).",
    )
    scan_parser.add_argument(
        "-T",
        "--terminal",
        action="store_true",
        help="Terminal-only mode: display full detailed evidence tables in the terminal without saving report files.",
    )
    scan_parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not write JSON, Markdown, or HTML report files to disk.",
    )
    scan_parser.add_argument(
        "--vuln-scan",
        dest="vuln_scan",
        action="store_true",
        default=True,
        help="Run safe active exposure and HTTP method probes in extended profile (default: enabled).",
    )
    scan_parser.add_argument(
        "--no-vuln-scan",
        dest="vuln_scan",
        action="store_false",
        help="Disable active sensitive path exposure probes and rely only on passive inspection.",
    )

    report_parser = commands.add_parser(
        "report",
        help="View a saved JSON report in the terminal or regenerate offline HTML and Markdown reports.",
        description="View a saved ShamTrace JSON file in the terminal (--terminal) or rebuild HTML and Markdown reports without rescanning.",
        formatter_class=HelpFormatter,
    )
    report_parser.add_argument("json_file", help="Path to an existing ShamTrace .json report.")
    report_parser.add_argument(
        "-o",
        "--output",
        default=None,
        metavar="DIR",
        help="Optional output directory (defaults to updating .html and .md next to json_file).",
    )
    report_parser.add_argument(
        "-T",
        "--terminal",
        action="store_true",
        help="Display the full report directly in the terminal instead of regenerating files.",
    )
    report_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Also print the full report in the terminal when regenerating files.",
    )
    report_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output in the terminal.",
    )

    return parser


def main():
    if "--no-color" in sys.argv:
        console.no_color = True
    if "--help" in sys.argv or "-h" in sys.argv or len(sys.argv) == 1:
        banner()
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        return

    args = parser.parse_args()
    if getattr(args, "no_color", False):
        console.no_color = True
    banner()
    try:
        if args.command == "report":
            import json
            from pathlib import Path
            from .display import show_report

            if getattr(args, "terminal", False):
                report_data = json.loads(Path(args.json_file).read_text(encoding="utf-8"))
                show_report(report_data, verbose=True)
                return
            html_path, md_path = regenerate_reports_from_json(args.json_file, args.output)
            if getattr(args, "verbose", False):
                report_data = json.loads(Path(args.json_file).read_text(encoding="utf-8"))
                show_report(report_data, verbose=True)
            console.print("Rebuilt reports from JSON evidence:", style="bold green")
            console.print(Text(f"Markdown  {md_path}"))
            console.print(Text(f"HTML      {html_path}"))
            return
        scan(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled cleanly by user (SIGINT).[/yellow]")
        raise SystemExit(130)
    except socket.gaierror:
        console.print(
            Text(
                f"DNS lookup failed for {args.url!r}. Check the hostname and network/DNS connection.",
                style="bold red",
            )
        )
        console.print(
            "[dim]Replace example domains with your actual authorized target. For .onion, use --tor with Tor running.[/dim]"
        )
        raise SystemExit(1)
    except httpx.ProxyError:
        console.print(
            "[bold red]SOCKS proxy connection failed.[/bold red] Check the proxy address and that the service is running."
        )
        raise SystemExit(1)
    except httpx.ConnectError:
        console.print(
            "[bold red]Connection failed.[/bold red] Check hostname, port, TLS certificate, and proxy availability."
        )
        raise SystemExit(1)
    except (ValueError, OSError, httpx.HTTPError) as error:
        console.print(Text(f"Scan failed: {error}", style="bold red"))
        raise SystemExit(1)
