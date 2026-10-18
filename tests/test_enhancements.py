import argparse
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import httpx

from shamtrace.checks import (
    is_in_scope,
    normalize_in_scope_url,
    detect_shared_edge,
    redact_sensitive,
    inspect_cookies,
    inspect_cors,
    inspect_tls_connection,
    fingerprint_technologies,
)
from shamtrace.discovery import inspect_metadata
from shamtrace.external_tools import parse_ports, run_whatweb, run_nmap
from shamtrace.network import stream_within_scope, open_stream_with_retry
from shamtrace.policies import policy_findings, normalize_findings, deduplicate_findings
from shamtrace.reports import regenerate_reports_from_json
from shamtrace.scanner import scan


class EnhancementTests(unittest.TestCase):
    def test_scope_validation_and_scoped_redirects(self):
        self.assertTrue(is_in_scope("https://example.test/login", "https://example.test/"))
        self.assertTrue(
            is_in_scope("https://example.test/", "http://example.test/", allow_https_upgrade=True)
        )
        self.assertFalse(is_in_scope("https://sub.example.test/", "https://example.test/"))
        self.assertFalse(is_in_scope("https://example.test:8443/", "https://example.test/"))

        seen = []

        def handle(request):
            seen.append(str(request.url))
            if request.url.path == "/":
                return httpx.Response(302, headers={"location": "/dashboard"})
            if request.url.path == "/dashboard":
                return httpx.Response(302, headers={"location": "https://external.test/phish"})
            return httpx.Response(200)

        with httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=False) as client:
            with stream_within_scope(
                client,
                "https://example.test/",
                "https://example.test/",
                follow_scoped_redirects=True,
            ) as (resp, final_url, info):
                self.assertEqual(resp.status_code, 302)
                self.assertEqual(final_url, "https://example.test/dashboard")
                self.assertTrue(info["followed"])
                self.assertEqual(info["hops"], 1)
                self.assertEqual(info["stop_reason"], "out_of_scope_redirect_blocked")
                self.assertEqual(info["blocked_location"], "https://external.test/phish")
        self.assertEqual(seen, ["https://example.test/", "https://example.test/dashboard"])

    def test_url_normalization_preserves_meaningful_params_and_skips_destructive(self):
        norm, reason = normalize_in_scope_url(
            "https://example.test/articles?b=2&utm_source=x&a=1#sec",
            "https://example.test/",
        )
        self.assertIsNone(reason)
        self.assertEqual(norm, "https://example.test/articles?a=1&b=2")

        blocked, reason = normalize_in_scope_url(
            "https://example.test/account?action=delete",
            "https://example.test/",
        )
        self.assertIsNone(blocked)
        self.assertEqual(reason, "unsafe_or_state_changing_query")

    def test_redaction_of_tokens_jwt_and_auth_headers(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc1234567"
        raw = {
            "url": f"https://example.test/callback?token=supersecret&page=2&jwt={jwt}",
            "Authorization": "Bearer secret-bearer-token-999",
            "note": f"Header Bearer my_secret_token_12345 and {jwt}",
        }
        cleaned = redact_sensitive(raw)
        serialized = json.dumps(cleaned)
        self.assertNotIn("supersecret", serialized)
        self.assertNotIn("secret-bearer-token-999", serialized)
        self.assertNotIn("my_secret_token_12345", serialized)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", serialized)
        self.assertIn("page=2", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_cookie_prefixes_and_cors_policies(self):
        headers = httpx.Headers([
            ("set-cookie", "__Host-sess=secret; Secure; HttpOnly; Domain=example.test; Path=/"),
            ("set-cookie", "__Host-valid=secret; Secure; HttpOnly; Path=/"),
            ("access-control-allow-origin", "null"),
            ("access-control-allow-credentials", "true"),
            ("x-content-type-options", "invalid-value"),
            ("strict-transport-security", "max-age=3600"),
            ("content-security-policy", "script-src 'unsafe-inline' *"),
        ])
        cookies = inspect_cookies(headers)
        self.assertFalse(cookies[0]["prefix_valid"])
        self.assertTrue(cookies[1]["prefix_valid"])

        cors = inspect_cors(headers, "https://example.test")
        self.assertEqual(cors["state"], "permissive")
        self.assertEqual(cors["risk"], "high")

        # Public wildcard CORS without credentials must NOT produce a vulnerability finding
        pub_headers = httpx.Headers({"access-control-allow-origin": "*"})
        self.assertEqual(inspect_cors(pub_headers)["risk"], "none")
        self.assertEqual(
            policy_findings(pub_headers, {"target": "https://example.test", "cookies": [], "content": {}}),
            [],
        )

        report = {"target": "https://example.test", "cookies": cookies, "content": {"html": None}}
        findings = policy_findings(headers, report)
        ids = {f["id"] for f in findings}
        self.assertIn("cookie-prefix-violation", ids)
        self.assertIn("cors-null-origin", ids)
        self.assertIn("x-content-type-options-invalid", ids)
        self.assertIn("hsts-short-max-age", ids)
        self.assertIn("csp-unsafe-inline-script", ids)
        self.assertIn("csp-broad-script-source", ids)

    def test_tls_connection_vs_audit_scope_and_expiry_classification(self):
        ssl_mock = MagicMock()
        ssl_mock.version.return_value = "TLSv1.3"
        ssl_mock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        ssl_mock.getpeercert.return_value = {
            "subject": ((("commonName", "example.test"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notBefore": "Jan  1 00:00:00 2020 GMT",
            "notAfter": "Jan  1 00:00:00 2021 GMT",
            "subjectAltName": [("DNS", "example.test")],
        }
        tls_info = inspect_tls_connection(ssl_mock, True)
        self.assertEqual(tls_info["connection"]["audit_scope"], "single_connection_only")
        self.assertTrue(tls_info["certificate"]["days_remaining"] < 0)
        report = {
            "target": "https://example.test",
            "cookies": [],
            "certificate": tls_info["certificate"],
            "content": {"html": None},
        }
        ids = {f["id"] for f in policy_findings(httpx.Headers(), report)}
        self.assertIn("tls-certificate-expired", ids)

        # Certificate expiring in 20 days is an operational_observation with severity 'info'
        report["certificate"] = {"not_after": "Nov 14 2026 GMT", "days_remaining": 20}
        exp_findings = policy_findings(httpx.Headers(), report)
        self.assertEqual(exp_findings[0]["id"], "tls-certificate-expiring-soon")
        self.assertEqual(exp_findings[0]["severity"], "info")
        self.assertEqual(exp_findings[0]["classification"], "operational_observation")

    def test_technology_fingerprinting_merges_duplicates(self):
        headers = httpx.Headers({
            "server": "Vercel",
            "x-vercel-id": "sin1::12345",
            "cf-ray": "89abcdef-SIN",
        })
        cookies = [{"name": "PHPSESSID", "secure": True, "httponly": True, "samesite": "Lax"}]
        content = {
            "html": {
                "generator_claim": "WordPress 6.5.2",
                "scripts": ["https://example.test/wp-content/themes/app.js"],
            }
        }
        fps = fingerprint_technologies(headers, cookies, content)
        vercel_entries = [f for f in fps if f["name"].lower() == "vercel"]
        self.assertEqual(len(vercel_entries), 1)
        self.assertEqual(vercel_entries[0]["confidence"], "high")
        self.assertIn("Server header: Vercel", vercel_entries[0]["evidence"])
        self.assertIn("Vercel edge headers", vercel_entries[0]["evidence"])

    def test_finding_deduplication_preserves_distinct_items(self):
        raw = [
            {"id": "header-content-security-policy", "title": "Header CSP", "affected_url": "https://example.test/"},
            {"id": "header-content-security-policy", "title": "Header CSP", "affected_url": "https://example.test/about"},
            {"id": "cookie-flags", "title": "Cookie flags", "evidence": "Cookie a: absent secure.", "affected_url": "https://example.test/"},
            {"id": "cookie-flags", "title": "Cookie flags", "evidence": "Cookie b: absent secure.", "affected_url": "https://example.test/"},
        ]
        normalize_findings(raw, "https://example.test/")
        deduped = deduplicate_findings(raw)
        self.assertEqual(len(deduped), 3)
        self.assertEqual(deduped[0]["occurrence_count"], 2)

    def test_metadata_not_found_vs_not_checked(self):
        def handle(request):
            if request.url.path == "/robots.txt":
                return httpx.Response(404, text="Not Found")
            return httpx.Response(302, headers={"location": "/login"})

        with httpx.Client(transport=httpx.MockTransport(handle)) as client:
            res = inspect_metadata(client, "https://example.test")
        self.assertEqual(res[0]["validation"]["state"], "not_found")
        self.assertEqual(res[1]["validation"]["state"], "not_checked")

    def test_retry_on_transient_timeout(self):
        attempts = []

        def handle(request):
            attempts.append(1)
            if len(attempts) == 1:
                raise httpx.ReadTimeout("transient timeout", request=request)
            return httpx.Response(200, text="ok")

        with httpx.Client(transport=httpx.MockTransport(handle)) as client:
            with open_stream_with_retry(client, "GET", "https://example.test", retries=1) as resp:
                self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(attempts), 2)

    def test_external_tools_port_validation_and_shared_cdn_protection(self):
        self.assertEqual(parse_ports("80, 443, 8080-8082"), [80, 443, 8080, 8081, 8082])
        for invalid in ["", "0", "70000", "8085-8080", "1-200", "80;rm -rf"]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_ports(invalid)

        shared = detect_shared_edge(["216.198.79.1"], httpx.Headers({"server": "Vercel"}))
        self.assertTrue(shared["is_shared_edge"])
        skipped_cdn = run_nmap("mostu.id", "80,443", shared_edge=shared, allow_shared_ip=False)
        self.assertEqual(skipped_cdn["status"], "skipped")
        self.assertIn("--allow-shared-ip", skipped_cdn["reason"])

        with patch("shamtrace.external_tools.shutil.which", return_value="/usr/bin/nmap"), patch(
            "shamtrace.external_tools.subprocess.run"
        ) as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["nmap"],
                returncode=0,
                stdout='<nmaprun><host><ports><port protocol="tcp" portid="443">'
                '<state state="open"/><service name="https" product="nginx" version="1.24"/></port></ports></host></nmaprun>',
                stderr="",
            )
            res = run_nmap("example.test", "443", timeout=10)
            self.assertEqual(res["status"], "completed")
            self.assertEqual(res["ports"][0]["port"], 443)
            self.assertEqual(res["ports"][0]["product"], "nginx")

    def test_html_report_hud_and_report_regeneration_subcommand(self):
        real_client = httpx.Client

        def handle(request):
            return httpx.Response(
                200,
                headers={"content-type": "text/html", "server": "Apache/2.4.58"},
                text='<title>Portal</title><form method="post" action="http://example.test/login"><input name="csrf_token" type="hidden"></form>',
            )

        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "shamtrace.scanner.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("127.0.0.1", 80))],
            ), patch(
                "shamtrace.scanner.httpx.Client",
                side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw),
            ), patch("shamtrace.scanner.show_report"), patch("shamtrace.scanner.console"):
                scan(argparse.Namespace(url="https://example.test", timeout=3, output=directory))

            json_file = next(Path(directory).glob("*.json"))
            html_file = next(Path(directory).glob("*.html"))
            html_text = html_file.read_text()
            report = json.loads(json_file.read_text())

            self.assertIn("MODULE EXECUTION TELEMETRY", html_text)
            self.assertIn("SEVERITY FILTER", html_text)
            self.assertIn("Severity Rationale", html_text)
            self.assertIn("Limitations &amp; False-Positive Context", html_text)
            self.assertIn("never be interpreted as proof that the target is secure", html_text)
            self.assertEqual(html_text.count("HTTPS page declares an HTTP form action"), 1)
            self.assertEqual(report["modules"]["http"]["status"], "completed")

            # Test regenerating HTML/Markdown from JSON via CLI report subcommand
            rebuilt_dir = Path(directory) / "rebuilt"
            cmd_res = subprocess.run(
                [sys.executable, "-m", "shamtrace", "report", str(json_file), "-o", str(rebuilt_dir), "--no-color"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(cmd_res.returncode, 0)
            self.assertTrue(list(rebuilt_dir.glob("*.html")))
            self.assertTrue(list(rebuilt_dir.glob("*.md")))

    def test_live_local_http_server_integration(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class LocalHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                if self.path == "/":
                    self.send_response(302)
                    self.send_header("Location", "/app")
                    self.end_headers()
                elif self.path == "/app":
                    body = (
                        b"<!doctype html><html><head><title>Local Lab</title>"
                        b'<meta name="generator" content="WordPress 6.5.0"></head><body>'
                        b'<a href="/about?section=team">About</a>'
                        b'<form method="POST" action="/login"><input name="csrf_token" type="hidden"></form>'
                        b'<script src="/static/main.js"></script></body></html>'
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Server", "nginx/1.24.0")
                    self.send_header("Access-Control-Allow-Origin", "null")
                    self.send_header("Set-Cookie", "__Host-id=SECRET_VAL; Path=/")
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/about?section=team":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><title>About Team</title></html>")
                elif self.path == "/static/main.js":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/javascript")
                    self.end_headers()
                    self.wfile.write(b'fetch("/api/v1/status?token=leak123");')
                elif self.path == "/robots.txt":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"User-agent: *\nDisallow: /admin\n")
                else:
                    self.send_response(404)
                    self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                with patch("shamtrace.scanner.show_report"), patch("shamtrace.scanner.console"):
                    scan(
                        argparse.Namespace(
                            url=f"http://127.0.0.1:{port}/",
                            timeout=5,
                            profile="extended",
                            pages=2,
                            retries=1,
                            rate_limit=20.0,
                            concurrency=2,
                            output=directory,
                        )
                    )
                report = json.loads(next(Path(directory).glob("*.json")).read_text())
                self.assertEqual(report["http_status"], 200)
                self.assertTrue(report["redirect_info"]["followed"])
                self.assertEqual(report["final_url"], f"http://127.0.0.1:{port}/app")
                self.assertEqual(report["modules"]["crawl"]["status"], "completed")
                self.assertEqual(
                    report["pages"]["results"][0]["url"],
                    f"http://127.0.0.1:{port}/about?section=team",
                )
                self.assertEqual(report["scripts"]["results"][0]["api_path_hints"], ["/api/v1/status"])
                finding_ids = {f["id"] for f in report["findings"]}
                self.assertIn("cors-null-origin", finding_ids)
                self.assertIn("cookie-prefix-violation", finding_ids)
                self.assertNotIn("SECRET_VAL", json.dumps(report))
        finally:
            server.shutdown()
            server.server_close()

    def test_vuln_exposures_js_secrets_takeover_and_taxonomy(self):
        from shamtrace.vuln_checks import (
            inspect_exposures,
            inspect_script_vulnerabilities,
            evaluate_passive_vulnerabilities,
            enrich_finding_taxonomy,
        )

        def handle(request):
            p = request.url.path
            if request.method == "OPTIONS":
                return httpx.Response(200, headers={"Allow": "GET, POST, PUT, TRACE"})
            if p == "/.env":
                return httpx.Response(200, headers={"content-type": "text/plain"}, text="APP_KEY=base64:xyz\nDB_PASSWORD=topsecret\n")
            if p == "/.git/HEAD":
                return httpx.Response(200, headers={"content-type": "text/plain"}, text="ref: refs/heads/main\n")
            if p == "/phpinfo.php":
                return httpx.Response(200, headers={"content-type": "text/html"}, text="<html><title>404 Not Found SPA</title></html>")
            return httpx.Response(404)

        with httpx.Client(transport=httpx.MockTransport(handle)) as client:
            exp = inspect_exposures(client, "https://example.test", max_probes=5)
        self.assertEqual(exp["exposed_count"], 2)
        exp_ids = {f["id"] for f in exp["findings"]}
        self.assertIn("exposed-env-file", exp_ids)
        self.assertIn("exposed-git-metadata", exp_ids)
        self.assertIn("http-trace-enabled", exp_ids)
        self.assertIn("http-dangerous-methods", exp_ids)
        self.assertNotIn("exposed-phpinfo", exp_ids)  # SPA 404 ignored!

        js_code = (
            'const k = "AKIA1234567890ABCDEF";\n'
            'const q = new URLSearchParams(location.search).get("q");\n'
            'document.getElementById("out").innerHTML = q;\n'
            '//# sourceMappingURL=app.bundle.js.map\n'
        )
        js_vuln = inspect_script_vulnerabilities(js_code, "https://example.test/app.js")
        self.assertEqual(len(js_vuln["credential_indicators"]), 1)
        self.assertIn("REDACTED", js_vuln["credential_indicators"][0]["masked_match"])
        self.assertEqual(js_vuln["source_maps"], ["app.bundle.js.map"])
        self.assertIn("innerHTML assignment", js_vuln["dom_sinks_with_url_source"])

        mock_report = {
            "target": "https://sub.example.test",
            "final_url": "https://sub.example.test",
            "http_status": 404,
            "dns": {
                "status": "complete",
                "spf": "v=spf1 +all",
                "dmarc": None,
                "queries": [{"type": "CNAME", "records": ["unclaimed-app.herokuapp.com."]}],
            },
            "scripts": {"results": [{"url": "https://sub.example.test/app.js", "vuln_analysis": js_vuln}]},
            "content": {
                "html": {
                    "links": ["https://sub.example.test/login?redirect_uri=https://evil.test"],
                    "external_scripts_without_sri": ["https://cdn.example.com/lib.js"],
                    "form_details": [{"method": "POST", "action": "https://sub.example.test/update", "has_csrf_field": False}],
                }
            },
        }
        passive = evaluate_passive_vulnerabilities(mock_report, httpx.Headers({"server": "nginx/1.24.0"}))
        p_ids = {f["id"] for f in passive}
        self.assertTrue({
            "subdomain-takeover-candidate",
            "dns-spf-permissive-or-missing",
            "dns-dmarc-missing",
            "js-hardcoded-secret",
            "js-source-map-exposed",
            "js-dom-xss-sink",
            "open-redirect-parameter-candidate",
            "missing-sri-external-script",
            "form-missing-csrf-token",
            "server-version-banner-disclosed",
        } <= p_ids)

        enriched = enrich_finding_taxonomy(passive[0])
        self.assertIn("cwe", enriched)
        self.assertIn("owasp", enriched)
        self.assertIn("cvss_score", enriched)


if __name__ == "__main__":
    unittest.main()
