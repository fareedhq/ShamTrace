"""Safe, non-intrusive vulnerability, exposure, secret-leak, and posture auditing modules."""
import re
from urllib.parse import urlsplit, urlunsplit, parse_qs
import httpx
from .checks import redact_sensitive
from .content import inspect_document
from .network import open_stream_with_retry


# CWE, OWASP Top 10 (2021), and CVSS v3.1 mapping for all ShamTrace finding IDs
FINDING_TAXONOMY = {
    "exposed-env-file": ("CWE-538", "A05:2021-Security Misconfiguration", 7.5),
    "exposed-git-metadata": ("CWE-538", "A05:2021-Security Misconfiguration", 7.5),
    "exposed-laravel-ignition": ("CWE-489", "A05:2021-Security Misconfiguration", 8.6),
    "exposed-spring-actuator": ("CWE-200", "A05:2021-Security Misconfiguration", 7.5),
    "exposed-phpinfo": ("CWE-200", "A05:2021-Security Misconfiguration", 5.3),
    "exposed-server-status": ("CWE-200", "A05:2021-Security Misconfiguration", 5.3),
    "exposed-wp-users-api": ("CWE-200", "A01:2021-Broken Access Control", 5.3),
    "exposed-docker-compose": ("CWE-538", "A05:2021-Security Misconfiguration", 6.5),
    "exposed-ds-store": ("CWE-538", "A05:2021-Security Misconfiguration", 3.7),
    "exposed-openapi-spec": ("CWE-200", "A05:2021-Security Misconfiguration", 3.7),
    "exposed-graphql-endpoint": ("CWE-200", "A05:2021-Security Misconfiguration", 3.7),
    "js-hardcoded-secret": ("CWE-798", "A07:2021-Identification and Authentication Failures", 7.5),
    "js-source-map-exposed": ("CWE-540", "A05:2021-Security Misconfiguration", 3.7),
    "js-dom-xss-sink": ("CWE-79", "A03:2021-Injection", 4.3),
    "subdomain-takeover-candidate": ("CWE-350", "A05:2021-Security Misconfiguration", 8.2),
    "dangling-cname-cloud-target": ("CWE-350", "A05:2021-Security Misconfiguration", 4.8),
    "http-dangerous-methods": ("CWE-749", "A05:2021-Security Misconfiguration", 5.3),
    "http-trace-enabled": ("CWE-693", "A05:2021-Security Misconfiguration", 4.3),
    "open-redirect-parameter-candidate": ("CWE-601", "A01:2021-Broken Access Control", 4.3),
    "ssrf-parameter-candidate": ("CWE-918", "A10:2021-Server-Side Request Forgery", 4.3),
    "missing-sri-external-script": ("CWE-829", "A08:2021-Software and Data Integrity Failures", 4.0),
    "form-missing-csrf-token": ("CWE-352", "A01:2021-Broken Access Control", 4.3),
    "form-http-downgrade": ("CWE-319", "A02:2021-Cryptographic Failures", 6.5),
    "unencrypted-http": ("CWE-319", "A02:2021-Cryptographic Failures", 5.3),
    "mixed-content-references": ("CWE-319", "A02:2021-Cryptographic Failures", 4.3),
    "tls-certificate-expired": ("CWE-298", "A02:2021-Cryptographic Failures", 7.4),
    "tls-certificate-expiring-soon": ("CWE-298", "A02:2021-Cryptographic Failures", 0.0),
    "cors-wildcard-with-credentials": ("CWE-942", "A05:2021-Security Misconfiguration", 6.5),
    "cors-null-origin": ("CWE-942", "A05:2021-Security Misconfiguration", 5.3),
    "cors-missing-vary-origin": ("CWE-942", "A05:2021-Security Misconfiguration", 3.1),
    "cookie-flags": ("CWE-614", "A05:2021-Security Misconfiguration", 3.7),
    "cookie-samesite-none-without-secure": ("CWE-614", "A05:2021-Security Misconfiguration", 3.7),
    "cookie-prefix-violation": ("CWE-614", "A05:2021-Security Misconfiguration", 3.7),
    "hsts-invalid-max-age": ("CWE-523", "A02:2021-Cryptographic Failures", 3.7),
    "hsts-disabled-or-ambiguous": ("CWE-523", "A02:2021-Cryptographic Failures", 3.7),
    "hsts-short-max-age": ("CWE-523", "A02:2021-Cryptographic Failures", 0.0),
    "header-strict-transport-security": ("CWE-523", "A05:2021-Security Misconfiguration", 0.0),
    "header-content-security-policy": ("CWE-693", "A05:2021-Security Misconfiguration", 0.0),
    "header-x-content-type-options": ("CWE-693", "A05:2021-Security Misconfiguration", 0.0),
    "header-referrer-policy": ("CWE-200", "A05:2021-Security Misconfiguration", 0.0),
    "header-permissions-policy": ("CWE-693", "A05:2021-Security Misconfiguration", 0.0),
    "framing-policy-not-observed": ("CWE-1021", "A05:2021-Security Misconfiguration", 3.1),
    "csp-unsafe-eval": ("CWE-693", "A05:2021-Security Misconfiguration", 3.1),
    "csp-unsafe-inline-script": ("CWE-693", "A05:2021-Security Misconfiguration", 3.1),
    "csp-broad-script-source": ("CWE-693", "A05:2021-Security Misconfiguration", 3.1),
    "dns-spf-permissive-or-missing": ("CWE-290", "A05:2021-Security Misconfiguration", 3.7),
    "dns-dmarc-missing": ("CWE-290", "A05:2021-Security Misconfiguration", 3.1),
    "server-version-banner-disclosed": ("CWE-200", "A05:2021-Security Misconfiguration", 2.0),
}


# Safe sensitive path probes with strict structural signature validators to prevent false positives on custom 404/SPA pages
SENSITIVE_PROBES = [
    {
        "path": "/.env",
        "finding_id": "exposed-env-file",
        "title": "Environment configuration file (/.env) is publicly accessible",
        "severity": "high",
        "classification": "verified_finding",
        "remediation": "Deny public web access to dotfiles (/.env) at the web server / reverse proxy layer and rotate any exposed credentials immediately.",
        "rationale": "Publicly accessible .env files frequently disclose database credentials, API keys, and application encryption secrets.",
        "validator": lambda text, mime: (
            "html" not in mime
            and not text.lstrip().startswith(("<", "{"))
            and bool(
                re.search(
                    r"(?m)^(?:APP_KEY|APP_ENV|DB_PASSWORD|DB_HOST|AWS_ACCESS_KEY_ID|REDIS_HOST|SECRET_KEY|DATABASE_URL)\s*=",
                    text,
                )
            )
        ),
    },
    {
        "path": "/.git/HEAD",
        "finding_id": "exposed-git-metadata",
        "title": "Exposed Git repository metadata (/.git/HEAD)",
        "severity": "high",
        "classification": "verified_finding",
        "remediation": "Block access to /.git/ directories in your web server configuration and remove .git metadata from production web roots.",
        "rationale": "Exposed .git directories allow attackers to reconstruct application source code, commit history, and hardcoded secrets.",
        "validator": lambda text, mime: (
            "html" not in mime
            and len(text) < 512
            and bool(re.match(r"^(?:ref:\s+refs/heads/\S+|[0-9a-f]{40})\s*$", text.strip()))
        ),
    },
    {
        "path": "/_ignition/health-check",
        "finding_id": "exposed-laravel-ignition",
        "title": "Laravel Ignition debug endpoint is publicly accessible",
        "severity": "high",
        "classification": "verified_finding",
        "remediation": "Set APP_DEBUG=false in production and restrict or upgrade facade/ignition to patched versions (CVE-2021-3129).",
        "rationale": "Exposed Ignition endpoints indicate active debug mode in production and have historically been associated with unauthenticated RCE (CVE-2021-3129).",
        "validator": lambda text, mime: (
            "json" in mime and '"can_execute_commands"' in text
        ),
    },
    {
        "path": "/actuator/health",
        "finding_id": "exposed-spring-actuator",
        "title": "Spring Boot Actuator telemetry endpoint is publicly accessible",
        "severity": "low",
        "classification": "configuration_observation",
        "remediation": "Restrict Spring Boot Actuator endpoints (/actuator/*) to internal management networks or require authentication.",
        "rationale": "Public actuator endpoints expose service health state and indicate whether sibling endpoints (/actuator/env, /actuator/heapdump) may be reachable.",
        "validator": lambda text, mime: (
            ("json" in mime or "actuator" in mime)
            and bool(re.search(r'^\s*\{\s*"status"\s*:\s*"(?:UP|DOWN|OUT_OF_SERVICE)"', text))
        ),
    },
    {
        "path": "/phpinfo.php",
        "finding_id": "exposed-phpinfo",
        "title": "PHP runtime configuration page (/phpinfo.php) is publicly accessible",
        "severity": "medium",
        "classification": "verified_finding",
        "remediation": "Remove phpinfo.php diagnostic scripts from production servers.",
        "rationale": "phpinfo() discloses internal filesystem paths, environment variables, loaded extensions, and PHP configuration directives.",
        "validator": lambda text, mime: (
            "<title>phpinfo()</title>" in text.lower()
            or ("php version" in text.lower() and "configuration file (php.ini) path" in text.lower())
        ),
    },
    {
        "path": "/wp-json/wp/v2/users",
        "finding_id": "exposed-wp-users-api",
        "title": "WordPress REST API discloses user account slugs (/wp-json/wp/v2/users)",
        "severity": "medium",
        "classification": "verified_finding",
        "remediation": "Restrict unauthenticated access to /wp-json/wp/v2/users via a security filter or WAF rule if author enumeration is not required.",
        "rationale": "Unauthenticated access to the WordPress users REST endpoint allows enumeration of valid account usernames/slugs.",
        "validator": lambda text, mime: (
            "json" in mime
            and text.lstrip().startswith("[")
            and '"slug":' in text
            and '"avatar_urls":' in text
        ),
    },
    {
        "path": "/swagger.json",
        "finding_id": "exposed-openapi-spec",
        "title": "Publicly accessible OpenAPI / Swagger specification (/swagger.json)",
        "severity": "low",
        "classification": "configuration_observation",
        "remediation": "Verify whether API specification files are intended to be public; restrict access in production if the API is internal.",
        "rationale": "OpenAPI/Swagger schemas enumerate all backend API routes, parameters, and authentication schemes.",
        "validator": lambda text, mime: (
            "json" in mime
            and text.lstrip().startswith("{")
            and ('"swagger":' in text or '"openapi":' in text)
            and '"paths":' in text
        ),
    },
    {
        "path": "/server-status",
        "finding_id": "exposed-server-status",
        "title": "Apache mod_status page (/server-status) is publicly accessible",
        "severity": "medium",
        "classification": "verified_finding",
        "remediation": "Restrict /server-status in Apache configuration using 'Require ip' or 'Require local'.",
        "rationale": "Apache server-status discloses active client IP addresses, requested URLs, and server worker telemetry.",
        "validator": lambda text, mime: (
            "apache server status for" in text.lower() and "server uptime" in text.lower()
        ),
    },
    {
        "path": "/.DS_Store",
        "finding_id": "exposed-ds-store",
        "title": "macOS directory metadata file (/.DS_Store) is publicly accessible",
        "severity": "low",
        "classification": "verified_finding",
        "remediation": "Remove .DS_Store files from deployment artifacts and block dotfile access at the web server.",
        "rationale": ".DS_Store files disclose filenames and directory structures within the web root.",
        "validator": lambda text, mime: (
            "html" not in mime and text.startswith("\x00\x00\x00\x01Bud1") or "Bud1" in text[:16]
        ),
    },
    {
        "path": "/docker-compose.yml",
        "finding_id": "exposed-docker-compose",
        "title": "Docker Compose orchestration file (/docker-compose.yml) is publicly accessible",
        "severity": "medium",
        "classification": "verified_finding",
        "remediation": "Remove docker-compose.yml and infrastructure manifests from the public web root.",
        "rationale": "Exposed Docker Compose files reveal internal service topologies, image versions, volume mounts, and environment variables.",
        "validator": lambda text, mime: (
            "html" not in mime
            and not text.lstrip().startswith("<")
            and bool(re.search(r"(?m)^services:\s*$", text))
            and bool(re.search(r"(?m)^\s+image:\s+\S+", text))
        ),
    },
]


# High-confidence secret patterns for passive JavaScript & HTML inspection
SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "high"),
    ("Google Cloud / Firebase API Key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), "medium"),
    ("Stripe Live Secret Key", re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"), "high"),
    ("GitHub Personal Access Token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{50,})\b"), "high"),
    ("GitLab Personal Access Token", re.compile(r"\b(glpat-[0-9A-Za-z_-]{20,})\b"), "high"),
    ("Slack Token / Webhook", re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}|https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+)\b"), "high"),
    ("Private Cryptographic Key Block", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"), "high"),
]

# Cloud CNAME fingerprints associated with Subdomain Takeover when unclaimed
TAKEOVER_PROVIDERS = [
    ("GitHub Pages", (".github.io",), ("There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file")),
    ("Heroku", (".herokuapp.com", ".herokussl.com", ".herokudns.com"), ("No such app", "herokucdn.com/error-pages/no-such-app.html")),
    ("AWS S3", (".s3.amazonaws.com", ".s3-website"), ("NoSuchBucket", "The specified bucket does not exist")),
    ("Vercel", (".vercel-dns.com", ".now.sh", ".vercel.app"), ("DEPLOYMENT_NOT_FOUND", "The deployment could not be found on Vercel")),
    ("Netlify", (".netlify.app", ".netlify.com"), ("Not Found - Request ID:",)),
    ("Azure App Service / Cloud", (".azurewebsites.net", ".cloudapp.net", ".azureedge.net", ".trafficmanager.net"), ("404 Web Site not found", "Error 404 - Web app not found")),
    ("Fastly", (".fastly.net",), ("Fastly error: unknown domain",)),
    ("Shopify", (".myshopify.com",), ("Sorry, this shop is currently unavailable",)),
    ("Pantheon", (".pantheonsite.io",), ("404 error unknown site!",)),
    ("Surge.sh", (".surge.sh",), ("project not found",)),
    ("Fly.io", (".fly.dev",), ("404 Not Found",)),
    ("Render", (".onrender.com",), ("Not Found",)),
]

OPEN_REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "return", "return_to", "returnto",
    "returnurl", "return_url", "next", "url", "target", "dest", "destination",
    "goto", "continue", "out", "view", "forward", "callback_url",
}

SSRF_CANDIDATE_PARAMS = {
    "uri", "path", "file", "document", "folder", "root", "pg", "pdf", "template",
    "php_path", "doc", "page_url", "webhook", "fetch", "load", "proxy", "endpoint",
}


def _mask_secret(val):
    s = str(val)
    if len(s) <= 10:
        return s[:3] + "***[REDACTED]"
    return f"{s[:6]}...[REDACTED]...{s[-3:]}"


def inspect_script_vulnerabilities(text, script_url):
    """Passively scan an inspected JS bundle for leaked credentials, source maps, and DOM XSS sink patterns."""
    creds_found = []
    for label, pattern, sev in SECRET_PATTERNS:
        for match in pattern.findall(text):
            masked = _mask_secret(match)
            creds_found.append({"type": label, "masked_match": masked, "severity": sev})

    source_maps = []
    for sm in re.findall(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", text):
        if not sm.startswith("data:"):
            source_maps.append(sm[:160])

    dom_sinks = []
    has_source = bool(re.search(r"\b(?:location\.(?:search|hash|href)|document\.URL|URLSearchParams)\b", text))
    if has_source:
        for sink_name, sink_re in [
            ("innerHTML assignment", r"\.innerHTML\s*="),
            ("outerHTML assignment", r"\.outerHTML\s*="),
            ("document.write()", r"\bdocument\.write(?:ln)?\s*\("),
            ("eval()", r"\beval\s*\("),
        ]:
            if re.search(sink_re, text):
                dom_sinks.append(sink_name)

    return {
        "credential_indicators": creds_found[:10],
        "source_maps": sorted(set(source_maps))[:5],
        "dom_sinks_with_url_source": dom_sinks,
        "script_url": redact_sensitive(script_url),
    }


def inspect_exposures(
    client,
    target,
    baseline_hash=None,
    max_probes=10,
    retries=0,
    rate_limiter=None,
    deadline=None,
    time_fn=None,
):
    """Safely check sensitive configuration and diagnostic paths with strict anti-false-positive validation."""
    parsed = urlsplit(target)
    results = []
    findings = []

    for probe in SENSITIVE_PROBES[:max_probes]:
        if deadline and time_fn and time_fn() >= deadline:
            break
        url = urlunsplit((parsed.scheme, parsed.netloc, probe["path"], "", ""))
        entry = {
            "path": probe["path"],
            "url": url,
            "http_status": None,
            "state": "not_checked",
        }
        try:
            with open_stream_with_retry(
                client, "GET", url, retries=retries, rate_limiter=rate_limiter
            ) as response:
                content = inspect_document(response, url, limit=32 * 1024, include_text=True)
                text = content.pop("_text", "")
                mime = (content.get("content_type") or "").split(";")[0].strip().lower()
                entry["http_status"] = response.status_code

                if response.status_code == 200:
                    if baseline_hash and content.get("sha256_inspected_bytes") == baseline_hash:
                        entry["state"] = "fallback_ignored"
                        entry["reason"] = "Identical to index page (SPA fallback)."
                    elif probe["validator"](text, mime):
                        entry["state"] = "exposed"
                        entry["reason"] = "Verified structural signature match on HTTP 200."
                        snippet = redact_sensitive(text[:180].replace("\n", " ").strip())
                        findings.append({
                            "id": probe["finding_id"],
                            "title": probe["title"],
                            "severity": probe["severity"],
                            "classification": probe["classification"],
                            "confidence": "high",
                            "category": "exposure",
                            "affected_url": url,
                            "evidence": {
                                "url": url,
                                "http_status": 200,
                                "content_type": mime,
                                "verified_signature_preview": snippet[:120] + ("..." if len(snippet) > 120 else ""),
                            },
                            "severity_rationale": probe["rationale"],
                            "limitations": "Verified via non-destructive GET signature matching; sensitive values are redacted.",
                            "recommendation": probe["remediation"],
                            "remediation": probe["remediation"],
                        })
                    else:
                        entry["state"] = "soft_404_or_mismatch"
                        entry["reason"] = "HTTP 200 returned, but content did not match file signature (custom 404/fallback)."
                elif response.status_code in {401, 403}:
                    entry["state"] = "restricted"
                    entry["reason"] = f"HTTP {response.status_code} (access restricted)."
                elif response.status_code in {404, 410}:
                    entry["state"] = "not_found"
                    entry["reason"] = f"HTTP {response.status_code} (not present)."
                else:
                    entry["state"] = f"http_{response.status_code}"
                    entry["reason"] = f"HTTP {response.status_code} returned."
        except httpx.HTTPError as err:
            entry["state"] = "error"
            entry["reason"] = str(err)
        results.append(entry)

    # Safe HTTP OPTIONS check on the target origin to detect dangerous HTTP methods
    methods_info = {"checked": False, "allowed_methods": [], "dangerous_methods": []}
    if not (deadline and time_fn and time_fn() >= deadline):
        try:
            with open_stream_with_retry(
                client, "OPTIONS", target, retries=retries, rate_limiter=rate_limiter
            ) as opt_resp:
                allow_hdr = opt_resp.headers.get("allow") or opt_resp.headers.get("access-control-allow-methods") or ""
                allowed = [m.strip().upper() for m in allow_hdr.split(",") if m.strip()]
                dangerous = [m for m in allowed if m in {"PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "PATCH"}]
                methods_info = {
                    "checked": True,
                    "http_status": opt_resp.status_code,
                    "allowed_methods": allowed,
                    "dangerous_methods": dangerous,
                }
                if "TRACE" in dangerous:
                    findings.append({
                        "id": "http-trace-enabled",
                        "title": "HTTP TRACE method is advertised as enabled",
                        "severity": "low",
                        "classification": "configuration_observation",
                        "confidence": "medium",
                        "category": "configuration",
                        "affected_url": target,
                        "evidence": {"allow": allow_hdr, "http_status": opt_resp.status_code},
                        "severity_rationale": "HTTP TRACE echoes client requests and is associated with Cross-Site Tracing (XST) in legacy environments.",
                        "limitations": "Observed via OPTIONS Allow header; active TRACE reflection was not executed.",
                        "recommendation": "Disable the TRACE method in your web server configuration (e.g., TraceEnable Off in Apache).",
                        "remediation": "Disable the TRACE method in your web server configuration (e.g., TraceEnable Off in Apache).",
                    })
                if any(m in dangerous for m in ("PUT", "DELETE", "PROPFIND")):
                    findings.append({
                        "id": "http-dangerous-methods",
                        "title": "State-modifying HTTP / WebDAV methods advertised in Allow header",
                        "severity": "low",
                        "classification": "configuration_observation",
                        "confidence": "medium",
                        "category": "configuration",
                        "affected_url": target,
                        "evidence": {"allow": allow_hdr, "dangerous_methods": dangerous},
                        "severity_rationale": "Advertising PUT, DELETE, or PROPFIND on a web root may indicate overly permissive method handling if not protected by authentication.",
                        "limitations": "Advertised in OPTIONS response headers only; no destructive PUT/DELETE requests were sent.",
                        "recommendation": "Ensure PUT, DELETE, and WebDAV methods are disabled on public static routes or strictly require authentication.",
                        "remediation": "Ensure PUT, DELETE, and WebDAV methods are disabled on public static routes or strictly require authentication.",
                    })
        except httpx.HTTPError:
            pass

    return {
        "status": "completed",
        "probes_checked": len(results),
        "exposed_count": sum(1 for r in results if r["state"] == "exposed"),
        "http_methods": methods_info,
        "results": results,
        "findings": findings,
    }


def evaluate_passive_vulnerabilities(report, headers):
    """Run passive vulnerability, takeover, secret-leak, parameter-surface, and DNS posture checks on collected evidence."""
    findings = []
    target = report.get("final_url") or report.get("target", "")
    https = urlsplit(target).scheme == "https"

    # 1. Subdomain Takeover & Dangling CNAME Check
    dns_queries = (report.get("dns") or {}).get("queries") or []
    cname_records = []
    for q in dns_queries:
        if q.get("type") == "CNAME" and q.get("records"):
            cname_records.extend(r.rstrip(".").lower() for r in q["records"])

    for cname in cname_records:
        for provider, suffixes, fingerprints in TAKEOVER_PROVIDERS:
            if any(cname.endswith(sfx) for sfx in suffixes):
                http_status = report.get("http_status")
                if http_status == 404:
                    findings.append({
                        "id": "subdomain-takeover-candidate",
                        "title": f"Potential Subdomain Takeover via dangling {provider} CNAME ({cname})",
                        "severity": "high",
                        "classification": "vulnerability_candidate",
                        "confidence": "medium",
                        "category": "dns_security",
                        "affected_url": target,
                        "evidence": {"cname": cname, "provider": provider, "http_status": http_status},
                        "severity_rationale": f"Domain CNAME points to {provider} ({cname}) and returned HTTP 404, which is a strong indicator of an unclaimed cloud resource.",
                        "limitations": "Requires manual verification of whether the external cloud project/bucket is unclaimed.",
                        "recommendation": f"Remove the dangling CNAME record ({cname}) from DNS or claim the corresponding {provider} resource immediately.",
                        "remediation": f"Remove the dangling CNAME record ({cname}) from DNS or claim the corresponding {provider} resource immediately.",
                    })
                else:
                    findings.append({
                        "id": "dangling-cname-cloud-target",
                        "title": f"External cloud CNAME delegation observed ({provider}: {cname})",
                        "severity": "info",
                        "classification": "configuration_observation",
                        "confidence": "high",
                        "category": "dns_security",
                        "affected_url": target,
                        "evidence": {"cname": cname, "provider": provider, "http_status": http_status},
                        "severity_rationale": f"Zone delegates via CNAME to {provider}; ensure DNS records are decommissioned before deleting cloud apps.",
                        "limitations": "Resource is currently responding (HTTP status is not 404); recorded for asset lifecycle tracking.",
                        "recommendation": "Maintain lifecycle tracking between DNS CNAME records and third-party cloud deployments.",
                        "remediation": "Maintain lifecycle tracking between DNS CNAME records and third-party cloud deployments.",
                    })

    # 2. Email & Domain Spoofing Posture (SPF & DMARC)
    dns_extra = report.get("dns") or {}
    if dns_extra.get("status") == "complete":
        spf = dns_extra.get("spf")
        dmarc = dns_extra.get("dmarc")
        if not spf:
            findings.append({
                "id": "dns-spf-permissive-or-missing",
                "title": "No SPF (v=spf1) record published in zone TXT records",
                "severity": "low",
                "classification": "configuration_observation",
                "confidence": "high",
                "category": "dns_security",
                "affected_url": target,
                "evidence": {"spf": None, "txt_records": dns_extra.get("txt_records", [])},
                "severity_rationale": "Without an SPF policy, mail receivers cannot verify authorized outbound mail servers for this domain.",
                "limitations": "Even domains that do not send email should publish a null SPF record ('v=spf1 -all') to prevent spoofing.",
                "recommendation": "Publish a restrictive SPF TXT record (e.g., 'v=spf1 -all' if no mail is sent, or include authorized senders with ~all / -all).",
                "remediation": "Publish a restrictive SPF TXT record (e.g., 'v=spf1 -all' if no mail is sent, or include authorized senders with ~all / -all).",
            })
        elif "+all" in spf.lower() or "?all" in spf.lower():
            findings.append({
                "id": "dns-spf-permissive-or-missing",
                "title": "Overly permissive SPF policy (+all or ?all)",
                "severity": "medium",
                "classification": "verified_finding",
                "confidence": "high",
                "category": "dns_security",
                "affected_url": target,
                "evidence": {"spf": spf},
                "severity_rationale": "An SPF record ending in '+all' or '?all' allows arbitrary hosts on the internet to send mail claiming to originate from this domain.",
                "limitations": "Directly observed in DNS TXT records.",
                "recommendation": "Replace '+all' or '?all' in your SPF record with '~all' (SoftFail) or '-all' (HardFail).",
                "remediation": "Replace '+all' or '?all' in your SPF record with '~all' (SoftFail) or '-all' (HardFail).",
            })
        if not dmarc:
            findings.append({
                "id": "dns-dmarc-missing",
                "title": "No DMARC policy published at _dmarc subdomain",
                "severity": "info",
                "classification": "configuration_observation",
                "confidence": "high",
                "category": "dns_security",
                "affected_url": target,
                "evidence": {"dmarc": None},
                "severity_rationale": "Absence of a DMARC record prevents domain-level enforcement and reporting of SPF/DKIM alignment failures.",
                "limitations": "Passive DNS query on _dmarc.<domain>.",
                "recommendation": "Publish a _dmarc TXT record (starting with 'v=DMARC1; p=quarantine;' or 'p=reject;') to protect against domain spoofing.",
                "remediation": "Publish a _dmarc TXT record (starting with 'v=DMARC1; p=quarantine;' or 'p=reject;') to protect against domain spoofing.",
            })

    # 3. JavaScript Secret Leaks, Source Maps, and DOM XSS Sink Candidates
    for s_item in (report.get("scripts") or {}).get("results", []):
        v_info = s_item.get("vuln_analysis") or {}
        s_url = s_item.get("url", target)
        for sec in v_info.get("credential_indicators", []):
            findings.append({
                "id": "js-hardcoded-secret",
                "title": f"Potential hardcoded credential in JavaScript bundle ({sec['type']})",
                "severity": sec["severity"],
                "classification": "vulnerability_candidate",
                "confidence": "medium",
                "category": "credential_exposure",
                "affected_url": s_url,
                "evidence": {"script": s_url, "type": sec["type"], "masked_preview": sec["masked_match"]},
                "severity_rationale": "Client-side JavaScript bundles are accessible to all users; hardcoded API keys or tokens can be extracted and abused.",
                "limitations": "Pattern-matched in static JS bundle; verify whether the key is a public client identifier or a privileged credential.",
                "recommendation": "Revoke and rotate the credential if privileged, and move authenticated API calls to a server-side backend.",
                "remediation": "Revoke and rotate the credential if privileged, and move authenticated API calls to a server-side backend.",
            })
        if v_info.get("source_maps"):
            findings.append({
                "id": "js-source-map-exposed",
                "title": "JavaScript bundle declares external Source Map reference (.js.map)",
                "severity": "low",
                "classification": "configuration_observation",
                "confidence": "high",
                "category": "exposure",
                "affected_url": s_url,
                "evidence": {"script": s_url, "source_maps": v_info["source_maps"]},
                "severity_rationale": "Production source maps allow reconstruction of unminified original frontend source code, comments, and internal logic.",
                "limitations": "Observed via sourceMappingURL directive in inspected JavaScript.",
                "recommendation": "Disable production source map generation or restrict .map files to internal error-tracking pipelines.",
                "remediation": "Disable production source map generation or restrict .map files to internal error-tracking pipelines.",
            })
        if v_info.get("dom_sinks_with_url_source"):
            findings.append({
                "id": "js-dom-xss-sink",
                "title": "JavaScript bundle combines URL/Location sources with dangerous DOM sinks",
                "severity": "low",
                "classification": "vulnerability_candidate",
                "confidence": "low",
                "category": "injection_surface",
                "affected_url": s_url,
                "evidence": {"script": s_url, "sinks": v_info["dom_sinks_with_url_source"]},
                "severity_rationale": "Presence of URL parameter sources alongside sinks like innerHTML or eval() indicates potential DOM-based XSS surface.",
                "limitations": "Static co-occurrence in bundle only; data-flow taint analysis and sanitization checks require manual review.",
                "recommendation": "Audit data flow from location.search/hash to DOM sinks; prefer textContent or a strict sanitizer like DOMPurify.",
                "remediation": "Audit data flow from location.search/hash to DOM sinks; prefer textContent or a strict sanitizer like DOMPurify.",
            })

    # 4. Open Redirect & SSRF Parameter Surface Discovery
    all_links = list(((report.get("content") or {}).get("html") or {}).get("links", []))
    for p_item in (report.get("pages") or {}).get("results", []):
        all_links.extend(((p_item.get("content") or {}).get("html") or {}).get("links", []))

    redirect_hits = []
    ssrf_hits = []
    for link in dict.fromkeys(all_links):
        try:
            sp = urlsplit(link)
            if not sp.query:
                continue
            params = parse_qs(sp.query, keep_blank_values=True)
            for p_name in params:
                p_low = p_name.lower()
                if p_low in OPEN_REDIRECT_PARAMS:
                    redirect_hits.append({"url": redact_sensitive(link), "param": p_name})
                elif p_low in SSRF_CANDIDATE_PARAMS:
                    ssrf_hits.append({"url": redact_sensitive(link), "param": p_name})
        except ValueError:
            continue

    if redirect_hits:
        findings.append({
            "id": "open-redirect-parameter-candidate",
            "title": "URL parameter(s) associated with redirection/navigation discovered",
            "severity": "low",
            "classification": "vulnerability_candidate",
            "confidence": "low",
            "category": "attack_surface",
            "affected_url": redirect_hits[0]["url"],
            "evidence": {"candidates": redirect_hits[:8]},
            "severity_rationale": "Parameters such as redirect, next, or returnUrl are frequent vectors for Open Redirect and OAuth token theft if unvalidated.",
            "limitations": "Passive parameter name discovery only; no external redirect payloads were injected.",
            "recommendation": "Validate all redirect targets against a strict server-side allowlist of relative paths or trusted domains.",
            "remediation": "Validate all redirect targets against a strict server-side allowlist of relative paths or trusted domains.",
        })
    if ssrf_hits:
        findings.append({
            "id": "ssrf-parameter-candidate",
            "title": "URL parameter(s) accepting path/URI/resource identifiers discovered",
            "severity": "info",
            "classification": "vulnerability_candidate",
            "confidence": "low",
            "category": "attack_surface",
            "affected_url": ssrf_hits[0]["url"],
            "evidence": {"candidates": ssrf_hits[:8]},
            "severity_rationale": "Parameters accepting file paths, URLs, or webhooks warrant review for Server-Side Request Forgery (SSRF) or Path Traversal.",
            "limitations": "Passive parameter discovery only; no active file/URL payloads were sent.",
            "recommendation": "Ensure resource-loading parameters use indirect object references (IDs) rather than raw file paths or URLs.",
            "remediation": "Ensure resource-loading parameters use indirect object references (IDs) rather than raw file paths or URLs.",
        })

    # 5. External Script Subresource Integrity (SRI) & POST Form CSRF Heuristics
    html_doc = (report.get("content") or {}).get("html") or {}
    ext_scripts_no_sri = html_doc.get("external_scripts_without_sri") or []
    if ext_scripts_no_sri:
        findings.append({
            "id": "missing-sri-external-script",
            "title": "Third-party script(s) loaded without Subresource Integrity (SRI)",
            "severity": "low",
            "classification": "configuration_observation",
            "confidence": "high",
            "category": "integrity",
            "affected_url": target,
            "evidence": {"external_scripts_without_sri": ext_scripts_no_sri[:10]},
            "severity_rationale": "Loading external scripts from third-party CDNs without an integrity hash exposes the page if the CDN or upstream package is compromised.",
            "limitations": "Applies to static <script src='...'> tags from cross-origin domains.",
            "recommendation": "Add 'integrity=\"sha384-...\"' and 'crossorigin=\"anonymous\"' attributes to third-party script tags.",
            "remediation": "Add 'integrity=\"sha384-...\"' and 'crossorigin=\"anonymous\"' attributes to third-party script tags.",
        })

    for form in html_doc.get("form_details", []):
        if (form.get("method") or "").upper() == "POST" and not form.get("has_csrf_field", False):
            findings.append({
                "id": "form-missing-csrf-token",
                "title": "POST form without recognizable hidden anti-CSRF token field",
                "severity": "low",
                "classification": "vulnerability_candidate",
                "confidence": "low",
                "category": "access_control",
                "affected_url": target,
                "evidence": {"method": form.get("method"), "action": form.get("action")},
                "severity_rationale": "State-changing POST forms without a synchronizer token or custom header protection may be susceptible to Cross-Site Request Forgery (CSRF).",
                "limitations": "Static HTML form inspection only; applications using SameSite=Strict/Lax cookies, custom X-XSRF-TOKEN headers via JS fetch, or unauthenticated public forms (e.g., search/login) may be safe.",
                "recommendation": "Verify that state-changing POST endpoints validate an unpredictable anti-CSRF token and enforce SameSite cookie policies.",
                "remediation": "Verify that state-changing POST endpoints validate an unpredictable anti-CSRF token and enforce SameSite cookie policies.",
            })

    # 6. Exact Server / Runtime Version Disclosure in Headers
    srv = headers.get("server") or ""
    pwr = headers.get("x-powered-by") or ""
    if re.search(r"/\d+\.\d+", srv) or re.search(r"\b\d+\.\d+", pwr):
        findings.append({
            "id": "server-version-banner-disclosed",
            "title": "HTTP response headers disclose specific software version numbers",
            "severity": "info",
            "classification": "configuration_observation",
            "confidence": "high",
            "category": "hardening",
            "affected_url": target,
            "evidence": {"server": srv or None, "x-powered-by": pwr or None},
            "severity_rationale": "Explicit version numbers in Server or X-Powered-By headers simplify automated reconnaissance against unpatched services.",
            "limitations": "Version banners can be spoofed or backported by OS distributions (e.g., Debian/Ubuntu) and are not proof of vulnerability.",
            "recommendation": "Suppress detailed version tokens in production (e.g., 'server_tokens off;' in nginx, 'ServerTokens Prod' in Apache, 'expose_php = Off' in PHP).",
            "remediation": "Suppress detailed version tokens in production (e.g., 'server_tokens off;' in nginx, 'ServerTokens Prod' in Apache, 'expose_php = Off' in PHP).",
        })

    return findings


def enrich_finding_taxonomy(finding):
    """Attach CWE, OWASP Top 10 (2021), and CVSS v3.1 score metadata to a finding dict."""
    fid = finding.get("id", "")
    cwe, owasp, cvss = FINDING_TAXONOMY.get(
        fid,
        (
            "CWE-693" if finding.get("severity") == "info" else "CWE-200",
            "A05:2021-Security Misconfiguration",
            {"high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}.get(finding.get("severity", "info"), 0.0),
        ),
    )
    finding.setdefault("cwe", cwe)
    finding.setdefault("owasp", owasp)
    finding.setdefault("cvss_score", cvss)
    return finding
