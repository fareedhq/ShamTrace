"""Configuration observations, vulnerability candidates, and verified findings with conservative severity and deduplication."""
import json
import re
from urllib.parse import urlsplit
from .checks import redact_sensitive

DEFAULT_LIMITATIONS = {
    "unencrypted-http": "Indicates the requested URL scheme only; does not test whether HTTPS is available on port 443.",
    "header-content-security-policy": "Absence of CSP is a defense-in-depth hardening observation, not proof of an XSS vulnerability.",
    "header-x-content-type-options": "Exploitability depends on whether user-controlled content can be uploaded or reflected with ambiguous MIME types.",
    "header-referrer-policy": "Impact depends on whether sensitive tokens or identifiers appear in application URLs.",
    "header-permissions-policy": "Browser feature restriction is hardening; absence alone is not an exploitable flaw.",
    "header-strict-transport-security": "HSTS applies only after a browser has completed an initial trusted HTTPS connection.",
    "cookie-flags": "Not every cookie holds session or authentication state; non-sensitive preference or analytics cookies may intentionally omit HttpOnly for client-side script access.",
    "mixed-content-references": "Static markup reference only; modern browsers may auto-upgrade or block mixed content at runtime.",
}

DEFAULT_RATIONALES = {
    "unencrypted-http": "Cleartext HTTP exposes traffic to passive interception and active tampering on untrusted networks.",
    "header-content-security-policy": "Informational hardening gap; CSP mitigates XSS impact but requires application-specific tuning.",
    "header-x-content-type-options": "Informational hardening gap; nosniff prevents browsers from MIME-sniffing non-executable responses.",
    "header-referrer-policy": "Informational hardening gap; explicit Referrer-Policy prevents unintended cross-origin URL disclosure.",
    "header-permissions-policy": "Informational hardening gap; restricts access to powerful browser APIs.",
    "header-strict-transport-security": "Informational hardening gap; HSTS instructs browsers to enforce HTTPS on future connections.",
    "cookie-flags": "Missing Secure or HttpOnly flags weaken cookie protection if the cookie carries session or authentication state; preference cookies may not require HttpOnly.",
    "mixed-content-references": "Referencing HTTP subresources from an HTTPS page weakens transport confidentiality or causes broken page assets.",
}

DEFAULT_CLASSIFICATIONS = {
    "unencrypted-http": "configuration_observation",
    "header-content-security-policy": "configuration_observation",
    "header-x-content-type-options": "configuration_observation",
    "header-referrer-policy": "configuration_observation",
    "header-permissions-policy": "configuration_observation",
    "header-strict-transport-security": "configuration_observation",
    "cookie-flags": "configuration_observation",
    "mixed-content-references": "configuration_observation",
}


def policy_findings(headers, report):
    if report.get("edge", {}).get("skip_followup"):
        return []
    findings = []
    target = report["target"]

    def add(
        code,
        title,
        evidence,
        recommendation,
        severity="low",
        confidence="high",
        classification="configuration_observation",
        category="configuration",
        rationale=None,
        limitations=None,
    ):
        findings.append({
            "id": code,
            "title": title,
            "priority": "review",
            "severity": severity,
            "severity_rationale": rationale
            or f"Rated {severity} based on passive configuration evidence without exploit confirmation.",
            "confidence": confidence,
            "classification": classification,
            "category": category,
            "evidence": redact_sensitive(evidence),
            "limitations": limitations
            or "Configuration observation from HTTP response headers/markup; runtime exploitability is not verified.",
            "recommendation": recommendation,
            "remediation": recommendation,
            "status": "observed",
            "affected_url": target,
        })

    https = urlsplit(target).scheme == "https"
    hsts = headers.get("strict-transport-security")
    if https and hsts:
        values = re.findall(r'(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?=;|$)', hsts, re.I)
        if not values:
            add(
                "hsts-invalid-max-age",
                "HSTS has no recognized max-age",
                hsts,
                "Set a valid positive max-age (e.g., max-age=31536000) after verifying HTTPS coverage.",
                severity="low",
                classification="verified_finding",
                rationale="Malformed HSTS header is ignored by browsers, leaving clients open to initial HTTP downgrade.",
            )
        elif len(values) != 1 or int(values[0]) == 0:
            add(
                "hsts-disabled-or-ambiguous",
                "HSTS is disabled or ambiguous",
                hsts,
                "Review duplicate directives; max-age=0 disables HSTS caching in browsers.",
                severity="low",
                classification="configuration_observation",
                rationale="max-age=0 explicitly clears HSTS protection in compliant user agents.",
            )
        elif int(values[0]) < 31536000:
            add(
                "hsts-short-max-age",
                "HSTS max-age is shorter than recommended (1 year)",
                hsts,
                "Increase HSTS max-age to at least 31536000 seconds (1 year) once HTTPS stability is confirmed.",
                severity="info",
                classification="configuration_observation",
                rationale="Short HSTS duration leaves infrequent visitors unprotected after policy expiration.",
            )

    xcto = headers.get("x-content-type-options")
    if xcto is not None and xcto.strip() and xcto.strip().lower() != "nosniff":
        add(
            "x-content-type-options-invalid",
            "X-Content-Type-Options has an unrecognized value",
            xcto,
            "Set X-Content-Type-Options: nosniff exactly.",
            severity="low",
            classification="verified_finding",
            rationale="Only the 'nosniff' directive is recognized by browsers; other values provide no protection.",
        )

    ref_policy = headers.get("referrer-policy")
    if ref_policy and ref_policy.strip():
        tokens = [t.strip().lower() for t in ref_policy.split(",") if t.strip()]
        effective = tokens[-1] if tokens else ""
        if effective == "unsafe-url":
            add(
                "referrer-policy-unsafe-url",
                "Referrer-Policy explicitly permits full URL disclosure (unsafe-url)",
                ref_policy,
                "Change Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
                severity="low",
                classification="configuration_observation",
                rationale="unsafe-url sends full URLs (including path and query parameters) to third-party origins, even over HTTP.",
            )

    mime = headers.get("content-type", "").lower()
    csp = headers.get("content-security-policy", "")
    directives = {}
    for part in csp.split(";"):
        words = part.split()
        if words:
            directives.setdefault(words[0].lower(), [w.lower() for w in words[1:]])
    script_policy = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-eval'" in script_policy:
        add(
            "csp-unsafe-eval",
            "CSP permits dynamic code evaluation",
            csp,
            "Remove dependencies on eval/Function and remove 'unsafe-eval' after application testing.",
            severity="low",
            classification="configuration_observation",
            rationale="Permitting 'unsafe-eval' weakens CSP protection against DOM-based XSS vectors that abuse dynamic code evaluation.",
        )
    if "'unsafe-inline'" in script_policy and not any(
        w.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for w in script_policy
    ):
        add(
            "csp-unsafe-inline-script",
            "CSP permits un-nonced inline scripts ('unsafe-inline')",
            csp,
            "Replace inline scripts with external bundles or use cryptographic nonces/hashes in script-src.",
            severity="low",
            classification="configuration_observation",
            rationale="Un-nonced 'unsafe-inline' in script-src neutralizes CSP's primary defense against injected inline script tags.",
        )
    if any(tok in script_policy for tok in ("*", "http:", "https:", "data:")):
        add(
            "csp-broad-script-source",
            "CSP permits overly broad script sources",
            csp,
            "Restrict script-src to explicit trusted origins or hashes/nonces instead of wildcard/scheme sources.",
            severity="low",
            classification="configuration_observation",
            rationale="Wildcard or scheme-wide script sources allow attackers to load scripts from arbitrary third-party endpoints on those schemes.",
        )

    if "text/html" in mime:
        xfo = headers.get("x-frame-options", "").upper()
        if "frame-ancestors" not in directives and xfo not in {"DENY", "SAMEORIGIN"}:
            add(
                "framing-policy-not-observed",
                "No recognized response-header framing restriction",
                {"x-frame-options": headers.get("x-frame-options"), "csp-frame-ancestors": None},
                "Decide whether embedding is needed; configure CSP frame-ancestors accordingly. Clickjacking impact requires UI validation.",
                severity="low",
                classification="configuration_observation",
                rationale="Without frame-ancestors or X-Frame-Options, HTML pages can be framed by external origins.",
                limitations="Clickjacking risk applies only if the page contains state-changing interactive UI elements.",
            )

    # CORS analysis — never treat public wildcard (*) without credentials as a vulnerability
    acao = (headers.get("access-control-allow-origin") or "").strip()
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    vary = (headers.get("vary") or "").lower()
    if acao:
        if acao == "*" and acac == "true":
            add(
                "cors-wildcard-with-credentials",
                "CORS combines wildcard origin (*) with Allow-Credentials: true",
                {"access-control-allow-origin": acao, "access-control-allow-credentials": acac},
                "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true; validate and allowlist specific trusted origins.",
                severity="medium",
                classification="verified_finding",
                rationale="Directly contradictory/insecure CORS policy attempting to combine wildcard origin access with credentials.",
                limitations="Modern browsers block '*' with credentials at the fetch layer, but server-side origin reflection logic may still be flawed.",
            )
        elif acao.lower() == "null":
            add(
                "cors-null-origin",
                "CORS allows 'null' origin",
                {"access-control-allow-origin": acao, "access-control-allow-credentials": acac or None},
                "Remove 'null' from Access-Control-Allow-Origin; sandboxed iframes and local documents can generate Origin: null requests.",
                severity="medium" if acac == "true" else "low",
                classification="vulnerability_candidate" if acac == "true" else "configuration_observation",
                rationale="An attacker can trigger cross-origin requests with Origin: null using a sandboxed iframe.",
            )
        elif acao != "*" and "origin" not in {t.strip() for t in vary.split(",")}:
            add(
                "cors-missing-vary-origin",
                "Specific CORS origin returned without Vary: Origin",
                {"access-control-allow-origin": acao, "vary": headers.get("vary")},
                "Add 'Vary: Origin' when dynamically returning specific Access-Control-Allow-Origin headers.",
                severity="low",
                classification="configuration_observation",
                rationale="Missing Vary: Origin can cause intermediate or browser caches to serve responses with the wrong CORS origin header.",
            )

    for cookie in report.get("cookies", []):
        if cookie["samesite"].lower() == "none" and not cookie["secure"]:
            add(
                "cookie-samesite-none-without-secure",
                "SameSite=None cookie lacks Secure",
                cookie["name"],
                "Set Secure for this cookie over HTTPS and verify browser acceptance.",
                severity="low",
                classification="verified_finding",
                rationale="Modern browsers reject SameSite=None cookies that do not also set the Secure attribute.",
            )
        if cookie.get("prefix") in {"__Host-", "__Secure-"} and not cookie.get("prefix_valid", True):
            add(
                "cookie-prefix-violation",
                f"Cookie {cookie['prefix']} prefix requirements not satisfied",
                {
                    "name": cookie["name"],
                    "secure": cookie["secure"],
                    "path": cookie.get("path"),
                    "domain": cookie.get("domain"),
                },
                "For __Host- cookies, set Secure, Path=/, and omit Domain. For __Secure- cookies, set Secure.",
                severity="low",
                classification="verified_finding",
                rationale="Browsers reject cookies with __Host- or __Secure- prefixes that violate RFC 6265bis attribute constraints.",
            )

    cert = report.get("certificate") or {}
    if cert.get("days_remaining") is not None:
        days = cert["days_remaining"]
        if days < 0:
            add(
                "tls-certificate-expired",
                "TLS certificate validity period has expired",
                {"not_after": cert.get("not_after"), "days_remaining": days},
                "Renew and deploy a valid TLS certificate immediately.",
                severity="high",
                classification="verified_finding",
                rationale="Expired TLS certificates cause connection failures or habituate users to bypassing TLS warnings.",
            )
        elif days <= 30:
            add(
                "tls-certificate-expiring-soon",
                "TLS certificate within 30-day renewal window (operational observation)",
                {"not_after": cert.get("not_after"), "days_remaining": days, "issuer": cert.get("issuer")},
                "Confirm that automated certificate renewal (e.g., Let's Encrypt / ACME 90-day cycle) is scheduled and functioning.",
                severity="info",
                classification="operational_observation",
                category="operational",
                rationale=(
                    f"Certificate expires in {days} day(s). Short-lived ACME/Let's Encrypt certificates (90-day validity) "
                    "normally renew within the final 30 days; this is an operational check, not a security vulnerability."
                ),
                limitations="Automated edge/ACME renewal cannot be observed from a single certificate check; verify renewal logs only if managed manually.",
            )

    for form in (report.get("content", {}).get("html") or {}).get("forms", []):
        if https and urlsplit(form["action"]).scheme == "http":
            add(
                "form-http-downgrade",
                "HTTPS page declares an HTTP form action",
                form,
                "Change the form destination to HTTPS and review which fields are submitted.",
                severity="medium",
                classification="vulnerability_candidate",
                rationale="Submitting form data from an HTTPS page over cleartext HTTP exposes user input to network interception.",
                limitations="Static HTML form action attribute; client-side JavaScript handlers may override form submission at runtime.",
            )
    return findings


def normalize_findings(findings, target):
    from .vuln_checks import enrich_finding_taxonomy
    redacted_target = redact_sensitive(target)
    for finding in findings:
        fid = finding["id"]
        finding.setdefault("title", fid.replace("-", " ").capitalize())
        finding.setdefault("severity", "info" if fid.startswith("header-") else "low")
        finding.setdefault(
            "classification",
            DEFAULT_CLASSIFICATIONS.get(fid, "configuration_observation"),
        )
        finding.setdefault(
            "severity_rationale",
            DEFAULT_RATIONALES.get(
                fid,
                f"Rated {finding['severity']} based on passive configuration observation; requires contextual verification.",
            ),
        )
        finding.setdefault("confidence", "high")
        finding.setdefault("category", "hardening")
        finding.setdefault("status", "observed")
        finding.setdefault("affected_url", redacted_target)
        finding["affected_url"] = redact_sensitive(finding["affected_url"])
        finding.setdefault("affected_urls", [finding["affected_url"]])
        finding["evidence"] = redact_sensitive(finding.get("evidence"))
        finding.setdefault(
            "limitations",
            DEFAULT_LIMITATIONS.get(
                fid,
                "Passive observation without active exploitation or runtime browser execution.",
            ),
        )
        finding.setdefault(
            "remediation",
            finding.get("recommendation", "Review configuration in application context."),
        )
        enrich_finding_taxonomy(finding)
    return findings


def deduplicate_findings(findings):
    """
    Deduplicate identical findings across pages while keeping distinct findings
    (such as different cookies, different forms, or different evidence payloads) separate.
    """
    grouped = {}
    order = []
    page_wide_ids = {
        "unencrypted-http",
        "header-content-security-policy",
        "header-x-content-type-options",
        "header-referrer-policy",
        "header-permissions-policy",
        "header-strict-transport-security",
        "framing-policy-not-observed",
        "hsts-invalid-max-age",
        "hsts-disabled-or-ambiguous",
        "hsts-short-max-age",
        "x-content-type-options-invalid",
        "referrer-policy-unsafe-url",
        "csp-unsafe-eval",
        "csp-unsafe-inline-script",
        "csp-broad-script-source",
        "cors-wildcard-with-credentials",
        "cors-null-origin",
        "cors-missing-vary-origin",
        "tls-certificate-expired",
        "tls-certificate-expiring-soon",
    }
    for item in findings:
        fid = item.get("id", "unknown")
        title = item.get("title", fid)
        # Page-wide response policy findings merge across URLs; specific artifact findings
        # (cookies, forms, mixed-content resources) include their evidence in the key so distinct items are never merged.
        ev_key = "" if fid in page_wide_ids else json.dumps(item.get("evidence"), sort_keys=True, default=str)
        key = (fid, title, ev_key)
        url = item.get("affected_url")
        if key not in grouped:
            cloned = dict(item)
            urls = list(dict.fromkeys((item.get("affected_urls") or []) + ([url] if url else [])))
            cloned["affected_urls"] = urls
            cloned["occurrence_count"] = len(urls) or 1
            grouped[key] = cloned
            order.append(key)
        else:
            existing = grouped[key]
            if url and url not in existing["affected_urls"]:
                existing["affected_urls"].append(url)
            for u in item.get("affected_urls") or []:
                if u and u not in existing["affected_urls"]:
                    existing["affected_urls"].append(u)
            existing["occurrence_count"] = len(existing["affected_urls"])
    return [grouped[k] for k in order]
