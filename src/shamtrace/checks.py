import datetime
import hashlib
import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

HEADER_RULES = {
    "content-security-policy": "Controls permitted content sources.",
    "x-content-type-options": "Controls MIME sniffing.",
    "referrer-policy": "Controls referrer disclosure.",
    "permissions-policy": "Controls browser feature access.",
}

SENSITIVE_QUERY_KEYS = {
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth",
    "authorization",
    "key",
    "api_key",
    "apikey",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "pwd",
    "session",
    "sessionid",
    "sid",
    "phpsessid",
    "jsessionid",
    "jwt",
    "signature",
    "sig",
    "code",
}

TRACKING_QUERY_KEYS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "msclkid",
    "_ga",
    "_gl",
}

DESTRUCTIVE_QUERY_KEYS = {
    "delete",
    "remove",
    "destroy",
    "logout",
    "signout",
    "logoff",
    "unsubscribe",
    "reset",
    "revoke",
    "drop",
    "purge",
    "wipe",
}

DESTRUCTIVE_QUERY_VALUES = {
    "delete",
    "remove",
    "destroy",
    "logout",
    "signout",
    "logoff",
    "unsubscribe",
    "reset",
    "revoke",
    "drop",
    "purge",
    "wipe",
}

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}

SHARED_EDGE_NETWORKS = (
    ipaddress.ip_network("216.198.79.0/24"),   # Vercel Anycast
    ipaddress.ip_network("76.76.21.0/24"),     # Vercel Anycast
    ipaddress.ip_network("185.199.108.0/22"),  # GitHub Pages
    ipaddress.ip_network("151.101.0.0/16"),    # Fastly
    ipaddress.ip_network("104.16.0.0/12"),     # Cloudflare
    ipaddress.ip_network("172.64.0.0/13"),     # Cloudflare
    ipaddress.ip_network("162.158.0.0/15"),    # Cloudflare
    ipaddress.ip_network("198.41.128.0/17"),   # Cloudflare
)

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_AUTH_SCHEME_RE = re.compile(r"\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{6,}", re.I)
_INLINE_SECRET_PARAM_RE = re.compile(
    r"(?i)\b(token|access_token|refresh_token|api_key|apikey|secret|password|passwd|session|sid|jwt|auth)=([^&\s\"';]+)"
)


def normalize_host(hostname):
    return (hostname or "").rstrip(".").lower()


def effective_port(parsed):
    if parsed.port is not None:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def validate_target(value):
    target = (value or "").strip()
    if not target:
        raise ValueError("Target cannot be empty.")
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in target):
        raise ValueError("Target URL contains control or whitespace characters.")
    if "://" not in target:
        target = "https://" + target

    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Supply a valid HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in URLs are not supported.")
    if parsed.fragment:
        raise ValueError("Remove the URL fragment (#...) before scanning.")
    try:
        port = parsed.port
    except ValueError as err:
        raise ValueError("Port must be between 1 and 65535.") from err
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    return target, parsed


def is_in_scope(candidate_url, target_url, allow_https_upgrade=False):
    """Verify whether candidate_url stays within the authorized target scope."""
    try:
        cand = urlsplit(candidate_url)
        base = urlsplit(target_url)
    except ValueError:
        return False
    if cand.scheme not in {"http", "https"} or not cand.hostname:
        return False
    if cand.username is not None or cand.password is not None:
        return False
    try:
        cand_port = effective_port(cand)
        base_port = effective_port(base)
    except ValueError:
        return False
    if normalize_host(cand.hostname) != normalize_host(base.hostname):
        return False
    if cand.scheme == base.scheme and cand_port == base_port:
        return True
    if (
        allow_https_upgrade
        and base.scheme == "http"
        and cand.scheme == "https"
        and base_port == 80
        and cand_port == 443
    ):
        return True
    return False


def normalize_in_scope_url(candidate_url, target_url):
    """
    Normalize and validate a URL for in-scope crawling while preserving meaningful
    query parameters, stripping tracking noise, and rejecting state-changing query actions.
    Returns (normalized_url, skip_reason).
    """
    try:
        parsed = urlsplit(candidate_url)
    except ValueError:
        return None, "malformed_url"
    if not is_in_scope(candidate_url, target_url, allow_https_upgrade=False):
        return None, "out_of_scope"
    if parsed.username or parsed.password:
        return None, "contains_credentials"

    # Normalize path
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    # Parse and filter query parameters
    meaningful_params = []
    if parsed.query:
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            k_low = k.strip().lower()
            v_low = v.strip().lower()
            if k_low in TRACKING_QUERY_KEYS:
                continue
            if (
                k_low in DESTRUCTIVE_QUERY_KEYS
                or v_low in DESTRUCTIVE_QUERY_VALUES
                or k_low in SENSITIVE_QUERY_KEYS
            ):
                return None, "unsafe_or_state_changing_query"
            meaningful_params.append((k, v))
        meaningful_params.sort(key=lambda item: (item[0], item[1]))

    normalized_query = urlencode(meaningful_params, doseq=True)
    host = normalize_host(parsed.hostname)
    default_port = 443 if parsed.scheme == "https" else 80
    netloc = f"{host}:{parsed.port}" if (parsed.port and parsed.port != default_port) else host
    return urlunsplit((parsed.scheme.lower(), netloc, path, normalized_query, "")), None


def detect_shared_edge(resolved_ips, headers=None, fingerprints=None):
    """Detect whether the target resolves to a shared CDN / cloud edge provider."""
    reasons = []
    if headers:
        srv = (headers.get("server") or "").lower()
        if "cloudflare" in srv or "cf-ray" in headers:
            reasons.append("Cloudflare CDN/WAF")
        if "vercel" in srv or "x-vercel-id" in headers:
            reasons.append("Vercel Edge Network")
        if "x-amz-cf-id" in headers:
            reasons.append("AWS CloudFront")
        if "x-fastly-request-id" in headers or "fastly-restarts" in headers:
            reasons.append("Fastly CDN")
        if "x-nf-request-id" in headers or "netlify" in srv:
            reasons.append("Netlify Edge")
    for ip_str in resolved_ips or []:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if any(ip_obj in net for net in SHARED_EDGE_NETWORKS):
                reasons.append(f"Shared edge IP range ({ip_str})")
        except ValueError:
            continue
    for fp in fingerprints or []:
        if "cdn_waf" in (fp.get("categories") or [fp.get("category")]) or "hosting_cdn" in (
            fp.get("categories") or [fp.get("category")]
        ):
            reasons.append(fp.get("name"))
    unique = list(dict.fromkeys(r for r in reasons if r))
    return {"is_shared_edge": bool(unique), "providers": unique}


def redact_url(url_str):
    """Redact sensitive query parameters and credentials from a URL string."""
    try:
        parsed = urlsplit(url_str)
    except ValueError:
        return _INLINE_SECRET_PARAM_RE.sub(r"\1=[REDACTED]", url_str)
    netloc = parsed.netloc
    if "@" in netloc:
        _, _, hostpart = netloc.rpartition("@")
        netloc = f"[REDACTED]@{hostpart}"
    query = parsed.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        redacted_pairs = []
        changed = False
        for k, v in pairs:
            if k.lower() in SENSITIVE_QUERY_KEYS or _JWT_RE.search(v):
                redacted_pairs.append((k, "[REDACTED]"))
                changed = True
            else:
                redacted_pairs.append((k, v))
        if changed:
            query = urlencode(redacted_pairs, safe="[]")
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))


def redact_sensitive(value, key_hint=None):
    """Recursively redact tokens, cookie values, and authentication data from evidence."""
    if value is None:
        return None
    if key_hint and str(key_hint).lower() in SENSITIVE_HEADER_KEYS:
        return "[REDACTED]"
    if isinstance(value, str):
        text = value
        if text.startswith(("http://", "https://")) and " " not in text:
            text = redact_url(text)
        text = _JWT_RE.sub("[REDACTED_JWT]", text)
        text = _AUTH_SCHEME_RE.sub(r"\1 [REDACTED]", text)
        text = _INLINE_SECRET_PARAM_RE.sub(r"\1=[REDACTED]", text)
        return text
    if isinstance(value, list):
        return [redact_sensitive(item, key_hint=key_hint) for item in value]
    if isinstance(value, dict):
        return {k: redact_sensitive(v, key_hint=k) for k, v in value.items()}
    return value


def inspect_cookies(headers):
    """Report cookie metadata and prefix compliance without persisting cookie values."""
    findings = []
    session_like_tokens = ("sess", "sid", "token", "auth", "jwt", "login", "user", "csrf", "xsrf")
    for raw in headers.get_list("set-cookie"):
        parts = raw.split(";")
        name, separator, _ = parts[0].strip().partition("=")
        if not separator or not name:
            continue
        attributes = {}
        for part in parts[1:]:
            key, _, value = part.strip().partition("=")
            if key:
                attributes[key.lower()] = value.strip()
        secure = "secure" in attributes
        httponly = "httponly" in attributes
        samesite = attributes.get("samesite") or "not specified"
        path = attributes.get("path")
        domain = attributes.get("domain")
        has_expiry = "max-age" in attributes or "expires" in attributes

        prefix = "none"
        prefix_valid = True
        if name.startswith("__Host-"):
            prefix = "__Host-"
            prefix_valid = bool(secure and path == "/" and not domain)
        elif name.startswith("__Secure-"):
            prefix = "__Secure-"
            prefix_valid = bool(secure)

        likely_sensitive = (
            prefix in {"__Host-", "__Secure-"}
            or any(tok in name.lower() for tok in session_like_tokens)
        )

        findings.append({
            "name": name,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
            "path": path,
            "domain": domain,
            "persistent": has_expiry,
            "prefix": prefix,
            "prefix_valid": prefix_valid,
            "likely_sensitive": likely_sensitive,
        })
    return findings


def _evaluate_header_value(name, value):
    if value is None:
        return "missing", "Header not present in response."
    cleaned = value.strip()
    if not cleaned:
        return "empty", "Header is present with an empty value."
    low = cleaned.lower()

    if name == "x-content-type-options":
        if low == "nosniff":
            return "strong", "Strict MIME-sniffing protection enabled."
        return "misconfigured", f"Expected 'nosniff', observed {cleaned!r}."

    if name == "strict-transport-security":
        matches = re.findall(r'(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?=;|$)', cleaned, re.I)
        if not matches:
            return "misconfigured", "No valid max-age directive found."
        if len(matches) > 1 or int(matches[0]) == 0:
            return "weak", "HSTS is disabled (max-age=0) or contains duplicate max-age directives."
        max_age = int(matches[0])
        if max_age < 31536000:
            return "weak", f"max-age={max_age} is shorter than the recommended 1 year (31536000s)."
        return "strong", f"max-age={max_age} (>= 1 year)."

    if name == "referrer-policy":
        tokens = [t.strip().lower() for t in cleaned.split(",") if t.strip()]
        effective = tokens[-1] if tokens else ""
        safe_policies = {
            "no-referrer",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        }
        weak_policies = {"origin", "origin-when-cross-origin", "no-referrer-when-downgrade", "unsafe-url"}
        if effective in safe_policies:
            return "strong", f"Effective policy '{effective}' restricts cross-origin referrer leakage."
        if effective in weak_policies:
            return "weak", f"Effective policy '{effective}' may expose URL origin or path across origins."
        return "misconfigured", f"Unrecognized Referrer-Policy token {effective!r}."

    if name == "content-security-policy":
        directives = {}
        for part in cleaned.split(";"):
            words = part.split()
            if words:
                directives.setdefault(words[0].lower(), [w.lower() for w in words[1:]])
        script_src = directives.get("script-src", directives.get("default-src", []))
        issues = []
        if "'unsafe-eval'" in script_src:
            issues.append("permits 'unsafe-eval'")
        if "'unsafe-inline'" in script_src and not any(
            w.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for w in script_src
        ):
            issues.append("permits un-nonced 'unsafe-inline'")
        if "*" in script_src or "http:" in script_src or "https:" in script_src or "data:" in script_src:
            issues.append("permits overly broad script sources")
        if issues:
            return "weak", "CSP present but " + ", ".join(issues) + "."
        return "adequate", "CSP present without obvious wildcard/unsafe-eval script tokens."

    if name == "permissions-policy":
        if "*" in cleaned:
            return "weak", "Permissions-Policy contains wildcard allowlists."
        return "adequate", "Permissions-Policy header declared."

    return "adequate", "Header present."


def assess_headers(headers, https):
    rules = dict(HEADER_RULES)
    if https:
        rules["strict-transport-security"] = "Advertises an HTTPS-only policy."

    results = []
    for name, purpose in rules.items():
        value = headers.get(name)
        if value is None:
            state = "missing"
        elif not value.strip():
            state = "empty"
        else:
            state = "present"
        quality, note = _evaluate_header_value(name, value)
        results.append({
            "header": name,
            "state": state,
            "value": value,
            "quality": quality,
            "evaluation": note,
            "purpose": purpose,
        })
    return results


def inspect_cors(headers, target_url=None):
    """Analyze passive CORS response headers without treating public wildcards as vulnerabilities."""
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials")
    acam = headers.get("access-control-allow-methods")
    acah = headers.get("access-control-allow-headers")
    aceh = headers.get("access-control-expose-headers")
    vary = headers.get("vary") or ""
    vary_tokens = {t.strip().lower() for t in vary.split(",") if t.strip()}

    credentials_true = (acac or "").strip().lower() == "true"
    origin_val = (acao or "").strip()

    state = "not_advertised"
    risk = "none"
    notes = []

    if origin_val:
        if origin_val == "*" and credentials_true:
            state = "misconfigured"
            risk = "high"
            notes.append(
                "Wildcard Access-Control-Allow-Origin (*) combined with Access-Control-Allow-Credentials: true."
            )
        elif origin_val.lower() == "null":
            state = "permissive"
            risk = "high" if credentials_true else "medium"
            notes.append(
                "Access-Control-Allow-Origin permits 'null' origin (reachable via sandboxed iframes)."
            )
        elif origin_val == "*":
            state = "public_wildcard"
            risk = "none"
            notes.append(
                "Public wildcard (*) without credentials; standard for public websites/CDNs and not a vulnerability by itself."
            )
        else:
            state = "specific_origin"
            if "origin" not in vary_tokens and "*" not in vary_tokens:
                risk = "low"
                notes.append(
                    "Specific origin allowed without 'Vary: Origin', which may cause shared cache issues."
                )
            else:
                notes.append(f"Explicit origin allowed: {origin_val}.")

    return {
        "state": state,
        "risk": risk,
        "allow_origin": acao,
        "allow_credentials": acac,
        "allow_methods": acam,
        "allow_headers": acah,
        "expose_headers": aceh,
        "vary_origin": "origin" in vary_tokens or "*" in vary_tokens,
        "notes": notes,
        "limitations": "Passive inspection of a standard response; dynamic Origin reflection requires active cross-origin preflight testing.",
    }


def inspect_tls_connection(ssl_object, https):
    """Extract negotiated TLS connection details and certificate metadata, distinct from full TLS audit."""
    if not https:
        return {
            "summary": "Not applicable (HTTP)",
            "certificate": None,
            "connection": {
                "applicable": False,
                "protocol": None,
                "cipher_suite": None,
                "cipher_bits": None,
                "certificate_verified": False,
                "audit_scope": "none",
            },
        }
    if not ssl_object:
        return {
            "summary": "Certificate verified; TLS details unavailable",
            "certificate": None,
            "connection": {
                "applicable": True,
                "protocol": None,
                "cipher_suite": None,
                "cipher_bits": None,
                "certificate_verified": True,
                "audit_scope": "single_connection_only",
                "limitations": "Socket stream did not expose ssl_object metadata; full cipher/protocol enumeration was not performed.",
            },
        }

    cipher = ssl_object.cipher()
    proto = ssl_object.version()
    cipher_name = cipher[0] if cipher else "unknown cipher"
    cipher_bits = cipher[2] if cipher and len(cipher) > 2 else None
    summary = f"{proto} / {cipher_name} (certificate verified)"

    peer = ssl_object.getpeercert() or {}
    not_before = peer.get("notBefore")
    not_after = peer.get("notAfter")
    days_remaining = None
    expiring_soon = False
    if not_after:
        try:
            expiry_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=datetime.timezone.utc
            )
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            days_remaining = (expiry_dt - now_dt).days
            expiring_soon = days_remaining <= 30
        except ValueError:
            pass

    fp_sha1 = None
    fp_sha256 = None
    fp_sha512 = None
    try:
        der_bytes = ssl_object.getpeercert(binary_form=True)
        if der_bytes:
            fp_sha1 = ":".join(f"{b:02X}" for b in hashlib.sha1(der_bytes).digest())
            fp_sha256 = ":".join(f"{b:02X}" for b in hashlib.sha256(der_bytes).digest())
            fp_sha512 = ":".join(f"{b:02X}" for b in hashlib.sha512(der_bytes).digest())
    except Exception:
        pass

    san_raw = peer.get("subjectAltName", []) or []
    san_dns_names = [val for kind, val in san_raw if kind == "DNS"]

    certificate = {
        "subject": peer.get("subject"),
        "issuer": peer.get("issuer"),
        "serial_number": peer.get("serialNumber"),
        "version": peer.get("version"),
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "expiring_soon": expiring_soon,
        "subject_alt_names": san_raw,
        "san_dns_names": san_dns_names,
        "fingerprint_sha1": fp_sha1,
        "fingerprint_sha256": fp_sha256,
        "fingerprint_sha512": fp_sha512,
        "ocsp": list(peer.get("OCSP", ()) or ()),
        "ca_issuers": list(peer.get("caIssuers", ()) or ()),
        "crl_distribution_points": list(peer.get("crlDistributionPoints", ()) or ()),
    }

    return {
        "summary": summary,
        "certificate": certificate,
        "connection": {
            "applicable": True,
            "protocol": proto,
            "cipher_suite": cipher_name,
            "cipher_bits": cipher_bits,
            "certificate_verified": True,
            "audit_scope": "single_connection_only",
            "limitations": "Describes only the single TLS session negotiated by Python's SSL library; does not enumerate deprecated protocols (SSLv3/TLS1.0/1.1), weak ciphers, or revocation status (OCSP/CRL).",
        },
    }


def fingerprint_technologies(headers, cookies, content, scripts=None, whatweb_plugins=None):
    """Identify and merge technologies passively by canonical name with combined evidence and confidence."""
    techs = {}
    rank = {"low": 1, "medium": 2, "high": 3}

    def record(name, category, confidence, evidence, version=None):
        clean_name = (name or "").strip()
        if not clean_name:
            return
        key = clean_name.lower()
        entry = techs.get(key)
        if not entry:
            techs[key] = {
                "name": clean_name,
                "category": category,
                "categories": [category],
                "version": version,
                "confidence": confidence,
                "evidence_items": [evidence],
                "evidence": evidence,
                "verified": False,
                "note": "Passive fingerprint/banner claim; version strings alone are not proof of a vulnerability.",
            }
            return

        if category not in entry["categories"]:
            entry["categories"].append(category)
            entry["category"] = ", ".join(entry["categories"])
        if evidence and evidence not in entry["evidence_items"]:
            entry["evidence_items"].append(evidence)
            entry["evidence"] = "; ".join(entry["evidence_items"])
        if version and not entry.get("version"):
            entry["version"] = version
        if rank.get(confidence, 1) > rank.get(entry["confidence"], 1):
            entry["confidence"] = confidence

    server = headers.get("server")
    if server:
        ver_match = re.search(r"([A-Za-z0-9._-]+?)(?:/(\d[\w.-]*))?(?:\s|$)", server.strip())
        srv_name = ver_match.group(1) if ver_match else server.strip()
        srv_ver = ver_match.group(2) if ver_match else None
        record(srv_name, "web_server", "medium", f"Server header: {server}", version=srv_ver)

    powered = headers.get("x-powered-by")
    if powered:
        ver_match = re.search(r"([A-Za-z0-9._-]+?)(?:/(\d[\w.-]*))?(?:\s|$)", powered.strip())
        p_name = ver_match.group(1) if ver_match else powered.strip()
        p_ver = ver_match.group(2) if ver_match else None
        record(p_name, "framework_runtime", "medium", f"X-Powered-By header: {powered}", version=p_ver)

    if "cf-ray" in headers or (server and "cloudflare" in server.lower()):
        record(
            "Cloudflare",
            "cdn_waf",
            "high" if "cf-ray" in headers else "medium",
            "Cloudflare response headers (cf-ray / Server)",
        )
    if "x-vercel-id" in headers or (server and "vercel" in server.lower()):
        record(
            "Vercel",
            "hosting_cdn",
            "high" if "x-vercel-id" in headers else "medium",
            "Vercel edge headers",
        )
    if "x-amz-cf-id" in headers or "x-amz-request-id" in headers:
        record("AWS CloudFront / S3", "hosting_cdn", "high", "AWS response headers")
    if "x-fastly-request-id" in headers or "fastly-restarts" in headers:
        record("Fastly", "cdn_waf", "high", "Fastly response headers")

    vary_hdr = (headers.get("vary") or "").lower()
    if "x-inertia" in vary_hdr or "x-inertia" in headers:
        record("Inertia.js", "frontend_framework", "high", "Response header: Vary: X-Inertia")

    alt_svc = headers.get("alt-svc") or ""
    if "h3=" in alt_svc.lower():
        record("HTTP/3 (QUIC)", "transport_protocol", "high", f"Alt-Svc header advertises HTTP/3 ({alt_svc.split(',')[0].strip()})")

    link_hdr = headers.get("link") or ""
    if "/build/assets/" in link_hdr.lower():
        record("Vite / Laravel Vite", "frontend_bundler", "high", "Link preload header references /build/assets/ bundle")

    cookie_names = {c["name"].lower() for c in (cookies or [])}
    if "phpsessid" in cookie_names:
        record("PHP", "framework_runtime", "medium", "Cookie name: PHPSESSID")
    if "jsessionid" in cookie_names:
        record("Java Servlet / Jakarta EE", "framework_runtime", "medium", "Cookie name: JSESSIONID")
    if "asp.net_sessionid" in cookie_names or ".aspnetcore.session" in cookie_names:
        record("ASP.NET", "framework_runtime", "medium", "Cookie name: ASP.NET session cookie")
    if "csrftoken" in cookie_names or "sessionid" in cookie_names:
        record("Django (candidate)", "framework_runtime", "low", "Cookie naming pattern (csrftoken/sessionid)")
    if "laravel_session" in cookie_names or "xsrf-token" in cookie_names or any(n.endswith("-session") for n in cookie_names):
        has_both = "xsrf-token" in cookie_names and ("laravel_session" in cookie_names or any(n.endswith("-session") for n in cookie_names))
        record(
            "Laravel" if has_both else "Laravel (candidate)",
            "framework_runtime",
            "high" if has_both else "low",
            "Cookie naming pattern (XSRF-TOKEN + *-session / laravel_session)",
        )

    html_data = (content or {}).get("html") or {}
    generator = html_data.get("generator_claim")
    if generator:
        ver_match = re.search(r"([A-Za-z0-9._\s-]+?)\s+(\d+\.\d+[\w.-]*)", generator.strip())
        if ver_match:
            record(
                ver_match.group(1).strip(),
                "cms_generator",
                "medium",
                f"Meta generator: {generator}",
                version=ver_match.group(2),
            )
        else:
            record(generator.strip(), "cms_generator", "low", f"Meta generator: {generator}")

    all_scripts = list(html_data.get("scripts") or [])
    if scripts and isinstance(scripts, dict):
        for s in scripts.get("results", []):
            if s.get("url"):
                all_scripts.append(s["url"])

    for s_url in all_scripts:
        low_url = s_url.lower()
        if "/wp-content/" in low_url or "/wp-includes/" in low_url:
            record("WordPress", "cms_generator", "high", f"Asset path: {redact_url(s_url)}")
        if "/_next/static/" in low_url:
            record("Next.js", "frontend_framework", "high", f"Asset path: {redact_url(s_url)}")
        if "/_nuxt/" in low_url:
            record("Nuxt.js", "frontend_framework", "high", f"Asset path: {redact_url(s_url)}")
        if "/build/assets/" in low_url:
            record("Vite / Laravel Vite", "frontend_bundler", "high", f"Asset path: {redact_url(s_url)}")
        elif re.search(r"/assets/(?:index|app)-[a-za-z0-9_-]{6,}\.js", low_url):
            record("Vite / Rollup SPA bundle", "frontend_bundler", "medium", f"Hashed bundle path: {redact_url(s_url)}")
        jq = re.search(r"jquery[.-](\d+\.\d+\.\d+)", low_url)
        if jq:
            record("jQuery", "javascript_library", "medium", f"Script URL: {redact_url(s_url)}", version=jq.group(1))

    for plugin in whatweb_plugins or []:
        p_name = plugin.get("name")
        if p_name:
            record(
                p_name,
                "whatweb_plugin",
                plugin.get("confidence", "medium"),
                f"WhatWeb: {plugin.get('detail') or p_name}",
                version=plugin.get("version"),
            )

    return list(techs.values())
