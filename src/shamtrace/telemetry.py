"""Extended infrastructure telemetry: IP geolocation/ASN, WAF detection, HSTS/security matrix, and fast TCP port probing."""
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import re
import socket
import urllib.request
import json

COMMON_SERVICE_PORTS = (
    (21, "ftp"),
    (22, "ssh"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (110, "pop3"),
    (143, "imap"),
    (443, "https"),
    (587, "submission"),
    (993, "imaps"),
    (995, "pop3s"),
    (3000, "http-dev"),
    (3306, "mysql"),
    (5432, "postgresql"),
    (8000, "http-alt"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
)


def inspect_ip_location(resolved_ips, proxy=None, timeout=2.5):
    """Lookup geolocation, ISP, ASN, timezone, and coordinates for the first public target IP."""
    if proxy:
        return {"status": "skipped", "reason": "Proxy/Tor routing active; external GeoIP lookup skipped."}
    if not resolved_ips:
        return {"status": "skipped", "reason": "No resolved IP addresses available."}

    public_ip = None
    for candidate in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(candidate)
            if not (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                public_ip = candidate
                break
        except ValueError:
            continue

    if not public_ip:
        return {"status": "skipped", "reason": "Target resolves to a private, loopback, or reserved IP address."}

    req_timeout = min(float(timeout or 2.5), 3.0)
    try:
        req = urllib.request.Request(
            f"https://ipwho.is/{public_ip}",
            headers={"User-Agent": "ShamTrace/0.2.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=req_timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if data.get("success") is not False and data.get("country"):
            conn = data.get("connection") or {}
            tz = data.get("timezone") or {}
            curr = data.get("currency") or {}
            return {
                "status": "completed",
                "ip": public_ip,
                "city": data.get("city"),
                "region": data.get("region"),
                "regionCode": data.get("region_code"),
                "country": data.get("country"),
                "countryCode": data.get("country_code"),
                "continent": data.get("continent"),
                "postCode": data.get("postal"),
                "coords": {
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                },
                "isp": conn.get("isp") or conn.get("org"),
                "org": conn.get("org"),
                "asn": f"AS{conn.get('asn')}" if conn.get("asn") else None,
                "ispDomain": conn.get("domain"),
                "timezone": tz.get("id") if isinstance(tz, dict) else tz,
                "utcOffset": tz.get("utc") if isinstance(tz, dict) else None,
                "currency": curr.get("name") if isinstance(curr, dict) else None,
                "currencyCode": curr.get("code") if isinstance(curr, dict) else None,
                "countryDomain": data.get("tld"),
            }
    except Exception as err:
        return {"status": "failed", "ip": public_ip, "reason": f"GeoIP lookup unavailable: {err}"}

    return {"status": "failed", "ip": public_ip, "reason": "GeoIP service returned no location record."}


def inspect_firewall(headers, cookies=None):
    """Detect WAF / Security Edge indicators passively from HTTP headers and cookie names."""
    waf_vendors = []
    evidence = []

    server = (headers.get("server") or "").lower()
    cookie_names = {c.get("name", "").lower() for c in (cookies or [])}

    if "cf-ray" in headers or "cloudflare" in server or "__cf_bm" in cookie_names:
        waf_vendors.append("Cloudflare WAF / Edge")
        evidence.append("cf-ray / Cloudflare header or __cf_bm cookie")
    if "x-sucuri-id" in headers or "x-sucuri-cache" in headers or "sucuri" in server:
        waf_vendors.append("Sucuri CloudProxy WAF")
        evidence.append("Sucuri headers / Server banner")
    if "x-iinfo" in headers or any(c.startswith(("incap_ses_", "visid_incap_")) for c in cookie_names):
        waf_vendors.append("Imperva Incapsula WAF")
        evidence.append("Imperva X-Iinfo header or incap_ses cookie")
    if "x-amzn-waf-action" in headers or ("x-amz-cf-id" in headers and "awselb" in server):
        waf_vendors.append("AWS WAF / CloudFront")
        evidence.append("AWS WAF / CloudFront headers")
    if "x-akamai-transformed" in headers or "akamaighost" in server or "ak_bmsc" in cookie_names:
        waf_vendors.append("Akamai Kona Site Defender")
        evidence.append("Akamai headers or ak_bmsc cookie")
    if "mod_security" in server or "modsecurity" in server or "nyob" in headers:
        waf_vendors.append("ModSecurity WAF")
        evidence.append("Server banner advertises ModSecurity")
    if any(c.startswith("ts") and len(c) >= 8 for c in cookie_names) and "bigip" in server:
        waf_vendors.append("F5 BIG-IP ASM")
        evidence.append("F5 BIG-IP cookies/banner")
    if "imunify360" in server or "x-imunify360" in headers:
        waf_vendors.append("Imunify360 WAF")
        evidence.append("Imunify360 header/banner")

    return {
        "hasWaf": len(waf_vendors) > 0,
        "wafVendors": waf_vendors,
        "evidence": evidence,
        "note": (
            f"Detected {', '.join(waf_vendors)}."
            if waf_vendors
            else "No explicit WAF signature observed in passive headers (silent or host-level WAFs such as Imunify360/ModSecurity may still operate without banner disclosure)."
        ),
    }


def inspect_http_security_matrix(headers, https):
    """Build quick boolean security matrix and HSTS preload compatibility summary."""
    hsts_raw = headers.get("strict-transport-security")
    xfo_raw = headers.get("x-frame-options")
    xcto_raw = headers.get("x-content-type-options")
    csp_raw = headers.get("content-security-policy")
    xxp_raw = headers.get("x-xss-protection")
    ref_raw = headers.get("referrer-policy")
    perm_raw = headers.get("permissions-policy")

    csp_has_frame_ancestors = bool(csp_raw and "frame-ancestors" in csp_raw.lower())

    http_security = {
        "strictTransportPolicy": bool(hsts_raw and "max-age=" in hsts_raw.lower() and "max-age=0" not in hsts_raw.lower()),
        "xFrameOptions": bool(xfo_raw or csp_has_frame_ancestors),
        "xContentTypeOptions": bool(xcto_raw and xcto_raw.strip().lower() == "nosniff"),
        "contentSecurityPolicy": bool(csp_raw and csp_raw.strip()),
        "referrerPolicy": bool(ref_raw and ref_raw.strip()),
        "permissionsPolicy": bool(perm_raw and perm_raw.strip()),
        "xXSSProtection": bool(xxp_raw and xxp_raw.strip() not in {"", "0"}),
    }

    hsts_info = {
        "present": bool(hsts_raw),
        "hstsHeader": hsts_raw,
        "maxAge": None,
        "includeSubDomains": False,
        "preload": False,
        "compatible": False,
        "message": "No Strict-Transport-Security header advertised.",
    }
    if hsts_raw:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts_raw, re.I)
        max_age = int(m.group(1)) if m else 0
        inc_sub = "includesubdomains" in hsts_raw.lower()
        preload = "preload" in hsts_raw.lower()
        compatible = bool(https and max_age >= 31536000 and inc_sub and preload)
        missing_parts = []
        if max_age < 31536000:
            missing_parts.append("max-age >= 31536000 (1 year)")
        if not inc_sub:
            missing_parts.append("includeSubDomains")
        if not preload:
            missing_parts.append("preload")
        if compatible:
            msg = "HSTS header meets hstspreload.org requirements (max-age >= 1 year, includeSubDomains, preload)."
        else:
            msg = f"HSTS active (max-age={max_age}), but not HSTS-preload ready (missing: {', '.join(missing_parts)})."
        hsts_info = {
            "present": True,
            "hstsHeader": hsts_raw,
            "maxAge": max_age,
            "includeSubDomains": inc_sub,
            "preload": preload,
            "compatible": compatible,
            "message": msg,
        }

    return http_security, hsts_info


def probe_common_ports(resolved_ips, timeout=1.0, proxy=None, shared_edge=None, allow_shared_ip=False):
    """Fast concurrent TCP connect probe on common service ports for in-scope dedicated targets."""
    if proxy:
        return {"status": "skipped", "reason": "Proxy/Tor routing active; direct TCP port probing disabled.", "openPorts": [], "failedPorts": []}
    if not resolved_ips:
        return {"status": "skipped", "reason": "No resolved IP address.", "openPorts": [], "failedPorts": []}

    target_ip = resolved_ips[0]
    try:
        ip_obj = ipaddress.ip_address(target_ip)
        if ip_obj.is_loopback or ip_obj.is_private:
            return {"status": "skipped", "reason": "Local/private IP; common port sweep skipped unless --nmap-ports specified.", "openPorts": [], "failedPorts": []}
    except ValueError:
        return {"status": "skipped", "reason": "Invalid IP literal.", "openPorts": [], "failedPorts": []}

    if shared_edge and shared_edge.get("is_shared_edge") and not allow_shared_ip:
        provider = shared_edge.get("provider") or "shared CDN/cloud edge"
        return {
            "status": "skipped",
            "reason": f"Target resolves to shared {provider} IP ({target_ip}); common port probe skipped unless --allow-shared-ip is passed.",
            "openPorts": [],
            "failedPorts": [],
        }

    sock_timeout = min(float(timeout or 1.0), 1.2)

    def check_port(item):
        port, service = item
        try:
            with socket.create_connection((target_ip, port), timeout=sock_timeout):
                return port, service, True
        except OSError:
            return port, service, False

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(check_port, COMMON_SERVICE_PORTS))

    open_ports = [p for p, _, is_open in results if is_open]
    open_details = [{"port": p, "service": srv} for p, srv, is_open in results if is_open]
    failed_ports = [p for p, _, is_open in results if not is_open]

    return {
        "status": "completed",
        "targetIp": target_ip,
        "openPorts": open_ports,
        "openDetails": open_details,
        "failedPorts": failed_ports,
    }
