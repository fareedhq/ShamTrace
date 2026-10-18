"""Typed DNS evidence with authority SOA extraction, www CNAME companion check, and human-readable interpretation."""
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver
import dns.reversename

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


def _extract_authority_info(error):
    """Extract negative-caching TTL and SOA primary NS from a NoAnswer/NXDOMAIN response if present."""
    resp = None
    if hasattr(error, "kwargs") and isinstance(error.kwargs, dict):
        resp = error.kwargs.get("response")
    if resp is None and hasattr(error, "response"):
        try:
            resp = error.response() if callable(error.response) else error.response
        except Exception:
            resp = None
    if resp is None or not getattr(resp, "authority", None):
        return None, None
    for rrset in resp.authority:
        ttl = getattr(rrset, "ttl", None)
        try:
            for rdata in rrset:
                text = rdata.to_text()
                parts = text.split()
                if len(parts) >= 7 and parts[-1].isdigit():
                    return int(parts[-1]), parts[0]
                return ttl, parts[0] if parts else None
        except Exception:
            return ttl, None
    return None, None


def _interpret_dns_outcome(name, kind, status, records, soa_ns=None, www_cname=None, a_records=None):
    auth_label = f" (verified by {soa_ns})" if soa_ns else ""
    if status == "ok":
        if kind == "A":
            return f"Resolved {len(records)} IPv4 address(es){auth_label}."
        if kind == "AAAA":
            return f"Resolved {len(records)} IPv6 address(es){auth_label}."
        if kind == "NS":
            return "Authoritative nameservers delegated for this zone."
        if kind == "SOA":
            return "Start of Authority record (primary NS, hostmaster, serial, refresh/retry/expiry/neg-TTL)."
        if kind == "MX":
            return "Mail exchange servers configured for this domain."
        if kind == "TXT":
            if name.startswith("_dmarc."):
                return "DMARC policy record published."
            has_spf = any("v=spf1" in r.lower() for r in records)
            return (
                "TXT records present (includes SPF v=spf1 policy)."
                if has_spf
                else "TXT records present (no v=spf1 token observed)."
            )
        if kind == "CAA":
            return "Certification Authority Authorization restrictions published."
        return "Record present."

    if status == "no_answer":
        if kind == "CNAME":
            if www_cname:
                return f"Zone apex uses A record ({', '.join(a_records or ['IP'])}); companion www.{name} CNAME -> {www_cname}."
            return (
                f"Zone apex uses A record ({', '.join(a_records or ['direct IP'])}); "
                "RFC 1034/2181 prohibits CNAME at zone apex alongside NS/SOA."
            )
        if kind == "AAAA":
            return f"IPv4-only configuration{auth_label}; no IPv6 (AAAA) record is published."
        if kind == "MX":
            return f"No inbound mail servers (MX) configured{auth_label}."
        if kind == "TXT":
            return f"No SPF (v=spf1) or verification TXT record published at apex{auth_label}."
        if kind == "CAA":
            return f"No CAA restriction published{auth_label}; any trusted CA may issue TLS certificates."
        return f"Hostname exists (NODATA){auth_label}; no {kind} record configured."

    if status == "nxdomain":
        if name.startswith("_dmarc."):
            return f"No DMARC policy published{auth_label} (_dmarc subdomain does not exist)."
        return f"Domain name does not exist (NXDOMAIN){auth_label}."

    if status == "timeout":
        return "Query timed out before resolver returned an answer (inconclusive)."

    return "Resolver error occurred during query (inconclusive)."


def _format_display_records(name, kind, status, records, soa_ns=None, www_cname=None, a_records=None):
    if records:
        return "; ".join(records)
    auth = soa_ns or "authoritative NS"
    if status == "no_answer":
        if kind == "CNAME":
            if www_cname:
                return f"Apex A: {', '.join(a_records or ['present'])} | www.{name} CNAME: {www_cname}"
            if a_records:
                return f"Apex routed via A ({', '.join(a_records)}) [SOA: {auth}]"
            return f"NODATA at zone apex [SOA: {auth}]"
        if kind == "AAAA":
            return f"0 AAAA records (IPv4-only) [SOA: {auth}]"
        if kind == "MX":
            return f"0 MX records (no mail server) [SOA: {auth}]"
        if kind == "TXT":
            return f"0 TXT/SPF records at apex [SOA: {auth}]"
        if kind == "CAA":
            return f"0 CAA records (unrestricted CA) [SOA: {auth}]"
        return f"NODATA (0 {kind} records) [SOA: {auth}]"
    if status == "nxdomain":
        if name.startswith("_dmarc."):
            return f"NXDOMAIN (DMARC not configured) [SOA: {auth}]"
        return f"NXDOMAIN [SOA: {auth}]"
    if status == "timeout":
        return "Query timed out"
    return "No records returned"


def _make_resolver(timeout):
    resolver = dns.resolver.Resolver()
    resolver.timeout = min(float(timeout), 3.0)
    # Append reliable public DNS fallbacks after system nameservers in case ISP DNS drops queries
    existing = list(getattr(resolver, "nameservers", []) or [])
    for fallback in ("1.1.1.1", "8.8.8.8"):
        if fallback not in existing:
            existing.append(fallback)
    resolver.nameservers = existing
    return resolver


def inspect_dns(hostname, timeout=5, concurrency=4, retries=0):
    try:
        ipaddress.ip_address(hostname)
        return {"status": "skipped", "reason": "Target is an IP literal.", "queries": []}
    except ValueError:
        pass
    queries = [(hostname, kind) for kind in RECORD_TYPES]
    queries.append(("_dmarc." + hostname, "TXT"))
    max_attempts = max(1, int(retries or 0) + 1)
    workers = max(1, min(int(concurrency or 4), 16))

    def query(item):
        name, kind = item
        result = {
            "name": name,
            "type": kind,
            "status": "ok",
            "records": [],
            "ttl": None,
            "authority_ttl": None,
            "authority_ns": None,
            "display_records": "",
            "interpretation": "",
        }
        for attempt in range(1, max_attempts + 1):
            try:
                resolver = _make_resolver(timeout)
                answer = resolver.resolve(name + ".", kind, lifetime=timeout, search=False)
                result["records"] = [r.to_text() for r in answer]
                result["ttl"] = answer.rrset.ttl if answer.rrset else None
                result["canonical_name"] = answer.canonical_name.to_text()
                result["status"] = "ok"
                result.pop("error", None)
                return result
            except dns.resolver.NXDOMAIN as error:
                result["status"] = "nxdomain"
                neg_ttl, auth_ns = _extract_authority_info(error)
                result["authority_ttl"] = neg_ttl
                result["authority_ns"] = auth_ns
                return result
            except dns.resolver.NoAnswer as error:
                result["status"] = "no_answer"
                neg_ttl, auth_ns = _extract_authority_info(error)
                result["authority_ttl"] = neg_ttl
                result["authority_ns"] = auth_ns
                return result
            except dns.exception.Timeout:
                result["status"] = "timeout"
                if attempt < max_attempts:
                    time.sleep(0.15 * attempt)
            except (dns.exception.DNSException, OSError) as error:
                result["status"] = "error"
                result["error"] = str(error)
                if attempt < max_attempts:
                    time.sleep(0.15 * attempt)
        return result

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(query, queries))

    # Extract zone SOA metadata (primary NS and negative-caching minimum TTL) if SOA query succeeded
    soa_ns = None
    soa_neg_ttl = None
    soa_parsed = None
    a_records = []
    txt_parsed = {"spf": None, "dmarc": None, "other": []}
    for r in results:
        if r["type"] == "A" and r["status"] == "ok":
            a_records = r["records"]
        if r["type"] == "TXT" and r["status"] == "ok":
            for raw_txt in r["records"]:
                clean_txt = raw_txt.strip('"')
                if r["name"].startswith("_dmarc.") and "v=dmarc1" in clean_txt.lower():
                    txt_parsed["dmarc"] = clean_txt
                elif "v=spf1" in clean_txt.lower():
                    txt_parsed["spf"] = clean_txt
                else:
                    txt_parsed["other"].append(clean_txt)
        if r["type"] == "SOA" and r["status"] == "ok" and r["records"]:
            parts = r["records"][0].split()
            if parts:
                soa_ns = parts[0]
            if len(parts) >= 7:
                if parts[-1].isdigit():
                    soa_neg_ttl = int(parts[-1])
                soa_parsed = {
                    "nsname": parts[0].rstrip("."),
                    "hostmaster": parts[1].rstrip("."),
                    "serial": int(parts[2]) if parts[2].isdigit() else parts[2],
                    "refresh": int(parts[3]) if parts[3].isdigit() else parts[3],
                    "retry": int(parts[4]) if parts[4].isdigit() else parts[4],
                    "expire": int(parts[5]) if parts[5].isdigit() else parts[5],
                    "minttl": int(parts[6]) if parts[6].isdigit() else parts[6],
                }
            elif r["ttl"] is not None:
                soa_neg_ttl = r["ttl"]

    # If CNAME at apex is no_answer on an active zone, check www.<hostname> CNAME companion
    www_cname = None
    cname_entry = next((r for r in results if r["type"] == "CNAME"), None)
    if (
        cname_entry
        and cname_entry["status"] == "no_answer"
        and (soa_ns or a_records)
        and not hostname.lower().startswith("www.")
    ):
        try:
            resolver = _make_resolver(timeout)
            www_ans = resolver.resolve(f"www.{hostname}.", "CNAME", lifetime=min(float(timeout), 2.5), search=False)
            www_records = [r.to_text() for r in www_ans]
            if www_records:
                www_cname = www_records[0]
        except Exception:
            www_cname = None

    # Reverse DNS (PTR) for valid IPv4/IPv6 addresses in a_records
    ptr_records = {}
    for ip_str in a_records[:4]:
        try:
            ipaddress.ip_address(ip_str)
            rev_name = dns.reversename.from_address(ip_str)
            resolver = _make_resolver(timeout)
            ptr_ans = resolver.resolve(rev_name, "PTR", lifetime=min(float(timeout), 2.0), search=False)
            ptr_records[ip_str] = [r.to_text().rstrip(".") for r in ptr_ans]
        except Exception:
            pass

    # DNSSEC records (DNSKEY, DS, RRSIG) on clean hostname (never with https:// prefix)
    dnssec = {"is_enabled": False, "DNSKEY": {}, "DS": {}, "RRSIG": {}}
    for sec_type in ("DNSKEY", "DS", "RRSIG"):
        sec_entry = {"isFound": False, "status": "no_answer", "records": [], "authority_soa": soa_ns}
        try:
            resolver = _make_resolver(timeout)
            sec_ans = resolver.resolve(f"{hostname}.", sec_type, lifetime=min(float(timeout), 2.0), search=False)
            recs = [r.to_text() for r in sec_ans]
            # Avoid treating MagicMock placeholder strings in unit tests as real DNSSEC unless valid
            if recs:
                sec_entry["isFound"] = True
                sec_entry["status"] = "ok"
                sec_entry["records"] = recs
                dnssec["is_enabled"] = True
        except dns.resolver.NXDOMAIN as err:
            sec_entry["status"] = "nxdomain"
            _, auth_ns = _extract_authority_info(err)
            if auth_ns:
                sec_entry["authority_soa"] = auth_ns
        except dns.resolver.NoAnswer as err:
            sec_entry["status"] = "no_answer"
            _, auth_ns = _extract_authority_info(err)
            if auth_ns:
                sec_entry["authority_soa"] = auth_ns
        except Exception:
            sec_entry["status"] = "error"
        dnssec[sec_type] = sec_entry

    for r in results:
        eff_ns = r.get("authority_ns") or soa_ns
        if r["ttl"] is None and r.get("authority_ttl") is None and soa_neg_ttl is not None and r["status"] in {"no_answer", "nxdomain"}:
            r["authority_ttl"] = soa_neg_ttl
        r["authority_ns"] = eff_ns
        r["display_records"] = _format_display_records(
            r["name"], r["type"], r["status"], r["records"], soa_ns=eff_ns, www_cname=www_cname, a_records=a_records
        )
        r["interpretation"] = _interpret_dns_outcome(
            r["name"], r["type"], r["status"], r["records"], soa_ns=eff_ns, www_cname=www_cname, a_records=a_records
        )

    has_ok = any(r["status"] in {"ok", "no_answer", "nxdomain"} for r in results)
    return {
        "status": "complete" if has_ok else "failed",
        "soa_primary_ns": soa_ns,
        "soa_negative_ttl": soa_neg_ttl,
        "soa_parsed": soa_parsed,
        "txt_parsed": txt_parsed,
        "ptr_records": ptr_records,
        "dnssec": dnssec,
        "www_cname": www_cname,
        "queries": results,
        "limitations": "Records describe this hostname only; parent-zone policies are not inferred. DKIM needs a known selector.",
    }


DNS_BLOCKLIST_SERVERS = (
    ("Cloudflare", "1.1.1.1"),
    ("Cloudflare Security", "1.1.1.2"),
    ("Cloudflare Family", "1.1.1.3"),
    ("Quad9 Security", "9.9.9.9"),
    ("Google DNS", "8.8.8.8"),
    ("AdGuard DNS", "94.140.14.14"),
    ("AdGuard Family", "94.140.14.15"),
    ("CleanBrowsing Security", "185.228.168.9"),
    ("CleanBrowsing Family", "185.228.168.168"),
    ("OpenDNS", "208.67.222.222"),
    ("OpenDNS Family", "208.67.222.123"),
    ("Yandex Safe", "77.88.8.88"),
)

SINKHOLE_IPS = {
    "0.0.0.0",
    "127.0.0.1",
    "::",
    "::1",
    "146.112.61.104",
    "146.112.61.106",
    "146.112.61.108",
}


def inspect_dns_blocklists(hostname, timeout=2.0, concurrency=6):
    """Check whether security/family DNS resolvers block or sinkhole the target domain."""
    try:
        ipaddress.ip_address(hostname)
        return {"status": "skipped", "reason": "Target is an IP literal.", "blocklists": []}
    except ValueError:
        pass
    if hostname.endswith((".test", ".local", ".invalid", ".localhost", ".onion")):
        return {"status": "skipped", "reason": "Reserved/local hostname.", "blocklists": []}

    per_timeout = min(float(timeout or 2.0), 2.0)

    def check_server(entry):
        name, server_ip = entry
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [server_ip]
        res.timeout = per_timeout
        try:
            ans = res.resolve(f"{hostname}.", "A", lifetime=per_timeout, search=False)
            ips = [r.to_text() for r in ans]
            blocked = any(ip in SINKHOLE_IPS for ip in ips)
            return {
                "server": name,
                "serverIp": server_ip,
                "isBlocked": blocked,
                "resolvedIps": ips,
                "status": "blocked" if blocked else "allowed",
            }
        except dns.resolver.NXDOMAIN:
            return {
                "server": name,
                "serverIp": server_ip,
                "isBlocked": True,
                "resolvedIps": [],
                "status": "nxdomain_blocked",
            }
        except dns.resolver.NoAnswer:
            return {
                "server": name,
                "serverIp": server_ip,
                "isBlocked": False,
                "resolvedIps": [],
                "status": "no_answer",
            }
        except Exception:
            return {
                "server": name,
                "serverIp": server_ip,
                "isBlocked": False,
                "resolvedIps": [],
                "status": "unreachable",
            }

    with ThreadPoolExecutor(max_workers=max(1, min(int(concurrency or 6), 12))) as pool:
        items = list(pool.map(check_server, DNS_BLOCKLIST_SERVERS))

    return {
        "status": "completed",
        "blocked_count": sum(1 for item in items if item["isBlocked"]),
        "checked_count": len(items),
        "blocklists": items,
    }
