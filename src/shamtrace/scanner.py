import math
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
import httpx
from rich.text import Text
from . import __version__ as VERSION
from .checks import (
    validate_target,
    assess_headers,
    inspect_cookies,
    inspect_cors,
    inspect_tls_connection,
    fingerprint_technologies,
    detect_shared_edge,
    redact_sensitive,
    redact_url,
)
from .display import console, show_report
from .reports import save_reports
from .content import inspect_document, build_findings
from .dns_checks import inspect_dns, inspect_dns_blocklists
from .discovery import inspect_metadata, inspect_scripts
from .assessment import assess
from .network import network_options, RateLimiter, stream_within_scope
from .crawl import inspect_pages
from .edge import inspect_edge
from .advisories import identify_components, lookup_advisories
from .policies import policy_findings, normalize_findings, deduplicate_findings
from .external_tools import parse_ports, run_whatweb, run_nmap
from .telemetry import (
    inspect_ip_location,
    inspect_firewall,
    inspect_http_security_matrix,
    probe_common_ports,
)
from .vuln_checks import inspect_exposures, evaluate_passive_vulnerabilities


def _build_inventory(final_url, content, pages_report, scripts_report, metadata_endpoints):
    html_doc = (content or {}).get("html") or {}
    links = list(pages_report.get("link_sources") or [
        {"url": redact_url(u), "source": redact_url(final_url)}
        for u in html_doc.get("same_origin_links", [])
    ])
    forms = list(pages_report.get("form_sources") or [
        {"method": f["method"], "action": redact_url(f["action"]), "source": redact_url(final_url)}
        for f in html_doc.get("forms", [])
    ])
    scripts = list(pages_report.get("script_sources") or [
        {"url": redact_url(s), "source": redact_url(final_url)}
        for s in html_doc.get("scripts", [])
    ])
    endpoint_candidates = []
    seen_Hints = set()
    for s_item in (scripts_report or {}).get("results", []):
        src = redact_url(s_item.get("url", final_url))
        for hint in s_item.get("api_path_hints", []):
            if (hint, src) not in seen_Hints:
                seen_Hints.add((hint, src))
                endpoint_candidates.append({"path": hint, "source": f"script:{src}"})
    for m_item in metadata_endpoints or []:
        val = m_item.get("validation") or {}
        if val.get("state") == "recognized":
            src = redact_url(m_item.get("url", final_url))
            for disallow in (val.get("directives") or {}).get("disallow", []):
                if disallow and (disallow, src) not in seen_Hints:
                    seen_Hints.add((disallow, src))
                    endpoint_candidates.append({"path": disallow, "source": f"robots:{src}"})
    return {
        "links": links,
        "forms": forms,
        "scripts": scripts,
        "endpoint_candidates": endpoint_candidates,
    }


def scan(args):
    if math.isnan(args.timeout) or not 0 < args.timeout <= 120:
        raise ValueError("Timeout must be greater than 0 and at most 120 seconds.")
    page_budget = getattr(args, "pages", 1)
    if not 1 <= page_budget <= 10:
        raise ValueError("--pages must be between 1 and 10.")
    retries = getattr(args, "retries", 0)
    if not 0 <= retries <= 3:
        raise ValueError("--retries must be between 0 and 3.")
    rate_limit = getattr(args, "rate_limit", 0.0)
    if math.isnan(rate_limit) or not 0.0 <= rate_limit <= 50.0:
        raise ValueError("--rate-limit must be between 0 and 50 requests/second.")
    concurrency = getattr(args, "concurrency", 4)
    if not 1 <= concurrency <= 16:
        raise ValueError("--concurrency must be between 1 and 16.")
    max_requests = getattr(args, "max_requests", 25)
    if not 1 <= max_requests <= 100:
        raise ValueError("--max-requests must be between 1 and 100.")
    max_duration = getattr(args, "max_duration", 180.0)
    if math.isnan(max_duration) or not 1.0 <= max_duration <= 600.0:
        raise ValueError("--max-duration must be between 1 and 600 seconds.")
    nmap_ports = getattr(args, "nmap_ports", None)
    if nmap_ports:
        parse_ports(nmap_ports)

    target, parsed = validate_target(args.url)
    profile = getattr(args, "profile", "basic")
    proxy = getattr(args, "proxy", None)
    if getattr(args, "require_proxy", False) and not proxy:
        raise ValueError("--require-proxy needs --tor or --proxy. No network requests were made.")
    network = network_options(parsed, proxy)
    follow_scoped_redirects = not getattr(args, "no_follow_redirects", False)
    rate_limiter = RateLimiter(rate_limit)

    started = time.monotonic()
    deadline = started + max_duration
    modules = {}

    console.print(
        f"Scope: {profile} profile • in-scope redirects {'enabled' if follow_scoped_redirects else 'disabled'} • TLS verification enabled\n",
        style="dim",
    )

    with console.status("[cyan][1/7] Running DNS checks..."):
        if profile == "extended" and not proxy:
            try:
                dns_report = inspect_dns(
                    parsed.hostname,
                    min(args.timeout, 5),
                    concurrency=concurrency,
                    retries=retries,
                )
                dns_status = dns_report.get("status", "complete")
                if dns_status == "complete":
                    modules["dns"] = {
                        "status": "completed",
                        "detail": f"Queried {len(dns_report.get('queries', []))} DNS record types.",
                    }
                elif dns_status == "skipped":
                    modules["dns"] = {"status": "skipped", "detail": dns_report.get("reason", "Skipped.")}
                else:
                    modules["dns"] = {"status": "failed", "detail": "All DNS queries timed out or failed."}
            except Exception as err:
                dns_report = {"status": "failed", "reason": str(err), "queries": []}
                modules["dns"] = {"status": "failed", "detail": f"DNS check error: {err}"}
        else:
            reason = "Proxy routing disables local target DNS." if proxy else "Not requested (basic profile; use --profile extended)."
            dns_report = {"status": "skipped", "reason": reason}
            modules["dns"] = {"status": "skipped", "detail": reason}

    with console.status("[cyan][2/7] Resolving target hostname..."):
        addresses = (
            []
            if proxy
            else sorted({
                item[4][0]
                for item in socket.getaddrinfo(
                    parsed.hostname,
                    parsed.port or (443 if parsed.scheme == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
            })
        )

    report = None
    headers = httpx.Headers()
    cookies = []
    content = {"bytes_inspected": 0, "truncated": False, "sha256_inspected_bytes": "", "html": None}
    edge = {"skip_followup": True, "reason": "Initial request incomplete."}
    final_url = target
    redirect_info = {"followed": False, "hops": 0, "chain": []}

    try:
        with httpx.Client(
            timeout=args.timeout,
            **({"proxy": proxy} if proxy else {}),
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent": f"ShamTrace/{VERSION}",
                "Accept": "*/*",
            },
        ) as client:
            with console.status("[cyan][3/7] Inspecting HTTP response, TLS, headers, cookies, and CORS..."):
                req_t0 = time.monotonic()
                with stream_within_scope(
                    client,
                    target,
                    target,
                    follow_scoped_redirects=follow_scoped_redirects,
                    max_redirects=min(5, max(0, max_requests - 1)),
                    retries=retries,
                    rate_limiter=rate_limiter,
                ) as (response, final_url, redirect_info):
                    http_response_time_ms = round((time.monotonic() - req_t0) * 1000, 2)
                    final_parsed = urlsplit(final_url)
                    is_https = final_parsed.scheme == "https"
                    headers = response.headers

                    ssl_object = None
                    if is_https:
                        stream = response.extensions.get("network_stream")
                        ssl_object = stream.get_extra_info("ssl_object") if stream else None

                    tls_info = inspect_tls_connection(ssl_object, is_https)
                    tls = tls_info["summary"]
                    certificate = tls_info["certificate"]

                    modules["http"] = {
                        "status": "completed",
                        "detail": f"HTTP {response.status_code} from {redact_sensitive(final_url)} ({http_response_time_ms} ms)",
                    }
                    modules["tls"] = (
                        {
                            "status": "completed",
                            "detail": f"{tls} (single connection; not a full cipher/protocol audit)",
                        }
                        if is_https
                        else {"status": "skipped", "detail": "Target uses cleartext HTTP."}
                    )

                    edge = inspect_edge(headers, response.status_code)
                    content = inspect_document(response, final_url)
                    assessed_headers = assess_headers(headers, is_https)
                    cookies = inspect_cookies(headers)
                    cors = inspect_cors(headers, final_url)
                    http_security, hsts_info = inspect_http_security_matrix(headers, is_https)
                    firewall_info = inspect_firewall(headers, cookies)
                    social_tags = (content.get("html") or {}).get("social_tags") or {}

                    if edge["skip_followup"]:
                        modules["headers_cookies_cors"] = {
                            "status": "skipped",
                            "detail": edge["reason"],
                        }
                    else:
                        modules["headers_cookies_cors"] = {
                            "status": "completed",
                            "detail": f"Evaluated {len(assessed_headers)} security headers, {len(cookies)} cookie(s), and CORS ({cors['state']}).",
                        }

                    report = {
                        "schema_version": "1.8",
                        "partial": False,
                        "network": network,
                        "edge": edge,
                        "profile": profile,
                        "status": {
                            "isUp": 200 <= response.status_code < 500,
                            "responseTimeMs": http_response_time_ms,
                            "responseCode": response.status_code,
                        },
                        "location": {"status": "skipped", "reason": "Not requested (basic profile)."},
                        "firewall": firewall_info,
                        "http_security": http_security,
                        "hsts": hsts_info,
                        "social_tags": social_tags,
                        "dns": dns_report,
                        "blocklists": {"status": "skipped", "blocklists": []},
                        "ports": {"status": "skipped", "openPorts": [], "failedPorts": []},
                        "certificate": certificate,
                        "tls_connection": tls_info["connection"],
                        "cors": cors,
                        "redirect_info": redirect_info,
                        "final_url": final_url,
                        "content": content,
                        "tool": "ShamTrace",
                        "version": VERSION,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "target": target,
                        "resolved_ips": addresses,
                        "http_status": response.status_code,
                        "http_version": response.http_version,
                        "tls": tls,
                        "server": headers.get("server"),
                        "powered_by": headers.get("x-powered-by"),
                        "redirect_location": headers.get("location"),
                        "headers": assessed_headers,
                        "cookies": cookies,
                        "metadata_endpoints": [],
                        "exposures": {"status": "skipped", "probes_checked": 0, "exposed_count": 0, "results": [], "findings": []},
                        "scripts": {"results": []},
                        "pages": {"results": []},
                        "fingerprints": [],
                        "components": [],
                        "advisories": {"provider": "OSV", "status": "disabled", "requests": 0, "results": []},
                        "external_tools": {},
                        "elapsed_seconds": round(time.monotonic() - started, 2),
                        "limitations": [
                            "In-scope redirects are followed up to 5 hops; out-of-scope redirects are blocked. HTML traversal follows the --pages budget; extended adds three metadata requests and up to three scripts.",
                            "Document inspection is capped at 512 KiB of decoded content; no JavaScript execution.",
                            "HTML observations describe source markup, not browser runtime behavior.",
                            "Header values and policies are passively evaluated; application context is required.",
                            "Missing headers are hardening observations, not proof of an exploitable vulnerability.",
                            "Server, framework, and generator banners are unverified claims and never proof of CVEs.",
                            "TLS reports the single negotiated connection and certificate, not all server-supported protocols or ciphers.",
                            "Cookie flags require context; non-sensitive preference cookies may intentionally omit HttpOnly.",
                            "DNS lists resolution results, not a verified connected peer.",
                            "The timeout applies to network operations, not a hard whole-scan deadline.",
                            "Sensitive tokens, authentication headers, and cookie values are redacted.",
                        ],
                    }

            used_requests = 1 + int(redirect_info.get("hops", 0))

            with console.status("[cyan][4/7] Inspecting metadata endpoints and static scripts..."):
                if time.monotonic() >= deadline or used_requests >= max_requests:
                    report["partial"] = True
                    modules["metadata"] = {"status": "skipped", "detail": "Skipped due to scan request/duration budget."}
                    modules["scripts"] = {"status": "skipped", "detail": "Skipped due to scan request/duration budget."}
                elif profile == "extended" and not edge["skip_followup"]:
                    try:
                        report["metadata_endpoints"] = inspect_metadata(
                            client,
                            final_url,
                            content["sha256_inspected_bytes"],
                            retries=retries,
                            rate_limiter=rate_limiter,
                        )
                        used_requests += len(report["metadata_endpoints"])
                        meta_errors = sum(1 for e in report["metadata_endpoints"] if e.get("status") == "error")
                        modules["metadata"] = {
                            "status": "failed" if meta_errors == len(report["metadata_endpoints"]) else "completed",
                            "detail": f"Checked {len(report['metadata_endpoints'])} metadata paths ({meta_errors} error(s)).",
                        }
                    except Exception as err:
                        modules["metadata"] = {"status": "failed", "detail": f"Metadata inspection failed: {err}"}

                    scripts = list((content.get("html") or {}).get("scripts", []))
                    script_budget = max(0, min(3, max_requests - used_requests))
                    try:
                        report["scripts"] = inspect_scripts(
                            client,
                            final_url,
                            scripts,
                            max_scripts=script_budget,
                            retries=retries,
                            rate_limiter=rate_limiter,
                        )
                        script_results = report["scripts"].get("results", [])
                        used_requests += len(script_results)
                        script_errors = sum(1 for s in script_results if s.get("state") == "error")
                        modules["scripts"] = {
                            "status": "failed" if (script_results and script_errors == len(script_results)) else "completed",
                            "detail": f"Inspected {len(script_results)} same-origin script(s) ({report['scripts'].get('scripts_discovered', 0)} discovered).",
                        }
                    except Exception as err:
                        modules["scripts"] = {"status": "failed", "detail": f"Script inspection failed: {err}"}
                else:
                    reason = edge["reason"] if edge["skip_followup"] else "Not requested (basic profile; use --profile extended)."
                    modules["metadata"] = {"status": "skipped", "detail": reason}
                    modules["scripts"] = {"status": "skipped", "detail": reason}

            with console.status("[cyan][5/7] Crawling in-scope HTML pages..."):
                if time.monotonic() >= deadline or used_requests >= max_requests:
                    report["partial"] = True
                    modules["crawl"] = {"status": "skipped", "detail": "Skipped due to scan request/duration budget."}
                elif not edge["skip_followup"]:
                    effective_page_budget = min(page_budget, 1 + max(0, max_requests - used_requests))
                    try:
                        report["pages"] = inspect_pages(
                            client,
                            final_url,
                            content,
                            effective_page_budget,
                            retries=retries,
                            rate_limiter=rate_limiter,
                            deadline=deadline,
                        )
                        crawled = report["pages"].get("results", [])
                        used_requests += len(crawled)
                        if page_budget > 1:
                            crawl_errors = sum(1 for p in crawled if p.get("state") == "error")
                            modules["crawl"] = {
                                "status": "failed" if (crawled and crawl_errors == len(crawled)) else "completed",
                                "detail": f"Visited {len(crawled)} additional in-scope page(s) (budget: {page_budget}).",
                            }
                        else:
                            modules["crawl"] = {
                                "status": "skipped",
                                "detail": "Single-page mode (--pages 1); pass --pages 2..10 to crawl same-origin links.",
                            }
                    except Exception as err:
                        modules["crawl"] = {"status": "failed", "detail": f"Crawl module error: {err}"}
                else:
                    modules["crawl"] = {"status": "skipped", "detail": edge["reason"]}

            with console.status("[cyan][6/7] Checking exposures, component inventory, and advisories..."):
                if profile == "extended" and getattr(args, "vuln_scan", False) and not edge["skip_followup"]:
                    exp_budget = max(0, min(10, max_requests - used_requests))
                    if exp_budget > 0 and time.monotonic() < deadline:
                        try:
                            exp_res = inspect_exposures(
                                client,
                                final_url,
                                baseline_hash=content["sha256_inspected_bytes"],
                                max_probes=exp_budget,
                                retries=retries,
                                rate_limiter=rate_limiter,
                                deadline=deadline,
                                time_fn=time.monotonic,
                            )
                            report["exposures"] = exp_res
                            used_requests += exp_res.get("probes_checked", 0) + (
                                1 if (exp_res.get("http_methods") or {}).get("checked") else 0
                            )
                            modules["vuln_exposures"] = {
                                "status": "completed",
                                "detail": (
                                    f"Probed {exp_res.get('probes_checked', 0)} sensitive paths "
                                    f"({exp_res.get('exposed_count', 0)} exposed) & HTTP methods."
                                ),
                            }
                        except Exception as err:
                            modules["vuln_exposures"] = {"status": "failed", "detail": f"Exposure probe failed: {err}"}
                    else:
                        modules["vuln_exposures"] = {
                            "status": "skipped",
                            "detail": "Skipped due to scan request/duration budget.",
                        }
                else:
                    reason = (
                        edge["reason"]
                        if edge["skip_followup"]
                        else "Not requested (use CLI default or --vuln-scan with --profile extended)."
                    )
                    modules["vuln_exposures"] = {"status": "skipped", "detail": reason}

                scripts_initial = list((content.get("html") or {}).get("scripts", []))
                all_discovered_scripts = list(
                    dict.fromkeys(scripts_initial + (report["pages"].get("discovered_scripts") or []))
                )
                report["components"] = [] if edge["skip_followup"] else identify_components(all_discovered_scripts)
                cve_enabled = getattr(args, "cve", False)
                try:
                    report["advisories"] = lookup_advisories(
                        client, report["components"], enabled=cve_enabled
                    )
                    adv_status = report["advisories"].get("status", "disabled")
                    if adv_status in {"disabled", "not_applicable"}:
                        modules["advisories"] = {
                            "status": "skipped",
                            "detail": report["advisories"].get("reason", "Advisory lookup skipped."),
                        }
                    elif adv_status == "complete":
                        modules["advisories"] = {
                            "status": "completed",
                            "detail": f"Queried {report['advisories'].get('requests', 0)} package version(s) via OSV.",
                        }
                    else:
                        modules["advisories"] = {
                            "status": "failed"
                            if all(r.get("status") == "error" for r in report["advisories"].get("results", []))
                            else "completed",
                            "detail": report["advisories"].get("reason", "Partial advisory results."),
                        }
                except Exception as err:
                    modules["advisories"] = {"status": "failed", "detail": f"Advisory lookup error: {err}"}

        with console.status("[cyan][7/7] Running fingerprinting and optional external integrations..."):
            ww_res = run_whatweb(
                final_url,
                timeout=args.timeout,
                enabled=getattr(args, "whatweb", False),
                proxy=proxy,
            )
            modules["whatweb"] = {"status": ww_res["status"], "detail": ww_res.get("reason", "")}

            report["fingerprints"] = (
                []
                if edge["skip_followup"]
                else fingerprint_technologies(
                    headers,
                    cookies,
                    content,
                    report["scripts"],
                    whatweb_plugins=ww_res.get("plugins"),
                )
            )
            modules["fingerprinting"] = (
                {"status": "skipped", "detail": edge["reason"]}
                if edge["skip_followup"]
                else {
                    "status": "completed",
                    "detail": f"Consolidated {len(report['fingerprints'])} unique technology fingerprint(s).",
                }
            )

            shared_edge = detect_shared_edge(addresses, headers, report["fingerprints"])
            report["shared_edge"] = shared_edge
            if profile == "extended" and not proxy:
                report["location"] = inspect_ip_location(
                    addresses,
                    proxy=proxy,
                    timeout=min(args.timeout, 2.5),
                )
                report["blocklists"] = inspect_dns_blocklists(
                    parsed.hostname,
                    timeout=min(args.timeout, 2.0),
                    concurrency=concurrency,
                )
                report["ports"] = probe_common_ports(
                    addresses,
                    timeout=min(args.timeout, 1.0),
                    proxy=proxy,
                    shared_edge=shared_edge,
                    allow_shared_ip=getattr(args, "allow_shared_ip", False),
                )
            nm_res = run_nmap(
                parsed.hostname,
                port_spec=nmap_ports,
                timeout=args.timeout,
                proxy=proxy,
                shared_edge=shared_edge,
                allow_shared_ip=getattr(args, "allow_shared_ip", False),
            )
            report["external_tools"] = {"whatweb": ww_res, "nmap": nm_res}
            modules["nmap"] = {"status": nm_res["status"], "detail": nm_res.get("reason", "")}

    except KeyboardInterrupt:
        if report is not None:
            report["partial"] = True
            for mod_key in ("metadata", "scripts", "crawl", "vuln_exposures", "fingerprinting", "advisories", "whatweb", "nmap"):
                modules.setdefault(
                    mod_key,
                    {"status": "skipped", "detail": "Scan interrupted by user (SIGINT); partial results saved."},
                )
            report["modules"] = modules
            report["inventory"] = _build_inventory(
                final_url, content, report.get("pages", {}), report.get("scripts", {}), report.get("metadata_endpoints", [])
            )
            report["elapsed_seconds"] = round(time.monotonic() - started, 2)
            raw_findings = [] if edge["skip_followup"] else build_findings(report)
            raw_findings += policy_findings(headers, report)
            if not edge["skip_followup"]:
                raw_findings += (report.get("exposures") or {}).get("findings", [])
                raw_findings += evaluate_passive_vulnerabilities(report, headers)
            normalize_findings(raw_findings, final_url)
            report["findings"] = deduplicate_findings(raw_findings)
            report["summary"] = {
                "review_items": len(report["findings"]),
                "requests": 1
                + int(redirect_info.get("hops", 0))
                + len(report["metadata_endpoints"])
                + len(report["scripts"]["results"])
                + len(report["pages"]["results"])
                + (report.get("exposures") or {}).get("probes_checked", 0),
                "assessment": "Partial scan interrupted by user; observations require contextual review.",
            }
            report["assessment"] = assess(report)
            if not (getattr(args, "terminal", False) or getattr(args, "no_save", False)):
                json_path, _ = save_reports(report, args.output)
                console.print(f"\n[yellow]Partial evidence saved to {json_path.parent}[/yellow]")
        raise

    report["modules"] = modules
    report["inventory"] = _build_inventory(
        final_url,
        content,
        report.get("pages", {}),
        report.get("scripts", {}),
        report.get("metadata_endpoints", []),
    )
    report["elapsed_seconds"] = round(time.monotonic() - started, 2)
    raw_findings = [] if edge["skip_followup"] else build_findings(report)
    raw_findings += policy_findings(headers, report)
    if not edge["skip_followup"]:
        raw_findings += (report.get("exposures") or {}).get("findings", [])
        raw_findings += evaluate_passive_vulnerabilities(report, headers)
    normalize_findings(raw_findings, final_url)
    for page in report["pages"]["results"]:
        raw_findings.extend(page.get("findings", []))
    report["findings"] = deduplicate_findings(raw_findings)

    initial_reqs = 1 + int(redirect_info.get("hops", 0))
    exp_reqs = (report.get("exposures") or {}).get("probes_checked", 0) + (
        1 if ((report.get("exposures") or {}).get("http_methods") or {}).get("checked") else 0
    )
    report["summary"] = {
        "review_items": len(report["findings"]),
        "requests": initial_reqs
        + len(report["metadata_endpoints"])
        + len(report["scripts"]["results"])
        + len(report["pages"]["results"])
        + exp_reqs,
        "assessment": "Observations requiring contextual review; no exploit validation.",
    }
    report["assessment"] = assess(report)
    terminal_only = getattr(args, "terminal", False)
    no_save = getattr(args, "no_save", False) or terminal_only
    show_report(report, verbose=getattr(args, "verbose", False) or terminal_only)
    if no_save:
        console.print(f"\nCompleted in {report['elapsed_seconds']}s (terminal-only mode)", style="bold green")
    else:
        json_path, markdown_path = save_reports(report, args.output)
        console.print(f"\nCompleted in {report['elapsed_seconds']}s", style="bold green")
        console.print(Text(f"JSON      {json_path}"))
        console.print(Text(f"Markdown  {markdown_path}"))
        console.print(Text(f"HTML      {json_path.with_suffix('.html')}"))
