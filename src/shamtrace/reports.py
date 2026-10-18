"""Offline Cyber-Tech HUD HTML report, Markdown report, JSON export, and report regeneration from JSON."""
import html
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from .checks import redact_sensitive
from .dns_checks import _format_display_records, _interpret_dns_outcome


def _build_dns_rows(dns_report):
    queries = (dns_report or {}).get("queries") or []
    soa_ns = (dns_report or {}).get("soa_primary_ns")
    soa_neg_ttl = (dns_report or {}).get("soa_negative_ttl")
    www_cname = (dns_report or {}).get("www_cname")
    a_records = []
    for q in queries:
        if q.get("type") == "A" and q.get("status") == "ok":
            a_records = q.get("records") or []
        if q.get("type") == "SOA" and q.get("status") == "ok" and q.get("records"):
            parts = q["records"][0].split()
            if parts and not soa_ns:
                soa_ns = parts[0]
            if len(parts) >= 7 and parts[-1].isdigit() and soa_neg_ttl is None:
                soa_neg_ttl = int(parts[-1])

    rows = []
    for q in queries:
        ttl_val = q.get("ttl")
        auth_ttl = q.get("authority_ttl")
        if auth_ttl is None and ttl_val is None and soa_neg_ttl is not None and q.get("status") in {"no_answer", "nxdomain"}:
            auth_ttl = soa_neg_ttl
        if ttl_val is not None:
            ttl_display = str(ttl_val)
        elif auth_ttl is not None:
            ttl_display = f"{auth_ttl} (SOA neg-TTL)"
        else:
            ttl_display = "—"

        eff_ns = q.get("authority_ns") or soa_ns
        disp_rec = q.get("display_records") or _format_display_records(
            q["name"], q["type"], q["status"], q.get("records") or [], soa_ns=eff_ns, www_cname=www_cname, a_records=a_records
        )
        interp = q.get("interpretation") or _interpret_dns_outcome(
            q["name"], q["type"], q["status"], q.get("records") or [], soa_ns=eff_ns, www_cname=www_cname, a_records=a_records
        )
        rows.append([
            f"{q['name']} / {q['type']}",
            q["status"],
            ttl_display,
            disp_rec,
            interp,
        ])
    return rows


def _flatten_x509_name(name_tuples):
    if not name_tuples:
        return "-"
    if isinstance(name_tuples, dict):
        return ", ".join(f"{k}={v}" for k, v in name_tuples.items())
    parts = []
    try:
        for rdn in name_tuples:
            for k, v in rdn:
                parts.append(f"{k}={v}")
    except Exception:
        return str(name_tuples)
    return ", ".join(parts) if parts else "-"


def plain(value):
    value = redact_sensitive(value)
    if value is None:
        return "Not available"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def esc(value):
    return html.escape(plain(value), quote=True)


def md_cell(value):
    value = html.escape(plain(value))
    return (
        re.sub(r"([\\`*_{}\[\]])", r"\\\1", value)
        .replace("|", r"\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def sections(report):
    assessment = report.get("assessment", {})
    network = report.get("network", {})
    modules = report.get("modules", {})
    cors = report.get("cors", {})
    tls_conn = report.get("tls_connection", {})
    inventory = report.get("inventory", {})

    inv_rows = []
    for item in inventory.get("links", [])[:25]:
        inv_rows.append(["link", item.get("url"), item.get("source"), "In-scope HTML link"])
    for item in inventory.get("forms", [])[:25]:
        inv_rows.append([
            f"form ({item.get('method', 'GET')})",
            item.get("action"),
            item.get("source"),
            "HTML form action",
        ])
    for item in inventory.get("scripts", [])[:25]:
        inv_rows.append(["script", item.get("url"), item.get("source"), "Public script reference"])
    for item in inventory.get("endpoint_candidates", [])[:30]:
        inv_rows.append([
            "endpoint_candidate",
            item.get("path"),
            item.get("source"),
            "Static string hint (unverified)",
        ])

    status_info = report.get("status") or {}
    loc_info = report.get("location") or {}
    fw_info = report.get("firewall") or {}
    hsts_info = report.get("hsts") or {}
    social_tags = report.get("social_tags") or ((report.get("content") or {}).get("html") or {}).get("social_tags") or {}

    scope_rows = [
        ["Target", report["target"]],
        ["Final URL (in-scope)", report.get("final_url", report["target"])],
        ["Time (UTC)", report["timestamp"]],
        ["Profile", report.get("profile", "basic")],
        ["Scan completion", "Partial (interrupted/budget reached)" if report.get("partial") else "Complete"],
        ["HTTP status", f"{report['http_status']} ({status_info.get('responseTimeMs')} ms)" if status_info.get("responseTimeMs") is not None else report["http_status"]],
        ["TLS connection (negotiated)", report["tls"]],
        ["TLS audit scope", tls_conn.get("audit_scope", "single_connection_only")],
        ["Server claim", report.get("server")],
        ["WAF / Firewall detection", ", ".join(fw_info.get("wafVendors") or []) if fw_info.get("hasWaf") else fw_info.get("note", "No explicit WAF signature")],
        ["HSTS preload status", hsts_info.get("message") or ("Present" if hsts_info.get("present") else "Not advertised")],
        ["Resolved IPs", ", ".join(report["resolved_ips"]) or "Skipped / unavailable"],
    ]
    if loc_info.get("status") == "completed":
        coords = loc_info.get("coords") or {}
        scope_rows.extend([
            ["Geolocation", f"{loc_info.get('city') or '-'}, {loc_info.get('region') or '-'}, {loc_info.get('country') or '-'} ({loc_info.get('countryCode') or '-'})"],
            ["ISP / Organization / ASN", f"{loc_info.get('isp') or '-'} / {loc_info.get('org') or '-'} ({loc_info.get('asn') or '-'})"],
            ["Coordinates / Timezone / Currency", f"{coords.get('latitude')}, {coords.get('longitude')} | {loc_info.get('timezone') or '-'} | {loc_info.get('currency') or '-'} ({loc_info.get('currencyCode') or '-'})"],
        ])
    if social_tags:
        scope_rows.append([
            "Social & Document Meta",
            f"title={social_tags.get('title')!r}, viewport={social_tags.get('viewport')!r}, favicon={social_tags.get('favicon')!r}",
        ])
    scope_rows.extend([
        ["Route", network.get("route", "direct")],
        [
            "Privacy",
            "SOCKS routing; anonymity not verified"
            if network.get("route") == "socks-proxy"
            else "Direct connection: target sees your network egress address",
        ],
        ["Target requests", report.get("summary", {}).get("requests")],
        ["Advisory requests", report.get("advisories", {}).get("requests", 0)],
    ])

    result = [
        ("Executive assessment", ["Conclusion"], [[v] for v in assessment.get("conclusions", [])]),
        (
            "Scope, infrastructure, and transport",
            ["Item", "Evidence"],
            scope_rows,
        ),
        (
            "Module status",
            ["Module", "Status", "Detail"],
            [
                [name, info.get("status", "skipped"), info.get("detail", "")]
                for name, info in modules.items()
            ],
        ),
        (
            "Findings requiring review",
            [
                "Finding / URL",
                "Classification",
                "Severity & Rationale",
                "Confidence",
                "Evidence",
                "Limitations",
                "Remediation",
            ],
            [
                [
                    f.get("title", f["id"])
                    + " — "
                    + ", ".join(f.get("affected_urls", [f.get("affected_url", report["target"])])),
                    f.get("classification", "configuration_observation"),
                    f"{f.get('severity', 'info').upper()}: {f.get('severity_rationale', '')}",
                    f.get("confidence", "high"),
                    f.get("evidence"),
                    f.get("limitations", "Passive observation only."),
                    f.get("remediation", f.get("recommendation", "")),
                ]
                for f in report.get("findings", [])
            ],
        ),
        (
            "Discovery inventory",
            ["Artifact Type", "URL / Path", "Discovery Source", "Notes"],
            inv_rows,
        ),
        (
            "Technology fingerprints (unverified claims)",
            ["Technology", "Category", "Version", "Confidence", "Evidence", "Caveat"],
            [
                [
                    t["name"],
                    t["category"],
                    t.get("version") or "Unspecified",
                    t["confidence"],
                    t["evidence"],
                    t.get("note", "Version banner alone is not CVE proof."),
                ]
                for t in report.get("fingerprints", [])
            ],
        ),
        (
            "DNS evidence",
            ["Name / type", "State", "TTL", "Records / Authority Response", "Interpretation"],
            _build_dns_rows(report.get("dns", {})),
        ),
        (
            "HTTP header evidence",
            ["Header", "State", "Quality", "Value", "Evaluation"],
            [
                [
                    v["header"],
                    v["state"],
                    v.get("quality", v["state"]),
                    v["value"],
                    v.get("evaluation", v.get("purpose", "")),
                ]
                for v in report["headers"]
            ],
        ),
        (
            "CORS configuration",
            ["Field", "Observation"],
            [
                ["State", cors.get("state", "not_advertised")],
                ["Access-Control-Allow-Origin", cors.get("allow_origin")],
                ["Access-Control-Allow-Credentials", cors.get("allow_credentials")],
                ["Access-Control-Allow-Methods", cors.get("allow_methods")],
                ["Vary includes Origin", cors.get("vary_origin")],
                ["Notes", "; ".join(cors.get("notes", [])) or "No CORS headers advertised."],
                ["Limitations", cors.get("limitations")],
            ]
            if cors
            else [],
        ),
        (
            "Metadata validation",
            ["URL", "HTTP", "Result", "Explanation"],
            [
                [
                    e["url"],
                    e.get("http_status"),
                    e["validation"]["state"],
                    e["validation"]["reason"],
                ]
                for e in report.get("metadata_endpoints", [])
            ],
        ),
        (
            "Cookie metadata (values excluded)",
            ["Name", "Prefix", "Prefix Valid", "Secure", "HttpOnly", "SameSite"],
            [
                [
                    c["name"],
                    c.get("prefix", "none"),
                    c.get("prefix_valid", True),
                    c["secure"],
                    c["httponly"],
                    c["samesite"],
                ]
                for c in report["cookies"]
            ],
        ),
        (
            "Component inventory",
            ["Package", "Version", "Confidence", "Evidence"],
            [
                [c["name"], c["version"], c["confidence"], c["evidence"]]
                for c in report.get("components", [])
            ],
        ),
    ]
    advisories = report.get("advisories", {})
    rows = [
        [
            advisories.get("status", "not_run"),
            advisories.get("reason", "Package-version matching; exploitability unverified."),
            "",
            "",
        ]
    ]
    for item in advisories.get("results", []):
        component = item["component"]
        for advisory in item["advisories"]:
            rows.append([
                f"{component['name']}@{component['version']}",
                advisory["id"],
                ", ".join(advisory["aliases"]),
                advisory["summary"],
            ])
        if not item["advisories"]:
            rows.append([
                f"{component['name']}@{component['version']}",
                item["status"],
                "",
                item.get("reason", "No advisory match returned; this is not proof of safety."),
            ])
    result.append(("Advisory / CVE candidates", ["Package / status", "Advisory", "Aliases", "Summary"], rows))
    result.append((
        "Script evidence",
        ["URL", "Result", "Bytes / truncated", "Unverified API paths"],
        [
            [
                s["url"],
                s["state"],
                f"{s.get('content', {}).get('bytes_inspected', 0)} / {s.get('content', {}).get('truncated', False)}",
                s.get("api_path_hints", []),
            ]
            for s in report.get("scripts", {}).get("results", [])
        ],
    ))
    result.append((
        "Discovered pages",
        ["URL", "HTTP", "State", "Title"],
        [
            [
                p["url"],
                p.get("http_status"),
                p["state"],
                (p.get("content", {}).get("html") or {}).get("title"),
            ]
            for p in report.get("pages", {}).get("results", [])
        ],
    ))
    certificate = report.get("certificate") or {}
    result.append(("Certificate evidence", ["Field", "Value"], [[k, v] for k, v in certificate.items()]))

    dns_extra = report.get("dns") or {}
    dnssec = dns_extra.get("dnssec") or {}
    ptr_records = dns_extra.get("ptr_records") or {}
    if dnssec or ptr_records:
        d_rows = []
        for ip_k, ptr_v in ptr_records.items():
            d_rows.append([f"PTR ({ip_k})", "ok", ", ".join(ptr_v)])
        for sec_k in ("DNSKEY", "DS", "RRSIG"):
            sec_item = dnssec.get(sec_k) or {}
            if sec_item:
                d_rows.append([
                    f"DNSSEC / {sec_k}",
                    sec_item.get("status", "no_answer"),
                    "; ".join(sec_item.get("records") or []) or f"Not published (Authority SOA: {sec_item.get('authority_soa') or '-'})",
                ])
        if d_rows:
            result.append(("DNSSEC & Reverse DNS (PTR)", ["Check", "Status", "Records / Authority"], d_rows))

    blocklists = (report.get("blocklists") or {}).get("blocklists") or []
    if blocklists:
        result.append((
            "DNS Security & Family Blocklists",
            ["Provider", "Resolver IP", "Blocked", "Resolved IPs / Status"],
            [
                [
                    b.get("server"),
                    b.get("serverIp"),
                    b.get("isBlocked"),
                    ", ".join(b.get("resolvedIps") or []) or b.get("status"),
                ]
                for b in blocklists
            ],
        ))

    exposures = report.get("exposures") or {}
    if exposures.get("results"):
        exp_rows = []
        http_m = exposures.get("http_methods") or {}
        if http_m.get("checked"):
            exp_rows.append([
                "OPTIONS / (HTTP Methods)",
                http_m.get("http_status"),
                "warning" if http_m.get("dangerous_methods") else "ok",
                "Allowed: " + (", ".join(http_m.get("allowed_methods") or []) or "Not advertised")
                + (f" | Dangerous: {', '.join(http_m['dangerous_methods'])}" if http_m.get("dangerous_methods") else ""),
            ])
        for e_item in exposures.get("results", []):
            exp_rows.append([
                e_item.get("path"),
                e_item.get("http_status"),
                e_item.get("state"),
                e_item.get("reason"),
            ])
        result.append((
            "Sensitive Path & Exposure Probes",
            ["Path / Check", "HTTP", "State", "Verification Detail"],
            exp_rows,
        ))

    ports_probe = report.get("ports") or {}
    if ports_probe.get("status") == "completed":
        open_details = ports_probe.get("openDetails") or []
        open_str = ", ".join(f"{d['port']}/{d['service']}" for d in open_details) or "None"
        closed_str = ", ".join(str(p) for p in (ports_probe.get("failedPorts") or [])) or "None"
        result.append((
            "TCP Service Port Probe",
            ["Target IP", "Open Ports", "Closed / Filtered Ports"],
            [[ports_probe.get("targetIp"), open_str, closed_str]],
        ))

    external = report.get("external_tools") or {}
    whatweb = external.get("whatweb") or {}
    if whatweb:
        ww_rows = [[whatweb.get("status", "skipped"), whatweb.get("reason", ""), "", ""]]
        for p in whatweb.get("plugins", []):
            ww_rows.append([p.get("name"), p.get("version"), p.get("confidence"), p.get("detail")])
        result.append(("WhatWeb integration", ["Plugin / Status", "Version / Reason", "Confidence", "Detail"], ww_rows))

    nmap = external.get("nmap") or {}
    if nmap:
        nm_rows = [[nmap.get("status", "skipped"), nmap.get("reason", ""), "", ""]]
        for p in nmap.get("ports", []):
            nm_rows.append([
                f"{p.get('port')}/{p.get('protocol')}",
                p.get("state"),
                p.get("service"),
                f"{p.get('product') or ''} {p.get('version') or ''}".strip() or "Not advertised",
            ])
        result.append((
            "Nmap scoped port scan",
            ["Port / Status", "State / Reason", "Service", "Banner claim (non-CVE)"],
            nm_rows,
        ))

    result.append(("Coverage gaps", ["Not established"], [[v] for v in assessment.get("coverage_gaps", [])]))
    result.append(("Limitations", ["Interpretation"], [[v] for v in report.get("limitations", [])]))
    return result


def _render_findings_html(findings, default_target):
    from .vuln_checks import enrich_finding_taxonomy
    if not findings:
        return (
            '<div class="empty-note">No findings recorded for this response. '
            "<strong>Note:</strong> Zero findings or skipped modules do not establish that the target is free of vulnerabilities.</div>"
        )
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1

    filter_bar = (
        '<input type="radio" name="sev-filter" id="sev-all" class="filter-radio" checked>'
        '<input type="radio" name="sev-filter" id="sev-high" class="filter-radio">'
        '<input type="radio" name="sev-filter" id="sev-medium" class="filter-radio">'
        '<input type="radio" name="sev-filter" id="sev-low" class="filter-radio">'
        '<input type="radio" name="sev-filter" id="sev-info" class="filter-radio">'
        '<input type="radio" name="cls-filter" id="cls-all" class="filter-radio" checked>'
        '<input type="radio" name="cls-filter" id="cls-verified" class="filter-radio">'
        '<input type="radio" name="cls-filter" id="cls-candidate" class="filter-radio">'
        '<input type="radio" name="cls-filter" id="cls-config" class="filter-radio">'
        '<div class="hud-filter-bar">'
        '<div class="filter-group"><span class="label">SEVERITY FILTER</span>'
        f'<label for="sev-all" class="filter-chip">All ({len(findings)})</label>'
        f'<label for="sev-high" class="filter-chip chip-high">High ({counts["high"]})</label>'
        f'<label for="sev-medium" class="filter-chip chip-medium">Medium ({counts["medium"]})</label>'
        f'<label for="sev-low" class="filter-chip chip-low">Low ({counts["low"]})</label>'
        f'<label for="sev-info" class="filter-chip chip-info">Info ({counts["info"]})</label>'
        "</div>"
        '<div class="filter-group"><span class="label">CLASSIFICATION</span>'
        '<label for="cls-all" class="filter-chip">All Types</label>'
        '<label for="cls-verified" class="filter-chip">Verified</label>'
        '<label for="cls-candidate" class="filter-chip">Candidate</label>'
        '<label for="cls-config" class="filter-chip">Config / Ops</label>'
        "</div></div>"
    )

    cards = []
    for idx, raw_f in enumerate(findings, start=1):
        f = enrich_finding_taxonomy(dict(raw_f))
        sev = (f.get("severity") or "info").lower()
        cls = (f.get("classification") or "configuration_observation").lower()
        cls_label = cls.replace("_", " ").title()
        sev_badge = f'<span class="badge sev-{esc(sev)}">&bull; {esc(sev.upper())}</span>'
        cwe_badge = f'<span class="badge conf">{esc(f.get("cwe", "CWE-200"))}</span>'
        cvss_val = f.get("cvss_score", 0.0)
        cvss_badge = f'<span class="badge conf">CVSS {esc(cvss_val)}</span>' if cvss_val else ""
        conf_badge = f'<span class="badge conf">{esc((f.get("confidence") or "high").title())} Confidence</span>'
        cls_badge = f'<span class="badge cls-badge">{esc(cls_label)} &bull; {esc(f.get("owasp", "OWASP A05"))}</span>'
        urls = f.get("affected_urls") or [f.get("affected_url") or default_target]
        urls_html = ", ".join(f"<code>{esc(u)}</code>" for u in urls)
        cards.append(
            f'<article class="finding-card sev-border-{esc(sev)} sev-card-{esc(sev)} cls-card-{esc(cls)}">'
            f'<div class="finding-head">'
            f'<div><span class="hud-index">#{idx:04d}</span><h3>{esc(f.get("title", f.get("id")))}</h3></div>'
            f'<div class="badges">{sev_badge}{cwe_badge}{cvss_badge}{cls_badge}{conf_badge}</div></div>'
            f'<div class="finding-summary">'
            f'<div><span class="label">Affected URL(s) ({len(urls)})</span><p>{urls_html}</p></div>'
            f'<div><span class="label">Severity Rationale</span><p>{esc(f.get("severity_rationale", ""))}</p></div>'
            f'<div><span class="label">Remediation</span><p>{esc(f.get("remediation", f.get("recommendation", "")))}</p></div>'
            f"</div>"
            f'<details class="hud-drawer" open>'
            f'<summary>EVIDENCE &amp; LIMITATION TELEMETRY</summary>'
            f'<div class="finding-grid">'
            f'<div><span class="label">Supporting Evidence</span><pre class="evidence-box">{esc(f.get("evidence"))}</pre></div>'
            f'<div><span class="label">Limitations &amp; False-Positive Context</span><p>{esc(f.get("limitations", ""))}</p></div>'
            f"</div></details></article>"
        )
    return filter_bar + '<div class="findings-list">' + "".join(cards) + "</div>"


def _render_modules_html(modules):
    if not modules:
        return ""
    rows = []
    for idx, (name, info) in enumerate(modules.items(), start=1):
        st = (info.get("status") or "skipped").lower()
        rows.append(
            f"<tr>"
            f'<td class="mono-id">#{idx:02d}</td>'
            f'<td><strong>{esc(name)}</strong></td>'
            f'<td><span class="badge st-{esc(st)}">&bull; {esc(st.title())}</span></td>'
            f"<td>{esc(info.get('detail', ''))}</td>"
            f"</tr>"
        )
    return (
        '<section id="sec-modules" class="panel-card">'
        '<div class="panel-header"><div class="panel-title"><span class="sec-tag">01 //</span> MODULE EXECUTION TELEMETRY</div>'
        '<span class="panel-more">&bull;&bull;&bull;</span></div>'
        '<div class="panel-body"><div class="scroll"><table><thead><tr>'
        "<th>ID</th><th>MODULE</th><th>STATUS</th><th>EXECUTION DETAIL</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></div></section>"
    )


def build_report_texts(report):
    """Build sanitized JSON, Markdown, and Enterprise SaaS Dashboard HTML strings for a report dictionary."""
    sanitized_report = redact_sensitive(report)
    lines = ["# ShamTrace assessment", ""]
    blocks = []

    blocks.append(_render_modules_html(sanitized_report.get("modules", {})))
    blocks.append(
        '<section id="sec-findings" class="panel-card">'
        '<div class="panel-header"><div class="panel-title"><span class="sec-tag">02 //</span> DEDUPLICATED FINDINGS &amp; OBSERVATIONS</div>'
        '<span class="panel-more">&bull;&bull;&bull;</span></div>'
        '<div class="panel-body">'
        + _render_findings_html(sanitized_report.get("findings", []), sanitized_report.get("target", ""))
        + "</div></section>"
    )

    sec_num = 3
    for title, columns, rows in sections(sanitized_report):
        lines += ["## " + title, ""]
        if not rows:
            rows = [["No evidence collected in this section."] + [""] * (len(columns) - 1)]
        lines += [
            "| " + " | ".join(columns) + " |",
            "| " + " | ".join(["---"] * len(columns)) + " |",
        ]
        lines += ["| " + " | ".join(md_cell(v) for v in row) + " |" for row in rows]
        lines += [""]

        if title == "Findings requiring review":
            continue

        sec_id = "sec-" + re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        head = "".join("<th>" + esc(v) + "</th>" for v in columns)
        body = "".join(
            "<tr>" + "".join("<td>" + esc(v) + "</td>" for v in row) + "</tr>"
            for row in rows
        )
        blocks.append(
            f'<section id="{esc(sec_id)}" class="panel-card">'
            f'<div class="panel-header"><div class="panel-title"><span class="sec-tag">{sec_num:02d} //</span> {esc(title.upper())}</div>'
            f'<span class="panel-more">&bull;&bull;&bull;</span></div>'
            f'<div class="panel-body"><div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div></div></section>'
        )
        sec_num += 1

    inv = sanitized_report.get("inventory") or {}
    pages_count = 1 + len((sanitized_report.get("pages") or {}).get("results", []))
    scripts_count = len((sanitized_report.get("scripts") or {}).get("results", []))
    endpoints_count = len(inv.get("endpoint_candidates", []))
    modules = sanitized_report.get("modules") or {}
    completed_mods = sum(1 for m in modules.values() if m.get("status") == "completed")
    total_mods = len(modules) or 1
    findings_list = sanitized_report.get("findings") or []
    fps = sanitized_report.get("fingerprints") or []
    loc_info = sanitized_report.get("location") or {}
    status_info = sanitized_report.get("status") or {}
    http_sec = sanitized_report.get("http_security") or {}
    dns_queries = (sanitized_report.get("dns") or {}).get("queries") or []
    dns_ok = sum(1 for q in dns_queries if q.get("status") == "ok")

    resp_ms = status_info.get("responseTimeMs")
    latency_str = f"{resp_ms} ms" if resp_ms is not None else f"{sanitized_report.get('elapsed_seconds', 0)}s"
    target_url = sanitized_report.get("target", "")
    timestamp_short = str(sanitized_report.get("timestamp", ""))[:10] or "Today"

    # Mini vertical sparkline SVG for the 4 top KPI cards
    def _spark_svg(active_idx=2):
        bars = []
        heights = [14, 22, 30, 18, 25]
        for i, h in enumerate(heights):
            x = 4 + i * 7
            y = 32 - h
            color = "#18181b" if i == active_idx else "#d4d4d0"
            bars.append(f'<rect x="{x}" y="{y}" width="3" height="{h}" rx="1.5" fill="{color}"/>')
        return f'<svg width="40" height="34" viewBox="0 0 40 34" fill="none">{"".join(bars)}</svg>'

    # 4 Top KPI Cards matching the reference dashboard
    kpi_cards = (
        '<div class="kpi-grid">'
        # KPI 1: HTTP Status & Latency
        '<div class="kpi-card"><div class="kpi-top"><div>'
        '<span class="kpi-label">HTTP STATUS &amp; LATENCY</span>'
        f'<div class="kpi-val">{esc(sanitized_report.get("http_status"))} <small>{esc(latency_str)}</small></div>'
        f"</div>{_spark_svg(2)}</div>"
        f'<div class="kpi-foot"><span class="info-dot">TLS</span><span class="kpi-delta">{esc("Verified" if "verified" in str(sanitized_report.get("tls", "")).lower() else "Inspected")}</span></div></div>'
        # KPI 2: Review Findings
        '<div class="kpi-card"><div class="kpi-top"><div>'
        '<span class="kpi-label">REVIEW FINDINGS</span>'
        f'<div class="kpi-val">{len(findings_list)} <small>Items</small></div>'
        f"</div>{_spark_svg(1)}</div>"
        f'<div class="kpi-foot"><span class="info-dot">STACK</span><span class="kpi-delta">{len(fps)} Tech Fingerprints</span></div></div>'
        # KPI 3: Modules Completed
        '<div class="kpi-card"><div class="kpi-top"><div>'
        '<span class="kpi-label">MODULES COMPLETED</span>'
        f'<div class="kpi-val">{completed_mods} / {total_mods} <small>Active</small></div>'
        f"</div>{_spark_svg(3)}</div>"
        f'<div class="kpi-foot"><span class="info-dot">MODE</span><span class="kpi-delta">Profile: {esc(sanitized_report.get("profile", "extended"))}</span></div></div>'
        # KPI 4: Surface Coverage
        '<div class="kpi-card"><div class="kpi-top"><div>'
        '<span class="kpi-label">SURFACE REQUESTS</span>'
        f'<div class="kpi-val">{esc(sanitized_report.get("summary", {}).get("requests", 1))} <small>Req</small></div>'
        f"</div>{_spark_svg(4)}</div>"
        f'<div class="kpi-foot"><span class="info-dot">SCOPE</span><span class="kpi-delta">{pages_count} Page(s) &bull; { len(dns_queries) } DNS</span></div></div>'
        "</div>"
    )

    # Left Analytics Panel: Telemetry Matrix Chart (waffle/block chart like SALES TREND)
    mod_cols = [
        ("DNS", len(dns_queries) or 2, dns_ok or 1),
        ("HTTP", 8, 6),
        ("TLS", 7, 5 if "verified" in str(sanitized_report.get("tls", "")).lower() else 1),
        ("HDRS", 8, sum(1 for h in sanitized_report.get("headers", []) if h.get("state") == "present")),
        ("COOK", 6, len(sanitized_report.get("cookies") or []) or 1),
        ("CORS", 5, 3 if (sanitized_report.get("cors") or {}).get("state") != "not_advertised" else 1),
        ("META", 6, len(sanitized_report.get("metadata_endpoints") or []) or 1),
        ("SCRP", 7, scripts_count or 1),
        ("CRWL", 6, pages_count),
        ("TECH", 8, min(8, len(fps) or 2)),
        ("PORT", 7, min(7, len((sanitized_report.get("ports") or {}).get("openPorts") or []) or 1)),
        ("FIND", 9, min(9, len(findings_list) or 1)),
    ]
    matrix_cols_html = []
    for label_col, total_blk, active_blk in mod_cols:
        cells = []
        for r_idx in range(10, 0, -1):
            cls_cell = "cell-dark" if r_idx <= active_blk else ("cell-mid" if r_idx <= total_blk else "cell-empty")
            cells.append(f'<span class="m-cell {cls_cell}"></span>')
        matrix_cols_html.append(
            f'<div class="m-col"><div class="m-stack">{"".join(cells)}</div><span class="m-label">{label_col}</span></div>'
        )

    # Right Analytics Panel: Security Controls Breakdown vertical bar chart
    sec_controls = [
        ("HSTS", 85 if http_sec.get("strictTransportPolicy") else 20),
        ("CSP", 88 if http_sec.get("contentSecurityPolicy") else 25),
        ("XFO", 80 if http_sec.get("xFrameOptions") else 22),
        ("XCTO", 90 if http_sec.get("xContentTypeOptions") else 20),
        ("REF", 78 if http_sec.get("referrerPolicy") else 24),
        ("PERM", 75 if http_sec.get("permissionsPolicy") else 18),
        ("TLS", 92 if "verified" in str(sanitized_report.get("tls", "")).lower() else 30),
        ("DNS", 82 if dns_ok > 0 else 28),
    ]
    active_ctrl_count = sum(1 for _, pct in sec_controls if pct >= 50)
    vbars_html = []
    for ctrl_name, pct in sec_controls:
        vbars_html.append(
            f'<div class="vbar-col" title="{ctrl_name}: {pct}%">'
            f'<div class="vbar-track"><div class="vbar-fill" style="height:{pct}%"></div></div>'
            f'<span class="vbar-lbl">{ctrl_name}</span></div>'
        )

    loc_badge = (
        f"{loc_info.get('city') or '-'}, {loc_info.get('countryCode') or '-'}"
        if loc_info.get("status") == "completed"
        else (", ".join(sanitized_report.get("resolved_ips") or []) or "Direct")
    )

    analytics_row = (
        '<div class="analytics-grid">'
        # Left Card: Telemetry & Surface Matrix
        '<div class="panel-card">'
        '<div class="panel-header"><div class="panel-title">TELEMETRY &amp; SURFACE MATRIX</div>'
        '<span class="panel-more">&bull;&bull;&bull;</span></div>'
        '<div class="panel-body">'
        '<div class="chart-top-bar">'
        f'<div><span class="muted-sm">Target Origin :</span> <strong class="chart-big-num">{esc(target_url)}</strong></div>'
        '<div class="chart-legend"><span class="leg-item"><i class="dot-mid"></i> DISCOVERED</span><span class="leg-item"><i class="dot-dark"></i> VERIFIED / ACTIVE</span></div>'
        '<div class="seg-tabs"><span class="seg-tab">Basic</span><span class="seg-tab active">Extended</span><span class="seg-tab">Scoped</span></div>'
        "</div>"
        f'<div class="matrix-chart">{"".join(matrix_cols_html)}</div>'
        "</div></div>"
        # Right Card: Security Posture Breakdown
        '<div class="panel-card">'
        '<div class="panel-header"><div class="panel-title">SECURITY POSTURE BREAKDOWN</div>'
        '<span class="panel-more">&bull;&bull;&bull;</span></div>'
        '<div class="panel-body">'
        '<div class="breakdown-top">'
        f'<div><span class="muted-sm">Controls Observed</span><div class="chart-big-num">{active_ctrl_count} / {len(sec_controls)}</div></div>'
        f'<span class="date-pill">{esc(loc_badge)}</span>'
        "</div>"
        f'<div class="vbar-chart">{"".join(vbars_html)}</div>'
        "</div></div>"
        "</div>"
    )

    sidebar_html = (
        '<aside class="sidebar">'
        '<div class="ws-box">'
        '<div class="ws-logo">S</div>'
        '<div class="ws-meta"><span class="ws-sub">Security Engine</span><strong>ShamTrace CLI</strong></div>'
        "</div>"
        '<div class="nav-group"><span class="nav-group-title">Main Menu</span>'
        '<a href="#top" class="nav-link active">Dashboard</a>'
        '<a href="#sec-modules" class="nav-link">Module Telemetry</a>'
        '<a href="#sec-findings" class="nav-link">Security Findings</a>'
        '<a href="#sec-executive-assessment" class="nav-link">Assessment Summary</a>'
        '<a href="#sec-scope-infrastructure-and-transport" class="nav-link">Scope &amp; Transport</a>'
        "</div>"
        '<div class="nav-group"><span class="nav-group-title">Infrastructure &amp; DNS</span>'
        '<a href="#sec-dns-evidence" class="nav-link">DNS Evidence</a>'
        '<a href="#sec-certificate-evidence" class="nav-link">SSL / Certificate</a>'
        '<a href="#sec-http-header-evidence" class="nav-link">Security Headers</a>'
        '<a href="#sec-cookie-metadata-values-excluded" class="nav-link">Cookie Metadata</a>'
        "</div>"
        '<div class="nav-group"><span class="nav-group-title">Surface &amp; Governance</span>'
        '<a href="#sec-sensitive-path-exposure-probes" class="nav-link">Exposure Probes</a>'
        '<a href="#sec-technology-fingerprints-unverified-claims" class="nav-link">Tech Fingerprints</a>'
        '<a href="#sec-discovery-inventory" class="nav-link">Surface Inventory</a>'
        '<a href="#sec-coverage-gaps" class="nav-link">Coverage Gaps</a>'
        '<a href="#sec-limitations" class="nav-link">Limitations</a>'
        "</div>"
        '<div class="sidebar-user">'
        '<div class="user-avatar">ST</div>'
        f'<div class="ws-meta"><strong>ShamTrace v{esc(sanitized_report.get("version", "0.2.0"))}</strong>'
        f'<span class="ws-sub">Schema v{esc(sanitized_report.get("schema_version", "1.8"))} &bull; Offline</span></div>'
        "</div>"
        "</aside>"
    )

    disclaimer_banner = (
        '<div class="notice-banner">'
        "<strong>Assessment Boundaries &amp; Caveats:</strong> "
        "This report reflects bounded, non-intrusive configuration and surface observations at the time of inspection. "
        "Failed or skipped modules, or the absence of findings, must never be interpreted as proof that the target is secure. "
        "Software version banners and CDN package references are unverified hints, not confirmed exploitable CVEs."
        "</div>"
    )

    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">\n'
        "<title>ShamTrace — Security Assessment Dashboard</title><style>\n"
        ":root{--outer:#dfdeda;--bg:#ffffff;--surface:#f6f6f4;--surface-2:#efefec;--border:#e6e6e2;--border-strong:#d6d6d0;--text:#18181b;--muted:#6e6e6a;--accent:#18181b;--green:#166534;--green-bg:#e8f5e9;--amber:#9a3412;--amber-bg:#ffedd5;--red:#9f1239;--red-bg:#ffe4e6;--mono:ui-monospace,'JetBrains Mono','Fira Code',Consolas,monospace;--sans:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}\n"
        "*{box-sizing:border-box}html,body{height:100%;margin:0}body{padding:18px;background:var(--outer);color:var(--text);font:13.5px/1.55 var(--sans);-webkit-font-smoothing:antialiased;overflow:hidden}\n"
        ".app-shell{max-width:1440px;height:calc(100vh - 36px);margin:0 auto;background:var(--bg);border-radius:18px;border:1px solid var(--border);box-shadow:0 20px 50px rgba(0,0,0,.06);display:grid;grid-template-columns:250px minmax(0,1fr);overflow:hidden}\n"
        ".sidebar{background:var(--surface);border-right:1px solid var(--border);padding:18px 14px;display:flex;flex-direction:column;gap:16px;height:100%;overflow-y:auto;flex-shrink:0;user-select:none}\n"
        ".ws-box,.sidebar-user{background:#fff;border:1px solid var(--border);border-radius:10px;padding:10px 12px;display:flex;align-items:center;gap:10px}\n"
        ".sidebar-user{margin-top:auto}\n"
        ".ws-logo,.user-avatar{width:32px;height:32px;border-radius:8px;background:#18181b;color:#fff;font:700 13px/1 var(--mono);display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}\n"
        ".user-avatar{border-radius:50%;background:#3f3f46;font-size:11px}\n"
        ".ws-meta{display:flex;flex-direction:column;min-width:0}.ws-meta strong{font-size:12.5px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.ws-sub{font-size:11px;color:var(--muted)}\n"
        ".nav-group{display:flex;flex-direction:column;gap:3px;padding-bottom:10px;border-bottom:1px solid var(--border)}\n"
        ".nav-group-title{font-size:11px;font-weight:600;color:var(--muted);padding:0 10px 4px}\n"
        ".nav-link{color:#52524e;text-decoration:none;font-size:12.5px;font-weight:500;padding:8px 12px;border-radius:8px;display:block;transition:all .12s}\n"
        ".nav-link:hover,.nav-link:focus,.nav-link.active{background:#fff;color:var(--text);font-weight:600;box-shadow:0 1px 3px rgba(0,0,0,.04)}\n"
        ".workspace{padding:0 26px 36px;min-width:0;height:100%;overflow-y:auto;scroll-behavior:smooth;background:#fff}\n"
        ".topbar{position:sticky;top:0;z-index:20;background:rgba(255,255,255,.95);backdrop-filter:blur(8px);display:flex;justify-content:space-between;align-items:center;gap:12px;padding:18px 0 14px;border-bottom:1px solid var(--border);margin-bottom:20px;flex-wrap:wrap}\n"
        ".breadcrumb{font-size:13px;color:var(--muted)}.breadcrumb strong{color:var(--text);font-weight:600}\n"
        ".top-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}\n"
        ".search-fake{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:6px 12px;font-size:12px;color:var(--muted);min-width:220px;display:flex;align-items:center;justify-content:space-between;gap:20px}\n"
        ".hero-row{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:18px;flex-wrap:wrap}\n"
        ".hero-row h1{margin:0;font-size:23px;font-weight:700;letter-spacing:-.02em;color:var(--text)}\n"
        ".hero-controls{display:flex;align-items:center;gap:8px;flex-wrap:wrap}\n"
        ".pill-ctrl,.date-pill{background:#fff;border:1px solid var(--border);border-radius:8px;padding:6px 12px;font-size:12px;font-weight:500;color:var(--text);display:inline-flex;align-items:center;gap:6px}\n"
        ".btn-dark{background:#262626;color:#fff;border-radius:8px;padding:7px 14px;font-size:12px;font-weight:600;text-decoration:none;border:none;display:inline-flex;align-items:center;gap:6px}\n"
        ".kpi-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:18px}\n"
        ".kpi-card{background:#fff;border:1px solid var(--border);border-radius:12px;overflow:hidden;display:flex;flex-direction:column;justify-content:space-between}\n"
        ".kpi-top{padding:16px 16px 12px;display:flex;justify-content:space-between;align-items:flex-end;gap:10px}\n"
        ".kpi-label{display:block;font:600 11px/1.2 var(--mono);color:var(--muted);letter-spacing:.04em;margin-bottom:8px}\n"
        ".kpi-val{font:700 22px/1.1 var(--mono);color:var(--text);letter-spacing:-.03em}.kpi-val small{font:500 12px/1 var(--sans);color:var(--muted);margin-left:3px}\n"
        ".kpi-foot{background:var(--surface);border-top:1px solid var(--border);padding:7px 14px;display:flex;justify-content:space-between;align-items:center;font-size:11.5px}\n"
        ".kpi-delta{color:var(--green);font-weight:600}.info-dot{color:#9ca3af;font:600 11px/1 var(--mono)}\n"
        ".analytics-grid{display:grid;grid-template-columns:1.65fr 1fr;gap:16px;margin-bottom:18px}\n"
        ".panel-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:4px;margin-bottom:18px;scroll-margin-top:76px;transition:border-color .2s,box-shadow .2s}\n"
        ".panel-card:target{border-color:#18181b;box-shadow:0 8px 24px rgba(0,0,0,.07)}\n"
        ".panel-header{padding:10px 14px;display:flex;justify-content:space-between;align-items:center}\n"
        ".panel-title{font:700 11.5px/1.2 var(--mono);letter-spacing:.05em;color:#52524e;display:flex;align-items:center;gap:6px}\n"
        ".panel-more{background:#fff;border:1px solid var(--border);border-radius:6px;padding:2px 7px;font-size:10px;color:var(--muted)}\n"
        ".panel-body{background:#fff;border-radius:10px;border:1px solid var(--border);padding:16px}\n"
        ".chart-top-bar,.breakdown-top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px}\n"
        ".muted-sm{font-size:12px;color:var(--muted)}.chart-big-num{font:700 18px/1.2 var(--mono);color:var(--text)}\n"
        ".chart-legend{display:flex;gap:14px;font:600 10.5px/1 var(--mono);color:var(--muted)}\n"
        ".leg-item{display:flex;align-items:center;gap:5px}.dot-mid,.dot-dark{width:7px;height:7px;border-radius:50%;display:inline-block}.dot-mid{background:#d4d4d0}.dot-dark{background:#18181b}\n"
        ".seg-tabs{background:var(--surface);border-radius:8px;padding:3px;display:flex;gap:2px}\n"
        ".seg-tab{font-size:11px;padding:4px 10px;border-radius:6px;color:var(--muted)}.seg-tab.active{background:#fff;color:var(--text);font-weight:600;box-shadow:0 1px 2px rgba(0,0,0,.05)}\n"
        ".matrix-chart{display:grid;grid-template-columns:repeat(12,1fr);gap:6px;padding-top:6px}\n"
        ".m-col{display:flex;flex-direction:column;align-items:center;gap:6px}.m-stack{display:flex;flex-direction:column;gap:3px;width:100%}\n"
        ".m-cell{height:11px;border-radius:2px;display:block}.cell-empty{background:#f5f5f3}.cell-mid{background:#e2e2dd}.cell-dark{background:#18181b}\n"
        ".m-label{font:600 10px/1 var(--mono);color:var(--muted)}\n"
        ".vbar-chart{display:grid;grid-template-columns:repeat(8,1fr);gap:10px;height:130px;align-items:end;padding-top:10px}\n"
        ".vbar-col{display:flex;flex-direction:column;align-items:center;gap:6px;height:100%}\n"
        ".vbar-track{width:6px;flex:1;background:#ecece8;border-radius:99px;display:flex;align-items:flex-end;overflow:hidden}\n"
        ".vbar-fill{width:100%;background:#18181b;border-radius:99px}\n"
        ".vbar-lbl{font:600 9.5px/1 var(--mono);color:var(--muted)}\n"
        ".notice-banner{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:12px 16px;margin-bottom:18px;color:#4b4b48;font-size:12.5px}\n"
        ".sec-tag{color:var(--muted);margin-right:4px}\n"
        ".badge{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:999px;font:600 11px/1.2 var(--sans)}\n"
        ".st-completed{background:var(--green-bg);color:var(--green)}.st-skipped{background:var(--surface-2);color:var(--muted)}.st-failed{background:var(--red-bg);color:var(--red)}\n"
        ".sev-high{background:var(--red-bg);color:var(--red)}.sev-medium{background:var(--amber-bg);color:var(--amber)}.sev-low{background:#e0f2fe;color:#0369a1}.sev-info{background:var(--surface-2);color:#52524e}\n"
        ".conf,.cls-badge{background:var(--surface);color:#52524e;border:1px solid var(--border);margin-left:6px}\n"
        ".filter-radio{display:none}.hud-filter-bar{display:flex;flex-wrap:wrap;justify-content:space-between;gap:12px;background:var(--surface);border-radius:10px;border:1px solid var(--border);padding:10px 14px;margin-bottom:14px}\n"
        ".filter-group{display:flex;flex-wrap:wrap;align-items:center;gap:6px}.filter-group .label{margin:0 6px 0 0}\n"
        ".filter-chip{cursor:pointer;font:600 11.5px/1 var(--sans);padding:6px 12px;border-radius:7px;background:#fff;border:1px solid var(--border);color:var(--muted);user-select:none}\n"
        ".filter-chip:hover{color:var(--text);border-color:var(--border-strong)}\n"
        "#sev-all:checked ~ .hud-filter-bar label[for='sev-all'],#sev-high:checked ~ .hud-filter-bar label[for='sev-high'],#sev-medium:checked ~ .hud-filter-bar label[for='sev-medium'],#sev-low:checked ~ .hud-filter-bar label[for='sev-low'],#sev-info:checked ~ .hud-filter-bar label[for='sev-info'],"
        "#cls-all:checked ~ .hud-filter-bar label[for='cls-all'],#cls-verified:checked ~ .hud-filter-bar label[for='cls-verified'],#cls-candidate:checked ~ .hud-filter-bar label[for='cls-candidate'],#cls-config:checked ~ .hud-filter-bar label[for='cls-config']{background:#18181b;color:#fff;border-color:#18181b}\n"
        "#sev-high:checked ~ .findings-list .finding-card:not(.sev-card-high),#sev-medium:checked ~ .findings-list .finding-card:not(.sev-card-medium),#sev-low:checked ~ .findings-list .finding-card:not(.sev-card-low),#sev-info:checked ~ .findings-list .finding-card:not(.sev-card-info){display:none}\n"
        "#cls-verified:checked ~ .findings-list .finding-card:not(.cls-card-verified_finding),#cls-candidate:checked ~ .findings-list .finding-card:not(.cls-card-vulnerability_candidate),#cls-config:checked ~ .findings-list .finding-card:not(.cls-card-configuration_observation):not(.cls-card-operational_observation){display:none}\n"
        ".finding-card{background:#fff;border:1px solid var(--border);border-radius:12px;padding:16px 18px;margin-bottom:12px}\n"
        ".sev-border-high{border-left:4px solid var(--red)}.sev-border-medium{border-left:4px solid var(--amber)}.sev-border-low{border-left:4px solid #0284c7}.sev-border-info{border-left:4px solid #a1a19a}\n"
        ".hud-index,.mono-id{font:600 12px/1 var(--mono);color:var(--muted);margin-right:8px}\n"
        ".finding-head{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border)}\n"
        ".finding-head h3{font-size:15px;font-weight:600;color:var(--text);margin:0;display:inline}\n"
        ".finding-summary,.finding-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}\n"
        ".hud-drawer{margin-top:12px;border-top:1px dashed var(--border);padding-top:10px}\n"
        ".hud-drawer summary{cursor:pointer;font:600 11px/1 var(--mono);color:var(--muted);letter-spacing:.04em;margin-bottom:10px}\n"
        ".label{display:block;font:600 10.5px/1.2 var(--mono);text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:4px}\n"
        ".evidence-box{margin:0;padding:10px 12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;font:12px/1.5 var(--mono);color:var(--text);white-space:pre-wrap;overflow-wrap:anywhere}\n"
        ".empty-note{padding:12px;color:var(--muted)}\n"
        ".scroll{overflow:auto}table{border-collapse:collapse;width:100%;text-align:left;font-size:13px}\n"
        "th{background:#fff;color:var(--muted);font:600 11px/1.3 var(--mono);text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--border);padding:10px 12px}\n"
        "td{padding:11px 12px;border-bottom:1px solid #f2f2ef;vertical-align:top;overflow-wrap:anywhere;min-width:80px;color:#27272a}\n"
        "tbody tr:last-child td{border-bottom:none}tbody tr:hover{background:#fafaf8}p{color:#3f3f3c;margin:4px 0}code{background:var(--surface);border:1px solid var(--border);border-radius:5px;padding:1px 6px;font:12px/1.3 var(--mono);color:var(--text)}\n"
        "@media (max-width:1080px){html,body{height:auto;overflow:auto}.app-shell{height:auto;grid-template-columns:1fr}.sidebar{display:none}.workspace{height:auto;overflow:visible}.kpi-grid{grid-template-columns:repeat(2,1fr)}.analytics-grid{grid-template-columns:1fr}}\n"
        "@media print{html,body{height:auto;overflow:visible;background:#fff;padding:0}.app-shell{height:auto;border:none;box-shadow:none;grid-template-columns:1fr}.sidebar,.topbar{display:none}.workspace{height:auto;overflow:visible}}\n"
        "</style><div class=\"app-shell\">"
        + sidebar_html
        + '<main class="workspace"><div id="top"></div>'
        '<div class="topbar">'
        '<div class="breadcrumb">Dashboard &nbsp;/&nbsp; <strong>Overview</strong></div>'
        '<div class="top-actions">'
        '<div class="search-fake"><span>Search telemetry...</span><span>Ctrl+F</span></div>'
        f'<span class="pill-ctrl">Schema v{esc(sanitized_report.get("schema_version", "1.8"))}</span>'
        "</div></div>"
        '<div class="hero-row">'
        f'<h1>Assessment Overview &mdash; {esc(target_url)}</h1>'
        '<div class="hero-controls">'
        f'<span class="pill-ctrl">{esc(sanitized_report.get("profile", "extended")).title()}</span>'
        f'<span class="date-pill">{esc(timestamp_short)}</span>'
        '<a href="#sec-findings" class="btn-dark">Review Findings</a>'
        "</div></div>"
        + kpi_cards
        + analytics_row
        + disclaimer_banner
        + "".join(blocks)
        + "</main></div></html>"
    )
    return json.dumps(sanitized_report, indent=2), "\n".join(lines), page


def _write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def save_reports(report, directory):
    output = Path(directory).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    base = output / f"shamtrace-{stamp}"
    json_path, markdown_path, html_path = (
        base.with_suffix(".json"),
        base.with_suffix(".md"),
        base.with_suffix(".html"),
    )
    json_text, md_text, html_text = build_report_texts(report)
    for path, text in [
        (json_path, json_text),
        (markdown_path, md_text),
        (html_path, html_text),
    ]:
        _write_private(path, text)
    return json_path, markdown_path


def regenerate_reports_from_json(json_file, output_dir=None):
    """Rebuild HTML and Markdown reports from an existing JSON report without rescanning."""
    source_path = Path(json_file).expanduser().resolve()
    if not source_path.is_file():
        raise ValueError(f"JSON report file not found: {source_path}")
    try:
        report = json.loads(source_path.read_text(encoding="utf-8"))
    except ValueError as err:
        raise ValueError(f"Invalid JSON report file: {err}") from err
    if not isinstance(report, dict) or "target" not in report or "headers" not in report:
        raise ValueError("Supplied JSON file is not a valid ShamTrace report schema.")

    _, md_text, html_text = build_report_texts(report)
    if output_dir:
        out_dir = Path(output_dir).expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        base = out_dir / f"{source_path.stem}-rebuilt-{stamp}"
        md_path, html_path = base.with_suffix(".md"), base.with_suffix(".html")
        _write_private(md_path, md_text)
        _write_private(html_path, html_text)
    else:
        md_path = source_path.with_suffix(".md")
        html_path = source_path.with_suffix(".html")
        for path, text in [(md_path, md_text), (html_path, html_text)]:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(text)
    return html_path, md_path
