from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text
from . import __version__ as VERSION

console = Console()


def banner():
    if console.width >= 80:
        top_bar = (
            Text("┏" + ("━" * 33) + "[ ", style="bright_black")
            + Text("★  ★  ★", style="bold bright_red")
            + Text(" ]" + ("━" * 34) + "┓", style="bright_black")
        )
        # Pita Atas: Hijau (Green stripe)
        art_1 = Text("┃ ", style="bright_black") + Text("███████╗██╗  ██╗ █████╗ ███╗   ███╗", style="bold bright_green") + Text("████████╗██████╗  █████╗  ██████╗███████╗", style="bold bright_green") + Text(" ┃", style="bright_black")
        art_2 = Text("┃ ", style="bright_black") + Text("██╔════╝██║  ██║██╔══██╗████╗ ████║", style="bold green") + Text("╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝", style="bold green") + Text(" ┃", style="bright_black")
        # Pita Tengah: Putih dengan 3 aksen Merah di tengah (White stripe + 3 Red accents)
        art_3 = (
            Text("┃ ", style="bright_black")
            + Text("███████╗", style="bold bright_white")
            + Text("███████║", style="bold bright_red")
            + Text("███████║██╔", style="bold bright_white")
            + Text("████", style="bold bright_red")
            + Text("╔██║   ██║   ██████╔╝", style="bold bright_white")
            + Text("███████║", style="bold bright_red")
            + Text("██║     █████╗  ", style="bold bright_white")
            + Text(" ┃", style="bright_black")
        )
        art_4 = Text("┃ ", style="bright_black") + Text("╚════██║██╔══██║██╔══██║██║╚██╔╝██║", style="bold white") + Text("   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ", style="bold white") + Text(" ┃", style="bright_black")
        # Pita Bawah: Hitam/Charcoal dengan outline Merah tegas (Black stripe + Red baseline)
        art_5 = Text("┃ ", style="bright_black") + Text("███████║██║  ██║██║  ██║██║ ╚═╝ ██║", style="bold grey35") + Text("   ██║   ██║  ██║██║  ██║╚██████╗███████╗", style="bold grey35") + Text(" ┃", style="bright_black")
        art_6 = Text("┃ ", style="bright_black") + Text("╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝", style="bold red") + Text("   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝", style="bold red") + Text(" ┃", style="bright_black")
        hud_line = (
            Text("┗━━[ ", style="bright_black")
            + Text("SHAM", style="bold bright_green")
            + Text("TRACE", style="bold bright_white")
            + Text(f" v{VERSION}", style="bold bright_red")
            + Text(" ]━━[ ", style="bright_black")
            + Text("★ ", style="bold bright_red")
            + Text("TACTICAL WEB SECURITY", style="bold bright_white")
            + Text(" ★", style="bold bright_red")
            + Text(" ]━━[ ", style="bright_black")
            + Text("EVIDENCE-FIRST", style="bold bright_green")
            + Text(" ]", style="bright_black")
        )
        pad_len = max(1, 79 - len(hud_line.plain))
        hud_line.append("━" * pad_len + "┛", style="bright_black")
        for line in (top_bar, art_1, art_2, art_3, art_4, art_5, art_6, hud_line):
            console.print(line, no_wrap=True)
    else:
        console.print(Text(f"[ ★ ★ ★ SHAMTRACE v{VERSION} // TACTICAL ASSESSMENT ]", style="bold bright_green"))


def _show_modules_table(report):
    modules = report.get("modules") or {}
    if not modules:
        return
    mod_table = Table(title="Module status", box=box.SIMPLE_HEAD, expand=True)
    mod_table.add_column("Module", style="cyan", no_wrap=True)
    mod_table.add_column("Status", no_wrap=True)
    mod_table.add_column("Detail", overflow="fold")
    for name, info in modules.items():
        st = info.get("status", "skipped")
        style = "green" if st == "completed" else ("red" if st == "failed" else "dim")
        mod_table.add_row(name, Text(st.upper(), style=style), Text(str(info.get("detail", ""))))
    console.print(mod_table)


def _severity_text(sev: str) -> Text:
    s = (sev or "info").upper()
    style = {
        "HIGH": "bold bright_red",
        "MEDIUM": "bold yellow",
        "LOW": "bold cyan",
        "INFO": "dim white",
    }.get(s, "white")
    return Text(s, style=style)


def _show_findings_table(report, full=False):
    findings = report.get("findings") or []
    if not findings:
        console.print("[green]No configuration or surface review items recorded.[/green]")
        return
    f_table = Table(
        title=f"Findings & Configuration Review ({len(findings)})",
        box=box.SIMPLE_HEAD,
        expand=True,
        show_lines=full,
    )
    f_table.add_column("Sev", no_wrap=True, width=7)
    f_table.add_column("CWE / CVSS", no_wrap=True, width=14)
    f_table.add_column("Finding", style="bold white", ratio=2, overflow="fold")
    f_table.add_column("Evidence", ratio=3, overflow="fold")
    if full:
        f_table.add_column("Remediation", ratio=3, overflow="fold")
    from .vuln_checks import enrich_finding_taxonomy
    for raw_item in findings:
        item = enrich_finding_taxonomy(dict(raw_item))
        title = item.get("title") or item.get("id", "finding")
        occ = item.get("occurrence_count", 1)
        if occ > 1:
            title = f"{title} (×{occ})"
        cwe_cvss = f"{item.get('cwe', 'CWE-200')} ({item.get('cvss_score', 0.0)})"
        row = [
            _severity_text(item.get("severity", "info")),
            Text(cwe_cvss, style="cyan"),
            Text(title),
            Text(str(item.get("evidence", ""))),
        ]
        if full:
            row.append(Text(str(item.get("remediation") or item.get("recommendation") or "")))
        f_table.add_row(*row)
    console.print(f_table)


def show_report(report, verbose=False):
    if not verbose:
        show_overview(report)
        return
    assessment = report.get("assessment", {})
    console.print("\n[bold bright_green]━━━ ASSESSMENT SUMMARY ━━━[/bold bright_green]")
    for conclusion in assessment.get("conclusions", []):
        console.print(Text("• " + conclusion))
    for gap in assessment.get("coverage_gaps", []):
        console.print(Text("Coverage gap: " + gap, style="dim"))

    status_info = report.get("status") or {}
    loc_info = report.get("location") or {}
    fw_info = report.get("firewall") or {}
    hsts_info = report.get("hsts") or {}

    summary = Table(title="Target, Transport & Infrastructure Summary", box=box.SIMPLE_HEAD, expand=True)
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", overflow="fold")
    resp_ms = status_info.get("responseTimeMs")
    http_str = f"{report.get('http_status')} ({resp_ms} ms)" if resp_ms is not None else str(report.get("http_status"))
    rows = [
        ("Target", report["target"]),
        ("Final URL", report.get("final_url", report["target"])),
        ("Resolved IPs", ", ".join(report.get("resolved_ips") or []) or "Not resolved locally"),
        ("HTTP Status / Latency", http_str),
        ("TLS", report.get("tls", "Not inspected")),
        ("Server claim", report.get("server") or "Not advertised"),
        ("Framework claim", report.get("powered_by") or "Not advertised"),
        ("WAF / Firewall", ", ".join(fw_info.get("wafVendors") or []) if fw_info.get("hasWaf") else "No explicit WAF banner"),
        ("HSTS Status", hsts_info.get("message") or ("Present" if hsts_info.get("present") else "Not advertised")),
        ("CORS Policy", (report.get("cors") or {}).get("state", "not_advertised")),
        ("Redirect", report.get("redirect_location") or "None"),
    ]
    if loc_info.get("status") == "completed":
        coords = loc_info.get("coords") or {}
        rows.extend([
            ("Location", f"{loc_info.get('city') or '-'}, {loc_info.get('region') or '-'}, {loc_info.get('country') or '-'} ({loc_info.get('countryCode') or '-'})"),
            ("ISP / ASN", f"{loc_info.get('isp') or '-'} ({loc_info.get('asn') or '-'})"),
            ("Coordinates / Timezone", f"{coords.get('latitude')}, {coords.get('longitude')} | {loc_info.get('timezone') or '-'} | {loc_info.get('currency') or '-'} ({loc_info.get('currencyCode') or '-'})"),
        ])
    for label, value in rows:
        summary.add_row(label, Text(str(value)))
    console.print(summary)

    _show_modules_table(report)

    cert = report.get("certificate") or {}
    tls_conn = report.get("tls_connection") or {}
    if cert or tls_conn.get("applicable"):
        tls_table = Table(title="TLS Connection & Certificate Cryptographic Inspection", box=box.SIMPLE_HEAD, expand=True)
        tls_table.add_column("Property", style="cyan", no_wrap=True)
        tls_table.add_column("Observed Value", overflow="fold")
        from .reports import _flatten_x509_name

        san_names = cert.get("san_dns_names") or [v for k, v in (cert.get("subject_alt_names") or []) if k == "DNS"]
        tls_rows = [
            ("Protocol / Cipher", f"{tls_conn.get('protocol') or '-'} / {tls_conn.get('cipher_suite') or '-'} ({tls_conn.get('cipher_bits') or '-'} bits)"),
            ("Subject", _flatten_x509_name(cert.get("subject"))),
            ("Issuer", _flatten_x509_name(cert.get("issuer"))),
            ("Serial Number", cert.get("serial_number") or "-"),
            ("Validity (UTC)", f"{cert.get('not_before') or '-'} → {cert.get('not_after') or '-'} ({cert.get('days_remaining', '-')} days remaining)"),
            ("Subject Alt Names (DNS)", ", ".join(san_names[:12]) + (f" (+{len(san_names) - 12} more)" if len(san_names) > 12 else "") if san_names else "-"),
            ("SHA-256 Fingerprint", cert.get("fingerprint_sha256") or "-"),
            ("SHA-1 Fingerprint", cert.get("fingerprint_sha1") or "-"),
            ("CA Issuers / OCSP", ", ".join((cert.get("ca_issuers") or []) + (cert.get("ocsp") or [])) or "-"),
        ]
        for k, v in tls_rows:
            tls_table.add_row(k, Text(str(v)))
        console.print(tls_table)

    table = Table(title="Security Headers", box=box.SIMPLE_HEAD, expand=True)
    table.add_column("Header", style="cyan", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Evaluation", overflow="fold")
    for item in report.get("headers", []):
        state = item["state"]
        quality = item.get("quality", state)
        style = "green" if quality in {"strong", "adequate"} else ("yellow" if state == "present" else "dim")
        table.add_row(
            item["header"],
            Text(state.upper(), style=style),
            Text(item.get("evaluation", item.get("purpose", ""))),
        )
    console.print(table)

    if report.get("cookies"):
        c_table = Table(title="Cookie Metadata", box=box.SIMPLE_HEAD, expand=True)
        for label in ("Name", "Prefix", "Secure", "HttpOnly", "SameSite"):
            c_table.add_column(label)
        for cookie in report["cookies"]:
            c_table.add_row(
                Text(cookie["name"]),
                str(cookie.get("prefix", "none")),
                str(cookie["secure"]),
                str(cookie["httponly"]),
                Text(cookie["samesite"]),
            )
        console.print(c_table)
    else:
        console.print("[dim]No Set-Cookie header observed.[/dim]")

    fingerprints = report.get("fingerprints") or []
    if fingerprints:
        fp_table = Table(title="Technology Fingerprints (Unverified Claims)", box=box.SIMPLE_HEAD, expand=True)
        for label in ("Technology", "Category", "Version", "Confidence", "Evidence"):
            fp_table.add_column(label, overflow="fold")
        for fp in fingerprints:
            fp_table.add_row(
                Text(fp["name"], style="bold white"),
                fp["category"],
                Text(str(fp.get("version") or "-")),
                fp["confidence"],
                Text(fp["evidence"]),
            )
        console.print(fp_table)

    dns_report = report.get("dns", {})
    if dns_report.get("queries"):
        from .reports import _build_dns_rows

        dns_table = Table(title="DNS Evidence", box=box.SIMPLE_HEAD, expand=True)
        for label in ("Name / Type", "Status", "TTL", "Records / Authority Response", "Interpretation"):
            dns_table.add_column(label, overflow="fold")
        for row in _build_dns_rows(dns_report):
            dns_table.add_row(Text(str(row[0]), style="cyan"), str(row[1]), str(row[2]), Text(str(row[3])), Text(str(row[4]), style="dim"))
        console.print(dns_table)

        ptr_map = dns_report.get("ptr_records") or {}
        dnssec = dns_report.get("dnssec") or {}
        if ptr_map or dnssec:
            extra_dns = Table(title="DNSSEC & Reverse DNS (PTR) Telemetry", box=box.SIMPLE_HEAD, expand=True)
            extra_dns.add_column("Check", style="cyan", no_wrap=True)
            extra_dns.add_column("Status", no_wrap=True)
            extra_dns.add_column("Detail", overflow="fold")
            for ip_k, ptr_vals in ptr_map.items():
                extra_dns.add_row(f"PTR ({ip_k})", Text("OK", style="green"), Text(", ".join(ptr_vals)))
            for sec_k in ("DNSKEY", "DS", "RRSIG"):
                sec_item = dnssec.get(sec_k) or {}
                if sec_item:
                    found = sec_item.get("isFound", False)
                    st_text = Text("SIGNED", style="green") if found else Text(str(sec_item.get("status", "no_answer")).upper(), style="dim")
                    detail = "; ".join(sec_item.get("records") or []) if found else f"Not published (Authority SOA: {sec_item.get('authority_soa') or '-'})"
                    extra_dns.add_row(f"DNSSEC {sec_k}", st_text, Text(detail))
            console.print(extra_dns)

    blocklists = (report.get("blocklists") or {}).get("blocklists") or []
    if blocklists:
        bl_table = Table(title="DNS Security & Family Blocklist Matrix", box=box.SIMPLE_HEAD, expand=True)
        bl_table.add_column("DNS Provider", style="cyan")
        bl_table.add_column("Resolver IP")
        bl_table.add_column("Status")
        for bl in blocklists:
            blocked = bl.get("isBlocked", False)
            st_badge = Text("BLOCKED", style="bold bright_red") if blocked else Text("CLEAN (ALLOWED)", style="green")
            bl_table.add_row(Text(str(bl.get("server"))), str(bl.get("serverIp")), st_badge)
        console.print(bl_table)

    ports_info = report.get("ports") or {}
    if ports_info.get("status") == "completed":
        p_table = Table(title=f"TCP Service Port Probe ({ports_info.get('targetIp')})", box=box.SIMPLE_HEAD, expand=True)
        p_table.add_column("Category", style="cyan", no_wrap=True)
        p_table.add_column("Ports", overflow="fold")
        open_details = ports_info.get("openDetails") or []
        open_str = ", ".join(f"{d['port']}/{d['service']}" for d in open_details) if open_details else (", ".join(str(p) for p in (ports_info.get("openPorts") or [])) or "None")
        closed_str = ", ".join(str(p) for p in (ports_info.get("failedPorts") or [])) or "None"
        p_table.add_row("Open Ports", Text(open_str, style="bold bright_green"))
        p_table.add_row("Closed / Filtered", Text(closed_str, style="dim"))
        console.print(p_table)

    endpoints = report.get("metadata_endpoints", [])
    if endpoints:
        m_table = Table(title="Metadata Endpoints", box=box.SIMPLE_HEAD, expand=True)
        m_table.add_column("URL", style="cyan", overflow="fold")
        m_table.add_column("State", no_wrap=True)
        m_table.add_column("Reason", overflow="fold")
        for ep in endpoints:
            val = ep.get("validation") or {}
            m_table.add_row(Text(ep["url"]), str(val.get("state", ep.get("status", "-"))), Text(str(val.get("reason", ""))))
        console.print(m_table)

    exposures = report.get("exposures") or {}
    if exposures.get("results"):
        exp_table = Table(title="Sensitive Path & Exposure Probes", box=box.SIMPLE_HEAD, expand=True)
        exp_table.add_column("Path / Check", style="cyan", no_wrap=True)
        exp_table.add_column("HTTP", no_wrap=True)
        exp_table.add_column("State", no_wrap=True)
        exp_table.add_column("Verification Detail", overflow="fold")
        http_m = exposures.get("http_methods") or {}
        if http_m.get("checked"):
            m_state = Text("WARNING", style="yellow") if http_m.get("dangerous_methods") else Text("OK", style="green")
            m_detail = "Allowed: " + (", ".join(http_m.get("allowed_methods") or []) or "Not advertised")
            exp_table.add_row("OPTIONS /", str(http_m.get("http_status", "-")), m_state, Text(m_detail))
        for e_item in exposures.get("results", []):
            st_val = e_item.get("state", "-")
            st_txt = Text("EXPOSED", style="bold bright_red") if st_val == "exposed" else Text(st_val, style="dim")
            exp_table.add_row(
                Text(str(e_item.get("path"))),
                str(e_item.get("http_status") or "-"),
                st_txt,
                Text(str(e_item.get("reason") or "")),
            )
        console.print(exp_table)

    content = report.get("content", {})
    html = content.get("html")
    if html:
        social = report.get("social_tags") or html.get("social_tags") or {}
        console.print(
            Text(
                f"Surface Inventory: Title={html.get('title')!r} | Viewport={social.get('viewport') or '-'} | "
                f"Favicon={social.get('favicon') or '-'} | Links={html.get('link_count', 0)} | "
                f"Forms={len(html.get('forms', []))} | Resources={html.get('resource_count', 0)}"
            )
        )

    _show_findings_table(report, full=True)

    console.print(
        "\n[dim]Observations require manual validation. "
        "Absence of findings or skipped modules does not establish target safety.[/dim]"
    )


def show_overview(report):
    summary = Table(title="Scan overview", box=box.SIMPLE_HEAD, expand=True)
    summary.add_column("Item", style="cyan", no_wrap=True)
    summary.add_column("Result", overflow="fold")
    edge = report.get("edge", {})
    cf = edge.get("cloudflare", {})
    content = report.get("content", {})
    html = content.get("html") or {}
    cors = report.get("cors") or {}
    for key, value in [
        ("Target", report["target"]),
        ("Transport", report.get("network", {}).get("route", "direct")),
        ("HTTP / TLS", f"{report['http_status']} / {report['tls']}"),
        ("Server claim", report.get("server") or "Not advertised"),
        ("CORS policy", cors.get("state", "not_advertised")),
        ("Cloudflare", f"{cf.get('state', 'not_observed')}; challenge: {cf.get('challenge', False)}"),
        ("Page", html.get("title") or "No HTML title observed"),
        (
            "Coverage",
            f"{report['summary']['requests']} HTTP requests; {len(report.get('dns', {}).get('queries', []))} DNS queries",
        ),
        ("Review items", str(len(report.get("findings", [])))),
    ]:
        summary.add_row(key, Text(str(value)))
    console.print(summary)
    _show_modules_table(report)
    endpoints = report.get("metadata_endpoints", [])
    if endpoints:
        table = Table(title="Metadata validation", box=box.SIMPLE_HEAD, expand=True)
        table.add_column("URL", overflow="fold")
        table.add_column("Result")
        for item in endpoints:
            table.add_row(Text(item["url"]), item["validation"]["state"])
        console.print(table)
    advisories = report.get("advisories", {})
    matches = sum(len(item["advisories"]) for item in advisories.get("results", []))
    console.print(Text(f"Advisories: {advisories.get('status', 'not_run')} | Candidate matches: {matches}"))
    for finding in report.get("findings", [])[:8]:
        console.print(Text(f"  {finding.get('severity', 'info').upper():6} {finding.get('title', finding['id'])}"))
    scripts = report.get("scripts", {}).get("results", [])
    hints = sorted({hint for item in scripts for hint in item.get("api_path_hints", [])})
    console.print(Text(f"Scripts inspected: {len(scripts)} | Unverified API path hints: {len(hints)}"))
    if edge.get("skip_followup"):
        console.print(Text(edge["reason"], style="yellow"))
    elif html.get("scripts") and not html.get("link_count"):
        console.print("[dim]HTML contains scripts; rendered navigation and forms were not evaluated.[/dim]")
    console.print("[dim]Full evidence and recommendations are in the reports. Use -v or --terminal for full terminal view.[/dim]")
