"""Explain evidence without inventing vulnerability confirmations or claiming target safety."""


def assess(report):
    conclusions = [f"Target returned HTTP {report['http_status']}; {report['tls']}."]
    gaps = []
    edge = report.get("edge", {})
    if edge.get("skip_followup"):
        return {
            "conclusions": [
                edge["reason"],
                "Follow-up requests skipped; application header findings suppressed.",
                "Target cannot be declared safe; origin application was blocked or unreachable.",
            ],
            "coverage_gaps": ["Origin application content and configuration were not assessed."],
            "next_steps": [
                "Review access policy with the site operator and scan an authorized accessible environment."
            ],
        }

    redirect_info = report.get("redirect_info") or {}
    if redirect_info.get("followed"):
        conclusions.append(
            f"Followed {redirect_info['hops']} in-scope redirect(s) to {report.get('final_url', report['target'])}."
        )
    elif redirect_info.get("stop_reason") == "out_of_scope_redirect_blocked":
        conclusions.append(
            f"Blocked redirect to out-of-scope destination ({redirect_info.get('blocked_location')})."
        )
        gaps.append("Redirect destination was outside the authorized target scope and was not followed.")

    if report.get("network", {}).get("route") == "socks-proxy":
        gaps.append("Target DNS was delegated to the SOCKS proxy; Tor identity and anonymity were not verified.")

    html = report["content"].get("html")
    if html:
        if html.get("scripts") and html["link_count"] == 0 and not html["forms"]:
            conclusions.append(
                "Initial HTML contains scripts but no links/forms. Client-rendered content is possible; zero counts do not describe the rendered application."
            )
        gaps.append("No JavaScript execution, authenticated browsing, or interaction with forms.")

    cors = report.get("cors") or {}
    if cors.get("state") and cors["state"] != "not_advertised":
        conclusions.append(f"CORS policy state: {cors['state']} ({'; '.join(cors.get('notes', []))}).")

    techs = report.get("fingerprints") or []
    if techs:
        names = ", ".join(
            f"{t['name']}" + (f" {t['version']}" if t.get("version") else "") + f" ({t['confidence']})"
            for t in techs[:6]
        )
        conclusions.append(
            f"Technology fingerprints observed: {names}. Version banners alone are unverified claims and not proof of CVEs."
        )

    endpoints = report.get("metadata_endpoints", [])
    for endpoint in endpoints:
        validation = endpoint["validation"]
        conclusions.append(f"{endpoint['url']}: {validation['state']} — {validation['reason']}")

    for query in report.get("dns", {}).get("queries", []):
        if query["type"] in {"AAAA", "MX"} and query["status"] == "no_answer":
            conclusions.append(
                f"DNS {query['type']}: no answer for this hostname; this alone is not a vulnerability."
            )
        if query["status"] in {"timeout", "error"}:
            gaps.append(f"DNS {query['type']} for {query['name']} was inconclusive ({query['status']}).")

    scripts = report.get("scripts", {})
    if scripts.get("same_origin_eligible", 0) > len(scripts.get("results", [])):
        gaps.append("Some scripts were not requested because the script budget was reached.")
    if report["content"]["truncated"]:
        gaps.append("Initial document exceeded the inspection limit.")

    advisories = report.get("advisories", {})
    matches = sum(len(item["advisories"]) for item in advisories.get("results", []))
    conclusions.append(
        f"Advisory lookup: {advisories.get('status', 'not_run')}; {matches} candidate matches. "
        + advisories.get("reason", "Matches require confirmation of component contents and affected functionality.")
    )
    for item in advisories.get("results", []):
        if item["status"] != "ok":
            gaps.append(f"Advisory lookup for {item['component']['name']}: {item['status']}.")
    if not report.get("components"):
        gaps.append(
            "No supported versioned npm CDN reference identified; backend and bundled dependency versions remain unknown."
        )
    for script in report.get("scripts", {}).get("results", []):
        if script.get("state") != "analyzed" or script.get("content", {}).get("truncated"):
            gaps.append(f"Script coverage incomplete: {script['url']}.")

    modules = report.get("modules") or {}
    for mod_name, mod_info in modules.items():
        if mod_info.get("status") in {"failed", "skipped"}:
            gaps.append(f"Module '{mod_name}' was {mod_info['status']}: {mod_info.get('detail', 'No detail')}.")

    conclusions.append(
        "Absence of findings or skipped/failed checks does not establish that the target is secure."
    )
    gaps.append(
        "No exploit validation, full port inventory, or full TLS protocol/cipher configuration audit. HTML traversal is limited by the page budget."
    )
    return {
        "conclusions": conclusions,
        "coverage_gaps": gaps,
        "next_steps": list(dict.fromkeys(finding["recommendation"] for finding in report["findings"])),
    }
