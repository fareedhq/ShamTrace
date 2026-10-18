"""Bounded HTML discovery with URL normalization (preserving meaningful parameters), source tracking, and no form submission."""
import time
from urllib.parse import urlsplit
import httpx
from .content import inspect_document, build_findings
from .checks import assess_headers, inspect_cookies, normalize_in_scope_url, redact_url
from .policies import policy_findings, normalize_findings
from .edge import inspect_edge
from .network import open_stream_with_retry


def inspect_pages(client, target, document, budget=1, retries=0, rate_limiter=None, deadline=None):
    initial_html = (document or {}).get("html") or {}
    queue = [(u, target) for u in initial_html.get("links", [])]
    norm_initial, _ = normalize_in_scope_url(target, target)
    seen = {norm_initial or target}

    all_links = list(dict.fromkeys(redact_url(u) for u in initial_html.get("same_origin_links", [])))
    all_forms = list(initial_html.get("forms", []))
    all_scripts = list(dict.fromkeys(initial_html.get("scripts", [])))
    link_sources = [
        {"url": redact_url(u), "source": redact_url(target)}
        for u in initial_html.get("same_origin_links", [])
    ]
    form_sources = [
        {"method": f["method"], "action": redact_url(f["action"]), "source": redact_url(target)}
        for f in initial_html.get("forms", [])
    ]
    script_sources = [
        {"url": redact_url(s), "source": redact_url(target)}
        for s in initial_html.get("scripts", [])
    ]

    result = {
        "budget": budget,
        "results": [],
        "skipped": 0,
        "discovered_links": all_links,
        "discovered_forms": all_forms,
        "discovered_scripts": all_scripts,
        "link_sources": link_sources,
        "form_sources": form_sources,
        "script_sources": script_sources,
        "limitations": "Same-origin HTML links are normalized (retaining meaningful query parameters while skipping state-changing actions); JavaScript routes and forms are not executed.",
    }
    while queue and len(result["results"]) < budget - 1:
        if deadline is not None and time.monotonic() >= deadline:
            result["stop_reason"] = "Max scan duration reached."
            break
        item_entry = queue.pop(0)
        raw_url, discovered_from = item_entry if isinstance(item_entry, tuple) else (item_entry, target)
        normalized_url, skip_reason = normalize_in_scope_url(raw_url, target)
        if not normalized_url:
            result["skipped"] += 1
            continue
        if normalized_url in seen:
            continue
        seen.add(normalized_url)
        parsed = urlsplit(normalized_url)
        item = {"url": normalized_url, "discovered_from": redact_url(discovered_from)}
        result["results"].append(item)
        try:
            with open_stream_with_retry(
                client, "GET", normalized_url, retries=retries, rate_limiter=rate_limiter
            ) as response:
                edge = inspect_edge(response.headers, response.status_code)
                content = inspect_document(response, normalized_url)
                item.update(http_status=response.status_code, state="observed", content=content)
                if edge["skip_followup"]:
                    item["state"] = "restricted"
                    result["stop_reason"] = edge["reason"]
                    break
                if response.status_code == 200:
                    evidence = {
                        "target": normalized_url,
                        "content": content,
                        "edge": edge,
                        "headers": assess_headers(response.headers, parsed.scheme == "https"),
                        "cookies": inspect_cookies(response.headers),
                    }
                    item["findings"] = normalize_findings(
                        build_findings(evidence) + policy_findings(response.headers, evidence),
                        normalized_url,
                    )
                    page_html = content.get("html") or {}
                    for next_link in page_html.get("links", []):
                        queue.append((next_link, normalized_url))
                    for l_url in page_html.get("same_origin_links", []):
                        r_url = redact_url(l_url)
                        if r_url not in all_links:
                            all_links.append(r_url)
                            link_sources.append({"url": r_url, "source": redact_url(normalized_url)})
                    for form in page_html.get("forms", []):
                        if form not in all_forms:
                            all_forms.append(form)
                            form_sources.append({
                                "method": form["method"],
                                "action": redact_url(form["action"]),
                                "source": redact_url(normalized_url),
                            })
                    for s_url in page_html.get("scripts", []):
                        if s_url not in all_scripts:
                            all_scripts.append(s_url)
                            script_sources.append({"url": redact_url(s_url), "source": redact_url(normalized_url)})
        except httpx.HTTPError as error:
            item.update(state="error", error=str(error))
    result["pending_links"] = len(queue)
    return result
