"""Bounded metadata and static script inspection, with fallback and not_found differentiation."""
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from xml.etree import ElementTree
import httpx
from .content import inspect_document
from .network import open_stream_with_retry

PATHS = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")


def validate_metadata(path, text, content, baseline_hash=None):
    if content["truncated"]:
        return {"state": "inconclusive", "reason": "Response exceeds inspection limit."}
    if baseline_hash and content["sha256_inspected_bytes"] == baseline_hash:
        return {
            "state": "fallback",
            "reason": "Response is byte-identical to the target page (SPA/application fallback, not a real file).",
        }
    if content["html"] or text.lstrip().lower().startswith(("<!doctype html", "<html")):
        return {
            "state": "invalid",
            "reason": "HTML returned where a metadata document was expected (soft-404 or fallback).",
        }
    if path == "/robots.txt":
        directives = {}
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            key, sep, value = line.partition(":")
            if sep and key.lower() in {"user-agent", "allow", "disallow", "sitemap", "crawl-delay"}:
                directives.setdefault(key.lower(), []).append(value.strip())
        valid = bool(directives.get("user-agent"))
        return {
            "state": "recognized" if valid else "invalid",
            "reason": "Recognized robots directives; rule semantics not evaluated."
            if valid
            else "No User-agent directive found.",
            "directives": directives,
        }
    if path == "/sitemap.xml":
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            return {"state": "invalid", "reason": "DTD/entity declarations are not processed."}
        try:
            root = ElementTree.fromstring(text)
        except ElementTree.ParseError:
            return {"state": "invalid", "reason": "Malformed XML."}
        tag = root.tag.rsplit("}", 1)[-1]
        if tag not in {"urlset", "sitemapindex"}:
            return {"state": "invalid", "reason": "XML root is not urlset or sitemapindex."}
        locations = [
            node.text.strip()
            for node in root.iter()
            if node.tag.rsplit("}", 1)[-1] == "loc" and node.text
        ]
        return {
            "state": "recognized",
            "reason": "Sitemap structure recognized; schema and URLs not verified.",
            "kind": tag,
            "location_count": len(locations),
            "locations_sample": locations[:20],
        }
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.lower() in {"contact", "expires", "canonical", "policy", "preferred-languages"}:
            fields.setdefault(key.lower(), []).append(value.strip())
    valid = any(v.startswith(("mailto:", "https://")) for v in fields.get("contact", []))
    expires = fields.get("expires", [])
    try:
        expiry = datetime.fromisoformat(expires[0].replace("Z", "+00:00"))
        valid = valid and expiry.tzinfo is not None and expiry > datetime.now(timezone.utc)
    except (ValueError, IndexError):
        valid = False
    return {
        "state": "recognized" if valid else "invalid",
        "reason": "Contact and future Expires recognized; full standard compliance not checked."
        if valid
        else "Requires a supported Contact and a future timezone-qualified Expires.",
        "fields": fields,
    }


def inspect_metadata(client, target, baseline_hash=None, retries=0, rate_limiter=None):
    parsed = urlsplit(target)
    results = []
    for path in PATHS:
        url = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        item = {"url": url, "status": "ok"}
        try:
            with open_stream_with_retry(
                client, "GET", url, retries=retries, rate_limiter=rate_limiter
            ) as response:
                content = inspect_document(response, url, limit=64 * 1024, include_text=True)
                text = content.pop("_text")
                item.update(
                    http_status=response.status_code,
                    redirect_location=response.headers.get("location"),
                    content=content,
                )
                if response.status_code == 200:
                    item["validation"] = validate_metadata(path, text, content, baseline_hash)
                elif response.status_code in {404, 410}:
                    item["validation"] = {
                        "state": "not_found",
                        "reason": f"HTTP {response.status_code}; metadata document was checked and is not present.",
                    }
                else:
                    item["validation"] = {
                        "state": "not_checked",
                        "reason": f"HTTP {response.status_code}; redirects are not followed.",
                    }
        except httpx.HTTPError as error:
            item.update(
                status="error",
                error=str(error),
                validation={"state": "inconclusive", "reason": "Request failed."},
            )
        results.append(item)
    return results


def origin(url):
    try:
        parsed = urlsplit(url)
        return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


def inspect_scripts(client, target, scripts, max_scripts=3, retries=0, rate_limiter=None):
    results = []
    candidates = list(dict.fromkeys(scripts))
    eligible = [
        url
        for url in candidates
        if origin(url) == origin(target)
        and not urlsplit(url).username
        and not urlsplit(url).password
    ]
    for url in eligible[:max_scripts]:
        item = {"url": url}
        try:
            with open_stream_with_retry(
                client, "GET", url, retries=retries, rate_limiter=rate_limiter
            ) as response:
                content = inspect_document(response, url, limit=512 * 1024, include_text=True)
                text = content.pop("_text")
                item.update(http_status=response.status_code, content=content)
                mime = (content["content_type"] or "").split(";")[0].strip().lower()
                if response.status_code != 200 or mime not in {
                    "application/javascript",
                    "text/javascript",
                    "application/x-javascript",
                }:
                    item["state"] = "not_analyzed"
                else:
                    item["state"] = "analyzed"
                    # Literal path hints only; never request discovered API paths.
                    hints = re.findall(
                        r'''["'](/(?:api|v[1-9]|graphql|oauth|auth|webhook)[\w/.-]{0,180})(?:[?"'])''',
                        text,
                    )
                    item["api_path_hints"] = sorted(set(hints))[:30]
                    from .vuln_checks import inspect_script_vulnerabilities
                    item["vuln_analysis"] = inspect_script_vulnerabilities(text, url)
                    item["interpretation"] = (
                        "Static string hints only; paths are not verified endpoints. JavaScript is not executed."
                    )
        except httpx.HTTPError as error:
            item.update(state="error", error=str(error))
        results.append(item)
    return {
        "scripts_discovered": len(candidates),
        "same_origin_eligible": len(eligible),
        "request_limit": max_scripts,
        "results": results,
    }
