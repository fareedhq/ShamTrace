"""Bounded document inspection; no discovered URL is requested."""
import hashlib
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
from .checks import is_in_scope, redact_sensitive

BODY_LIMIT = 512 * 1024


class DocumentParser(HTMLParser):
    def __init__(self, target):
        super().__init__(convert_charrefs=True)
        self.target = target
        self.in_title = False
        self.title = []
        self.generator = None
        self.meta_tags = {}
        self.favicon = None
        self.canonical = None
        self.forms = []
        self.form_details = []
        self._current_form = None
        self.resources = []
        self.external_scripts_without_sri = []
        self.links = 0
        self.link_urls = []
        self.base_seen = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag == "base" and attrs.get("href") and not self.base_seen:
            self.target = urljoin(self.target, attrs["href"])
            self.base_seen = True
        if tag == "meta":
            meta_key = (attrs.get("name") or attrs.get("property") or "").strip().lower()
            meta_val = attrs.get("content")
            if meta_key == "generator":
                self.generator = meta_val
            if meta_key and meta_val is not None:
                self.meta_tags[meta_key] = meta_val
        if tag == "link":
            rel_tokens = (attrs.get("rel") or "").lower().split()
            href = attrs.get("href")
            if href:
                if ("icon" in rel_tokens or "shortcut" in rel_tokens) and not self.favicon:
                    self.favicon = href
                if "canonical" in rel_tokens and not self.canonical:
                    self.canonical = urljoin(self.target, href)
        if tag == "a":
            self.links += 1
            if attrs.get("href"):
                self.link_urls.append(urljoin(self.target, attrs["href"]))
        if tag == "form":
            method = attrs.get("method", "get").upper()
            action = urljoin(self.target, attrs.get("action", ""))
            self.forms.append({"method": method, "action": action})
            self._current_form = {
                "method": method,
                "action": action,
                "inputs": [],
                "has_csrf_field": False,
            }
            self.form_details.append(self._current_form)
        if tag in {"input", "textarea", "select"} and self._current_form is not None:
            field_name = attrs.get("name") or attrs.get("id") or ""
            field_type = (attrs.get("type") or tag).lower()
            self._current_form["inputs"].append({"name": field_name, "type": field_type})
            if any(tok in field_name.lower() for tok in ("csrf", "xsrf", "_token", "authenticity_token")):
                self._current_form["has_csrf_field"] = True
        resource = attrs.get("src") if tag in {"script", "img", "iframe", "source"} else None
        if tag == "script" and resource:
            full_script_url = urljoin(self.target, resource)
            if (
                full_script_url.startswith(("http://", "https://"))
                and not is_in_scope(full_script_url, self.target)
                and not (attrs.get("integrity") or "").strip()
            ):
                self.external_scripts_without_sri.append(full_script_url)
        if tag == "link" and "stylesheet" in attrs.get("rel", "").lower().split():
            resource = attrs.get("href")
        if resource:
            self.resources.append({"type": tag, "url": urljoin(self.target, resource)})

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data):
        if self.in_title:
            self.title.append(data)


def inspect_document(response, target, limit=BODY_LIMIT, include_text=False):
    body = bytearray()
    truncated = False
    for chunk in response.iter_bytes(chunk_size=16384):
        remaining = limit - len(body)
        body.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated = True
            break
    result = {
        "bytes_inspected": len(body),
        "truncated": truncated,
        "sha256_inspected_bytes": hashlib.sha256(body).hexdigest(),
        "content_type": response.headers.get("content-type"),
        "html": None,
    }
    if include_text:
        result["_text"] = body.decode(response.encoding or "utf-8", errors="replace")
    if "text/html" in response.headers.get("content-type", "").lower():
        parser = DocumentParser(target)
        parser.feed(body.decode(response.encoding or "utf-8", errors="replace"))
        https = urlsplit(target).scheme == "https"
        same_origin = [u for u in parser.link_urls if is_in_scope(u, target)]
        external = [
            u
            for u in parser.link_urls
            if u.startswith(("http://", "https://")) and not is_in_scope(u, target)
        ]
        clean_title = " ".join("".join(parser.title).split())
        result["html"] = {
            "title": clean_title,
            "generator_claim": parser.generator,
            "social_tags": {
                "title": clean_title or parser.meta_tags.get("og:title"),
                "description": parser.meta_tags.get("description") or parser.meta_tags.get("og:description"),
                "viewport": parser.meta_tags.get("viewport"),
                "favicon": parser.favicon,
                "canonical": parser.canonical,
                "og_title": parser.meta_tags.get("og:title"),
                "og_type": parser.meta_tags.get("og:type"),
                "og_image": parser.meta_tags.get("og:image"),
                "twitter_card": parser.meta_tags.get("twitter:card"),
                "theme_color": parser.meta_tags.get("theme-color"),
            },
            "link_count": parser.links,
            "links": parser.link_urls,
            "same_origin_links": list(dict.fromkeys(same_origin)),
            "external_links": list(dict.fromkeys(external)),
            "forms": parser.forms,
            "form_details": parser.form_details,
            "scripts": [r["url"] for r in parser.resources if r["type"] == "script"],
            "external_scripts_without_sri": list(dict.fromkeys(parser.external_scripts_without_sri)),
            "resource_count": len(parser.resources),
            "resource_origins": sorted({
                f'{urlsplit(r["url"]).scheme}://{urlsplit(r["url"]).netloc}'
                for r in parser.resources
                if urlsplit(r["url"]).netloc
            }),
            "http_resources_on_https": [
                r for r in parser.resources if https and urlsplit(r["url"]).scheme == "http"
            ],
        }
    return result


def build_findings(report):
    findings = []

    def add(code, priority, evidence, action, severity=None, confidence="high", classification="configuration_observation"):
        item = {
            "id": code,
            "priority": priority,
            "confidence": confidence,
            "classification": classification,
            "evidence": redact_sensitive(evidence),
            "recommendation": action,
            "remediation": action,
        }
        if severity:
            item["severity"] = severity
        findings.append(item)

    if report["target"].startswith("http://"):
        add(
            "unencrypted-http",
            "review",
            "The supplied URL uses HTTP.",
            "Use HTTPS and verify the HTTP-to-HTTPS redirect separately.",
            severity="low",
        )
    recommendations = {
        "content-security-policy": "Inventory required script/style origins, trial Content-Security-Policy-Report-Only, then enforce a policy with nonces or hashes where appropriate.",
        "x-content-type-options": "Serve correct Content-Type values and configure X-Content-Type-Options: nosniff.",
        "referrer-policy": "Review whether Referrer-Policy: strict-origin-when-cross-origin meets application privacy requirements.",
        "permissions-policy": "Disable unused browser features through an application-specific Permissions-Policy.",
        "strict-transport-security": "After verifying HTTPS coverage, configure Strict-Transport-Security; evaluate subdomains before includeSubDomains.",
    }
    for header in report["headers"]:
        if header["state"] != "present":
            add(
                "header-" + header["header"],
                "review",
                f"{header['header']}: {header['state']} on this response.",
                recommendations.get(header["header"], header["purpose"]),
                severity="info",
            )
    for cookie in report["cookies"]:
        missing = [flag for flag in ("secure", "httponly") if not cookie[flag]]
        if missing:
            only_httponly_missing = missing == ["httponly"]
            sensitive = cookie.get("likely_sensitive", False)
            sev = "info" if (only_httponly_missing and not sensitive) else "low"
            conf = "medium" if not sensitive else "high"
            add(
                "cookie-flags",
                "review",
                f"Cookie {cookie['name']}: absent {', '.join(missing)}.",
                "Determine whether this cookie holds session or authentication state before changing its flags; non-sensitive preference/UI cookies may intentionally omit HttpOnly.",
                severity=sev,
                confidence=conf,
            )
    html = report["content"].get("html")
    if html and html["http_resources_on_https"]:
        add(
            "mixed-content-references",
            "review",
            html["http_resources_on_https"],
            "Replace HTTP resource references with HTTPS; verify browser behavior and CSP.",
            severity="low",
        )
    return findings
