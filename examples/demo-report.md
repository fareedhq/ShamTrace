# ShamTrace assessment

## Executive assessment

| Conclusion |
| --- |
| Target returned HTTP 200; Certificate verified; TLS details unavailable. |
| Technology fingerprints observed: nginx 1.24.0 (medium), DemoCMS 2.1.0 (medium). Version banners alone are unverified claims and not proof of CVEs. |
| https://demo-fixture.local.test/robots.txt: recognized — Recognized robots directives; rule semantics not evaluated. |
| https://demo-fixture.local.test/sitemap.xml: not\_found — HTTP 404; metadata document was checked and is not present. |
| https://demo-fixture.local.test/.well-known/security.txt: not\_found — HTTP 404; metadata document was checked and is not present. |
| DNS AAAA: no answer for this hostname; this alone is not a vulnerability. |
| Advisory lookup: disabled; 0 candidate matches. Use --cve to query OSV with detected package names and versions. |
| Absence of findings or skipped/failed checks does not establish that the target is secure. |

## Scope, infrastructure, and transport

| Item | Evidence |
| --- | --- |
| Target | https://demo-fixture.local.test |
| Final URL (in-scope) | https://demo-fixture.local.test |
| Time (UTC) | 2026-10-18T15:14:56.543222+00:00 |
| Profile | extended |
| Scan completion | Complete |
| HTTP status | 200 |
| TLS connection (negotiated) | Certificate verified; TLS details unavailable |
| TLS audit scope | single\_connection\_only |
| Server claim | nginx/1.24.0 |
| WAF / Firewall detection | No explicit WAF signature |
| HSTS preload status | Not advertised |
| Resolved IPs | 192.0.2.10 |
| Route | direct |
| Privacy | Direct connection: target sees your network egress address |
| Target requests | 6 |
| Advisory requests | 0 |

## Module status

| Module | Status | Detail |
| --- | --- | --- |
| dns | completed | Queried 5 DNS record types. |
| http | completed | HTTP 200 from https://demo-fixture.local.test |
| tls | completed | Certificate verified; TLS details unavailable (single connection; not a full cipher/protocol audit) |
| headers\_cookies\_cors | completed | Evaluated 5 security headers, 1 cookie(s), and CORS (not\_advertised). |
| metadata | completed | Checked 3 metadata paths (0 error(s)). |
| scripts | completed | Inspected 1 same-origin script(s) (2 discovered). |
| crawl | completed | Visited 1 additional in-scope page(s) (budget: 2). |
| advisories | skipped | Use --cve to query OSV with detected package names and versions. |
| whatweb | skipped | Not requested (use --whatweb to enable). |
| fingerprinting | completed | Consolidated 2 unique technology fingerprint(s). |
| nmap | skipped | Not requested (use --nmap-ports PORTS to scan specific in-scope ports). |

## Findings requiring review

| Finding / URL | Classification | Severity & Rationale | Confidence | Evidence | Limitations | Remediation |
| --- | --- | --- | --- | --- | --- | --- |
| Header content security policy — https://demo-fixture.local.test, https://demo-fixture.local.test/docs?page=1 | configuration\_observation | INFO: Informational hardening gap; CSP mitigates XSS impact but requires application-specific tuning. | high | content-security-policy: missing on this response. | Absence of CSP is a defense-in-depth hardening observation, not proof of an XSS vulnerability. | Inventory required script/style origins, trial Content-Security-Policy-Report-Only, then enforce a policy with nonces or hashes where appropriate. |
| Header referrer policy — https://demo-fixture.local.test, https://demo-fixture.local.test/docs?page=1 | configuration\_observation | INFO: Informational hardening gap; explicit Referrer-Policy prevents unintended cross-origin URL disclosure. | high | referrer-policy: missing on this response. | Impact depends on whether sensitive tokens or identifiers appear in application URLs. | Review whether Referrer-Policy: strict-origin-when-cross-origin meets application privacy requirements. |
| Header permissions policy — https://demo-fixture.local.test, https://demo-fixture.local.test/docs?page=1 | configuration\_observation | INFO: Informational hardening gap; restricts access to powerful browser APIs. | high | permissions-policy: missing on this response. | Browser feature restriction is hardening; absence alone is not an exploitable flaw. | Disable unused browser features through an application-specific Permissions-Policy. |
| No recognized response-header framing restriction — https://demo-fixture.local.test, https://demo-fixture.local.test/docs?page=1 | configuration\_observation | LOW: Without frame-ancestors or X-Frame-Options, HTML pages can be framed by external origins. | high | \{&quot;x-frame-options&quot;: null, &quot;csp-frame-ancestors&quot;: null\} | Clickjacking risk applies only if the page contains state-changing interactive UI elements. | Decide whether embedding is needed; configure CSP frame-ancestors accordingly. Clickjacking impact requires UI validation. |
| Header x content type options — https://demo-fixture.local.test/docs?page=1 | configuration\_observation | INFO: Informational hardening gap; nosniff prevents browsers from MIME-sniffing non-executable responses. | high | x-content-type-options: missing on this response. | Exploitability depends on whether user-controlled content can be uploaded or reflected with ambiguous MIME types. | Serve correct Content-Type values and configure X-Content-Type-Options: nosniff. |
| Header strict transport security — https://demo-fixture.local.test/docs?page=1 | configuration\_observation | INFO: Informational hardening gap; HSTS instructs browsers to enforce HTTPS on future connections. | high | strict-transport-security: missing on this response. | HSTS applies only after a browser has completed an initial trusted HTTPS connection. | After verifying HTTPS coverage, configure Strict-Transport-Security; evaluate subdomains before includeSubDomains. |

## Discovery inventory

| Artifact Type | URL / Path | Discovery Source | Notes |
| --- | --- | --- | --- |
| link | https://demo-fixture.local.test/docs?page=1 | https://demo-fixture.local.test | In-scope HTML link |
| form (POST) | https://demo-fixture.local.test/auth/login | https://demo-fixture.local.test | HTML form action |
| script | https://demo-fixture.local.test/static/app.js | https://demo-fixture.local.test | Public script reference |
| script | https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js | https://demo-fixture.local.test | Public script reference |
| endpoint\_candidate | /api/v1/health | script:https://demo-fixture.local.test/static/app.js | Static string hint (unverified) |
| endpoint\_candidate | /internal | robots:https://demo-fixture.local.test/robots.txt | Static string hint (unverified) |

## Technology fingerprints (unverified claims)

| Technology | Category | Version | Confidence | Evidence | Caveat |
| --- | --- | --- | --- | --- | --- |
| nginx | web\_server | 1.24.0 | medium | Server header: nginx/1.24.0 | Passive fingerprint/banner claim; version strings alone are not proof of a vulnerability. |
| DemoCMS | cms\_generator | 2.1.0 | medium | Meta generator: DemoCMS 2.1.0 | Passive fingerprint/banner claim; version strings alone are not proof of a vulnerability. |

## DNS evidence

| Name / type | State | TTL | Records / Authority Response | Interpretation |
| --- | --- | --- | --- | --- |
| demo-fixture.local.test / A | ok | 300 | 192.0.2.10 | Resolved 1 IPv4 address(es). |
| demo-fixture.local.test / AAAA | no\_answer | — | 0 AAAA records (IPv4-only) \[SOA: authoritative NS\] | Hostname exists (NODATA), but no IPv6 (AAAA) record is configured. |
| demo-fixture.local.test / CNAME | no\_answer | — | Apex routed via A (192.0.2.10) \[SOA: authoritative NS\] | No CNAME record (expected at zone apex; RFC 1034/2181 prohibits CNAME alongside NS/SOA). |
| demo-fixture.local.test / TXT | ok | 3600 | &quot;v=spf1 -all&quot; | TXT records present (includes SPF policy). |
| \_dmarc.demo-fixture.local.test / TXT | ok | 3600 | &quot;v=DMARC1; p=reject&quot; | DMARC policy record published. |

## HTTP header evidence

| Header | State | Quality | Value | Evaluation |
| --- | --- | --- | --- | --- |
| content-security-policy | missing | missing | Not available | Header not present in response. |
| x-content-type-options | present | strong | nosniff | Strict MIME-sniffing protection enabled. |
| referrer-policy | missing | missing | Not available | Header not present in response. |
| permissions-policy | missing | missing | Not available | Header not present in response. |
| strict-transport-security | present | strong | max-age=63072000; includeSubDomains | max-age=63072000 (&gt;= 1 year). |

## CORS configuration

| Field | Observation |
| --- | --- |
| State | not\_advertised |
| Access-Control-Allow-Origin | Not available |
| Access-Control-Allow-Credentials | Not available |
| Access-Control-Allow-Methods | Not available |
| Vary includes Origin | False |
| Notes | No CORS headers advertised. |
| Limitations | Passive inspection of a standard response; dynamic Origin reflection requires active cross-origin preflight testing. |

## Metadata validation

| URL | HTTP | Result | Explanation |
| --- | --- | --- | --- |
| https://demo-fixture.local.test/robots.txt | 200 | recognized | Recognized robots directives; rule semantics not evaluated. |
| https://demo-fixture.local.test/sitemap.xml | 404 | not\_found | HTTP 404; metadata document was checked and is not present. |
| https://demo-fixture.local.test/.well-known/security.txt | 404 | not\_found | HTTP 404; metadata document was checked and is not present. |

## Cookie metadata (values excluded)

| Name | Prefix | Prefix Valid | Secure | HttpOnly | SameSite |
| --- | --- | --- | --- | --- | --- |
| \_\_Host-session | \_\_Host- | True | True | True | not specified |

## Component inventory

| Package | Version | Confidence | Evidence |
| --- | --- | --- | --- |
| jquery | 3.7.1 | medium | https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js |

## Advisory / CVE candidates

| Package / status | Advisory | Aliases | Summary |
| --- | --- | --- | --- |
| disabled | Use --cve to query OSV with detected package names and versions. |  |  |

## Script evidence

| URL | Result | Bytes / truncated | Unverified API paths |
| --- | --- | --- | --- |
| https://demo-fixture.local.test/static/app.js | analyzed | 24 / False | \[&quot;/api/v1/health&quot;\] |

## Discovered pages

| URL | HTTP | State | Title |
| --- | --- | --- | --- |
| https://demo-fixture.local.test/docs?page=1 | 200 | observed | Docs Page 1 |

## Certificate evidence

| Field | Value |
| --- | --- |
| No evidence collected in this section. |  |

## WhatWeb integration

| Plugin / Status | Version / Reason | Confidence | Detail |
| --- | --- | --- | --- |
| skipped | Not requested (use --whatweb to enable). |  |  |

## Nmap scoped port scan

| Port / Status | State / Reason | Service | Banner claim (non-CVE) |
| --- | --- | --- | --- |
| skipped | Not requested (use --nmap-ports PORTS to scan specific in-scope ports). |  |  |

## Coverage gaps

| Not established |
| --- |
| No JavaScript execution, authenticated browsing, or interaction with forms. |
| Module &#x27;advisories&#x27; was skipped: Use --cve to query OSV with detected package names and versions.. |
| Module &#x27;whatweb&#x27; was skipped: Not requested (use --whatweb to enable).. |
| Module &#x27;nmap&#x27; was skipped: Not requested (use --nmap-ports PORTS to scan specific in-scope ports).. |
| No exploit validation, full port inventory, or full TLS protocol/cipher configuration audit. HTML traversal is limited by the page budget. |

## Limitations

| Interpretation |
| --- |
| In-scope redirects are followed up to 5 hops; out-of-scope redirects are blocked. HTML traversal follows the --pages budget; extended adds three metadata requests and up to three scripts. |
| Document inspection is capped at 512 KiB of decoded content; no JavaScript execution. |
| HTML observations describe source markup, not browser runtime behavior. |
| Header values and policies are passively evaluated; application context is required. |
| Missing headers are hardening observations, not proof of an exploitable vulnerability. |
| Server, framework, and generator banners are unverified claims and never proof of CVEs. |
| TLS reports the single negotiated connection and certificate, not all server-supported protocols or ciphers. |
| Cookie flags require context; non-sensitive preference cookies may intentionally omit HttpOnly. |
| DNS lists resolution results, not a verified connected peer. |
| The timeout applies to network operations, not a hard whole-scan deadline. |
| Sensitive tokens, authentication headers, and cookie values are redacted. |
