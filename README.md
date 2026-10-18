<div align="center">

```ascii
  ____  _                     _____                     
 / ___|| |__   __ _ _ __ ___ |_   _| __ __ _  ___ ___   
 \___ \| '_ \ / _` | '_ ` _ \  | || '__/ _` |/ __/ _ \  
  ___) | | | | (_| | | | | | | | || | | (_| | (_|  __/  
 |____/|_| |_|\__,_|_| |_| |_| |_||_|  \__,_|\___\___|  
```

### Tactical Web Security, Attack Surface & Vulnerability Auditing Engine

[![Tests](https://github.com/fareedhq/ShamTrace/actions/workflows/tests.yml/badge.svg)](https://github.com/fareedhq/ShamTrace/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE)
[![Standards](https://img.shields.io/badge/Security-CWE%20%7C%20OWASP%20%7C%20CVSS-orange.svg)](#)
[![Reports](https://img.shields.io/badge/Reports-HTML%20%7C%20JSON%20%7C%20Markdown-informational.svg)](#)
[![Mode](https://img.shields.io/badge/Mode-Evidence--First-emerald.svg)](#)

<p align="center">
  <b>ShamTrace</b> is an evidence-first web security configuration, attack surface, and vulnerability assessment engine.<br>
  Built for penetration testers, security engineers, and developers who require verifiable proof over noise.
</p>

[Quick Start](#quick-start) •
[Key Capabilities](#key-capabilities) •
[Vulnerability Modules](#vulnerability--exposure-modules) •
[Dashboard UI](#enterprise-saas-dashboard) •
[CLI Reference](#cli-usage-reference) •
[Contributing](#contributing--license)

---

</div>

## Quick Start

### 1. Installation

Requires **Python 3.10+**:

```bash
git clone https://github.com/fareedhq/ShamTrace.git
cd ShamTrace

# Create virtual environment and install in editable mode
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# (Optional) Link globally so you can run 'shamtrace' from any terminal
ln -sf $(pwd)/.venv/bin/shamtrace ~/.local/bin/shamtrace
```

### 2. Run an Assessment

```bash
# Standard comprehensive scan with exposure probes, DNSSEC, and vulnerability mapping
shamtrace scan https://your-target.example --authorized --pages 3 --cve

# Fast terminal-only inspection without writing report files to disk
shamtrace scan https://your-target.example --authorized --terminal
```

### 3. Open the Offline SaaS Dashboard

```bash
# View the generated self-contained Enterprise HTML dashboard
xdg-open results/*.html
# Or open in macOS: open results/*.html
```

---

## Key Capabilities

| Layer | Assessment Capabilities | Validation & Quality |
| :--- | :--- | :--- |
| **Vulnerability & Exposure** | Probes `/.env`, `/.git/HEAD`, `/_ignition`, `/actuator`, `/phpinfo`, `/swagger.json`, `/server-status`, `/.DS_Store` | Anti-False-Positive structural signature checks (never flags custom SPA 404 pages) |
| **Credential & Secret Leaks** | Passively inspects JS bundles for AWS Keys, GCP API Keys, Stripe Keys, GitHub/GitLab PATs, Private Keys | High-confidence regex with automatic `[REDACTED]` masking in all reports |
| **Attack Surface Discovery** | Detects Subdomain Takeover CNAMEs, DOM XSS sink candidates, Open Redirect & SSRF parameters | Evidence-first passive telemetry |
| **DNS & Infrastructure** | Queries `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, `CAA`, `_dmarc`, `DNSSEC` (`DNSKEY/DS/RRSIG`), `PTR` | Cross-referenced against 12 Security & Family Blocklists |
| **Transport & SSL/TLS** | X.509 DER Fingerprints (`SHA-1/256/512`), SANs, Serial, Expiry, HSTS Preload readiness | Distinguishes single connection from whole-server cipher audit |
| **Web Hardening Policies** | Deep audit of `CSP`, `HSTS`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `CORS`, `__Host-` cookies | RFC & W3C compliance checks without treating unauthenticated wildcards as flaws |
| **VAPT Taxonomy** | Every finding mapped to **CWE IDs**, **OWASP Top 10 (2021)**, and **CVSS v3.1** scores | Standardized for penetration testing & compliance audits |
| **Integrity & CSRF** | Checks Subresource Integrity (`integrity="sha..."`) and detects unauthenticated state-changing forms | Evaluates same-origin and cross-origin forms |

---

## Vulnerability & Exposure Modules

### 1. Sensitive File & Configuration Exposure
Safely checks high-risk paths using strict signature verification to eliminate false positives:
- **`/.env`**: Detects exposed environment credentials (`DB_PASSWORD=`, `APP_KEY=`, `AWS_`, `SECRET_KEY=`) -> **HIGH (CVSS 7.5, CWE-538)**
- **`/.git/HEAD`**: Detects exposed Git repository refs (`ref: refs/heads/...`) -> **HIGH (CVSS 7.5, CWE-538)**
- **`/_ignition/health-check`**: Detects exposed Laravel Ignition debug mode (`CVE-2021-3129` surface) -> **HIGH (CVSS 8.6, CWE-489)**
- **`/actuator/health`**: Detects Spring Boot Actuator endpoints -> **LOW (CVSS 3.7, CWE-200)**
- **`/phpinfo.php`**: Detects PHP diagnostic disclosure -> **MEDIUM (CVSS 5.3, CWE-200)**
- **`/wp-json/wp/v2/users`**: Detects WordPress REST API user enumeration -> **MEDIUM (CVSS 5.3, CWE-200)**
- **`/swagger.json` / `/openapi.json`**: Detects public API specifications -> **LOW (CVSS 3.7, CWE-200)**

### 2. JavaScript Secret & DOM XSS Sink Scanner
Audits inspected JavaScript bundles with zero execution:
- **Hardcoded Credentials**: Identifies AWS Access Keys (`AKIA...`), Google API Keys (`AIza...`), Stripe Live Keys (`sk_live_...`), GitHub PATs (`ghp_...`), GitLab PATs (`glpat-...`), Slack tokens/webhooks, and RSA/EC Private Key headers.
- **Source Map Disclosure**: Identifies production `//# sourceMappingURL=*.js.map` references allowing reconstruction of unminified frontend source code.
- **DOM XSS Sink Candidates**: Identifies dangerous sinks (`innerHTML =`, `document.write(`, `eval(`) receiving data from URL/location sources (`location.search`, `location.hash`, `URLSearchParams`).

### 3. Subdomain Takeover & Dangling DNS
Monitors `CNAME` records pointing to external cloud services (GitHub Pages, Heroku, AWS S3, Vercel, Netlify, Azure, Fastly, Shopify, Fly.io, Render) that return `404 Not Found` or unclaimed resource error signatures.

### 4. HTTP Dangerous Methods & Open Redirect Surface
- Sends an `OPTIONS` query to verify if state-modifying or dangerous methods (`PUT`, `DELETE`, `TRACE`, `PROPFIND`) are advertised.
- Passively catalogs parameters in discovered URLs matching common Open Redirect patterns (`?redirect=`, `?next=`, `?returnUrl=`) and SSRF patterns (`?url=`, `?file=`, `?path=`, `?webhook=`).

---

## Enterprise SaaS Dashboard

Every assessment generates a self-contained, offline HTML dashboard styled in a clean, modern Enterprise SaaS UI:

<div align="center">
  <img src="https://raw.githubusercontent.com/fareedhq/ShamTrace/main/examples/demo-preview.png" alt="ShamTrace Dashboard" width="900" onerror="this.style.display='none'"/>
</div>

- **Fixed Left Sidebar Navigation**: Quick jumps between *Dashboard*, *Module Telemetry*, *Security Findings*, *DNS Evidence*, *SSL / Certificate*, and *Exposure Probes*.
- **Top KPI Stat Cards**: Mini sparklines displaying HTTP status & latency, review items, active modules, and surface requests.
- **Side-by-Side Analytics**:
  - *Telemetry & Surface Matrix*: 12-column waffle block chart visualizing discovered vs active evidence.
  - *Security Posture Breakdown*: 8-pillar vertical chart showing implementation rate for `HSTS`, `CSP`, `XFO`, `XCTO`, `REF`, `PERM`, `TLS`, and `DNS`.
- **Pure-CSS Filtering**: Interactive filtering by Severity (`High`, `Medium`, `Low`, `Info`) and Classification without running any client-side JavaScript.
- **100% Offline & Private**: Zero CDN requests, zero font downloads, zero `<script>` tags, enforced by strict `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`.

---

## CLI Usage Reference

```
usage: shamtrace scan [-h] [-t SECONDS] [-o DIR] [--profile {basic,extended}]
                      [--no-follow-redirects] [--pages 1..10] [--retries 0..3]
                      [--rate-limit REQ_S] [--concurrency 1..16] [--max-requests 1..100]
                      [--max-duration SECONDS] [--cve] [--whatweb] [--nmap-ports PORTS]
                      [--allow-shared-ip] [--tor] [--proxy SOCKS_URL] [--require-proxy]
                      [--no-color] [--authorized] [-v] [-T] [--no-save]
                      [--vuln-scan | --no-vuln-scan]
                      url
```

### Common Commands

```bash
# Standard extended profile scan
shamtrace scan https://target.id --authorized

# Deep scan: 3-page crawl, rate-limited to 2 req/s, query OSV CVEs
shamtrace scan https://target.id --authorized --pages 3 --rate-limit 2 --cve

# Fast terminal output without saving report files
shamtrace scan https://target.id --authorized --terminal

# Anonymous scan routed via local Tor SOCKS proxy (127.0.0.1:9050)
shamtrace scan https://target.id --authorized --tor

# Optional external tool integrations (WhatWeb passive plugins & Nmap on specific ports)
shamtrace scan https://target.id --authorized --whatweb --nmap-ports 80,443,8080 -o results

# Rebuild HTML and Markdown reports from an existing JSON report without re-requesting the target
shamtrace report results/shamtrace-20261018T120000000000Z.json
```

<details>
<summary><b>Detailed Options & Flags</b></summary>

| Flag | Default | Description |
| :--- | :--- | :--- |
| `url` | *required* | Target URL (defaults to `https://` if scheme is omitted). |
| `-t, --timeout` | `15` | Network operation timeout in seconds (1..120). |
| `-o, --output` | `results` | Output directory for report files. |
| `--profile` | `extended` | `basic` (single response) or `extended` (DNS, metadata, scripts, exposures). |
| `--pages` | `1` | Maximum HTML pages to crawl within the same origin (1..10). |
| `--rate-limit` | `0.0` | Maximum requests per second (0 = unthrottled). |
| `--retries` | `0` | Number of retries for transient network timeouts (0..3). |
| `--concurrency`| `4` | Concurrent workers for DNS lookups (1..16). |
| `--cve` | `False` | Query OSV database for known package version CVEs. |
| `--terminal, -T`| `False` | Output detailed Rich tables directly in terminal without saving files. |
| `-v, --verbose`| `False` | Show detailed evidence tables in the terminal while still saving files. |
| `--vuln-scan` | `True` | Run active sensitive path exposure and HTTP method probes in extended profile. |
| `--tor` | `False` | Route all traffic via SOCKS5 proxy at `127.0.0.1:9050`. |
| `--whatweb` | `False` | Run passive WhatWeb fingerprinting (aggression 1). |
| `--nmap-ports` | `None` | Run scoped Nmap service scan on specified ports (e.g. `80,443,8080`). |
| `--allow-shared-ip` | `False` | Explicitly permit Nmap scans against shared CDN/cloud edge IPs. |

</details>

---

## Security, Scope & Boundaries

ShamTrace adheres strictly to defensive assessment standards:
1. **Zero Exploitation**: ShamTrace never injects active exploits, SQLi payloads, command injection strings, or brute-force requests.
2. **Anti-Denial-of-Service**: Strict concurrency controls, per-second rate limiters, and hard duration deadlines prevent accidental traffic spikes.
3. **Leak-Free Proxying**: When `--proxy` or `--tor` is configured, target DNS is never resolved locally, preventing DNS leakage.
4. **Shared Edge Protection**: Scans against Cloudflare, Vercel, Fastly, or CloudFront edge IPs automatically protect third-party tenants by suppressing raw port scans unless overridden.
5. **Data Redaction**: Sensitive cookie values, Bearer tokens, Authorization headers, and sensitive query parameters are redacted (`[REDACTED]`) before saving reports.

---

## Contributing & License

Contributions are welcome! Please review [SECURITY.md](SECURITY.md) before submitting security-related issues.

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
