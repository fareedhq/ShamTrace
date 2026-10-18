# Security Policy

## Responsible Disclosure & Scope

**ShamTrace** is designed strictly for defensive assessment, reconnaissance, and security posture validation on systems that you own or have explicit written permission to test.

We take the security of this project and the safety of networks inspected by it seriously.

### Reporting a Vulnerability

If you discover a security vulnerability within ShamTrace itself (such as a memory leak, regex denial of service, unintended egress leak when using SOCKS proxy, or sanitization failure in HTML/JSON reports):

1. **Do not open a public issue.**
2. Send an email to the project maintainers with details, reproduction steps, and proof-of-concept evidence.
3. We will acknowledge receipt within 48 hours and work with you to triage and release a patch.

### Ethical Use Guidelines

- Always ensure you have authorization before performing vulnerability assessments or network inspections.
- ShamTrace incorporates strict rate-limiting (`--rate-limit`), concurrency controls (`--concurrency`), and request budgets (`--max-requests`, `--max-duration`) to prevent unintended denial of service on audited targets.
- External port scanning via Nmap against detected shared edge/CDN IPs is blocked by default to prevent accidental cross-tenant port probing.
