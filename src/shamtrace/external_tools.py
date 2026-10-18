"""Strictly scoped, opt-in integrations for WhatWeb and Nmap without shell execution or shared-CDN port scanning."""
import json
import re
import shutil
import subprocess
from xml.etree import ElementTree
from .checks import redact_sensitive

MAX_NMAP_PORTS = 100
_PORT_TOKEN_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def parse_ports(port_spec):
    """Validate and normalize a user-supplied port list (e.g. '80,443,8000-8005')."""
    if port_spec is None:
        return []
    raw = str(port_spec).strip()
    if not raw:
        raise ValueError("Port specification cannot be empty.")
    ports = set()
    for part in raw.split(","):
        token = part.strip()
        if not token:
            raise ValueError(f"Invalid empty port token in {port_spec!r}.")
        match = _PORT_TOKEN_RE.match(token)
        if not match:
            raise ValueError(f"Invalid port specification {token!r}; use e.g. '80,443,8080-8085'.")
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) is not None else start
        if not (1 <= start <= 65535 and 1 <= end <= 65535) or start > end:
            raise ValueError(f"Port range {token!r} must be between 1 and 65535 with start <= end.")
        if (end - start + 1) > MAX_NMAP_PORTS or (len(ports) + (end - start + 1)) > MAX_NMAP_PORTS:
            raise ValueError(f"At most {MAX_NMAP_PORTS} ports may be scanned in a single scoped run.")
        ports.update(range(start, end + 1))
    return sorted(ports)


def run_whatweb(target_url, timeout=15, enabled=False, proxy=None):
    """Run WhatWeb passively/quietly (aggression 1, no redirects) if explicitly enabled."""
    if not enabled:
        return {
            "tool": "whatweb",
            "status": "skipped",
            "reason": "Not requested (use --whatweb to enable).",
            "plugins": [],
        }
    if proxy:
        return {
            "tool": "whatweb",
            "status": "skipped",
            "reason": "Skipped when SOCKS proxy/Tor is active to prevent direct egress leakage.",
            "plugins": [],
        }
    binary = shutil.which("whatweb")
    if not binary:
        return {
            "tool": "whatweb",
            "status": "skipped",
            "reason": "whatweb binary not found in system PATH.",
            "plugins": [],
        }
    cmd = [
        binary,
        "--color=never",
        "--no-errors",
        "--aggression=1",
        "--follow-redirect=never",
        "--max-threads=1",
        "--log-json=-",
        target_url,
    ]
    try:
        completed = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=max(5.0, min(float(timeout), 60.0)),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "tool": "whatweb",
            "status": "failed",
            "reason": "whatweb timed out before completion.",
            "plugins": [],
        }
    except OSError as error:
        return {
            "tool": "whatweb",
            "status": "failed",
            "reason": f"Failed to execute whatweb: {error}",
            "plugins": [],
        }

    plugins = []
    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        raw_plugins = entry.get("plugins") or {}
        for name, details in raw_plugins.items():
            if name in {"IP", "Country", "Title"} or not isinstance(details, dict):
                continue
            versions = details.get("version") or []
            strings = details.get("string") or []
            plugins.append({
                "name": name,
                "version": ", ".join(str(v) for v in versions[:3]) if versions else None,
                "detail": redact_sensitive(", ".join(str(s) for s in strings[:3])) if strings else None,
                "confidence": "medium",
            })

    if completed.returncode != 0 and not plugins:
        err_msg = (completed.stderr or "").strip()[:200] or f"Exit code {completed.returncode}"
        return {
            "tool": "whatweb",
            "status": "failed",
            "reason": f"whatweb exited with error: {err_msg}",
            "plugins": [],
        }

    return {
        "tool": "whatweb",
        "status": "completed",
        "reason": "Aggression level 1 (single request, redirects disabled).",
        "plugins": plugins,
        "limitations": "WhatWeb plugin matches are passive banner/signature hints and do not confirm vulnerabilities.",
    }


def run_nmap(hostname, port_spec=None, timeout=30, proxy=None, shared_edge=None, allow_shared_ip=False):
    """Run Nmap TCP connect scan on explicitly specified in-scope ports, blocking shared CDN/edge IPs by default."""
    if not port_spec:
        return {
            "tool": "nmap",
            "status": "skipped",
            "reason": "Not requested (use --nmap-ports PORTS to scan specific in-scope ports).",
            "ports": [],
        }
    ports = parse_ports(port_spec)
    if proxy:
        return {
            "tool": "nmap",
            "status": "skipped",
            "reason": "Skipped when SOCKS proxy/Tor is active to prevent direct TCP/DNS egress leakage.",
            "requested_ports": ports,
            "ports": [],
        }
    if not hostname or hostname.endswith(".onion"):
        return {
            "tool": "nmap",
            "status": "skipped",
            "reason": "Target hostname is not eligible for direct Nmap port inspection.",
            "requested_ports": ports,
            "ports": [],
        }
    if shared_edge and shared_edge.get("is_shared_edge") and not allow_shared_ip:
        providers = ", ".join(shared_edge.get("providers") or ["Shared CDN/Edge"])
        return {
            "tool": "nmap",
            "status": "skipped",
            "reason": (
                f"Target resolves to shared CDN/cloud edge infrastructure ({providers}). "
                "Port scanning shared multi-tenant IPs is blocked unless --allow-shared-ip is explicitly supplied."
            ),
            "requested_ports": ports,
            "ports": [],
        }
    binary = shutil.which("nmap")
    if not binary:
        return {
            "tool": "nmap",
            "status": "skipped",
            "reason": "nmap binary not found in system PATH.",
            "requested_ports": ports,
            "ports": [],
        }

    port_arg = ",".join(str(p) for p in ports)
    host_timeout = max(5, min(int(float(timeout) * 2), 120))
    cmd = [
        binary,
        "-Pn",
        "-sT",
        "-sV",
        "--version-light",
        "-T3",
        f"--host-timeout={host_timeout}s",
        "-p",
        port_arg,
        "-oX",
        "-",
        hostname,
    ]
    try:
        completed = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=host_timeout + 5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "tool": "nmap",
            "status": "failed",
            "reason": "nmap timed out before completion.",
            "requested_ports": ports,
            "ports": [],
        }
    except OSError as error:
        return {
            "tool": "nmap",
            "status": "failed",
            "reason": f"Failed to execute nmap: {error}",
            "requested_ports": ports,
            "ports": [],
        }

    xml_text = completed.stdout or ""
    if "<!ENTITY" in xml_text.upper():
        return {
            "tool": "nmap",
            "status": "failed",
            "reason": "Refused XML output containing ENTITY declarations.",
            "requested_ports": ports,
            "ports": [],
        }

    parsed_ports = []
    try:
        root = ElementTree.fromstring(xml_text)
        for port_el in root.findall(".//port"):
            state_el = port_el.find("state")
            service_el = port_el.find("service")
            state = state_el.get("state") if state_el is not None else "unknown"
            service_name = service_el.get("name") if service_el is not None else None
            product = service_el.get("product") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None
            parsed_ports.append({
                "port": int(port_el.get("portid", "0")),
                "protocol": port_el.get("protocol", "tcp"),
                "state": state,
                "service": service_name,
                "product": product,
                "version": version,
            })
    except ElementTree.ParseError:
        err_msg = (completed.stderr or "").strip()[:200] or f"Exit code {completed.returncode}"
        return {
            "tool": "nmap",
            "status": "failed",
            "reason": f"Could not parse nmap XML output ({err_msg}).",
            "requested_ports": ports,
            "ports": [],
        }

    return {
        "tool": "nmap",
        "status": "completed",
        "reason": f"Scanned {len(ports)} user-specified port(s) on {hostname}.",
        "requested_ports": ports,
        "ports": parsed_ports,
        "limitations": "Service and version strings are banner claims from TCP connect probes, not proof of exploitable CVEs.",
    }
