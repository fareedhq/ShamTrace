"""Explicit opt-in OSV queries for versioned npm CDN references."""
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit
import httpx

ENDPOINT = 'https://api.osv.dev/v1/query'
VERSION = r'(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)'


def identify_components(urls):
    components = {}
    for url in urls:
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or parsed.hostname not in {'cdn.jsdelivr.net', 'unpkg.com'}:
            continue
        prefix = '/npm/' if parsed.hostname == 'cdn.jsdelivr.net' else '/'
        match = re.fullmatch(re.escape(prefix) + r'(@[\w.-]+/[\w.-]+|[\w.-]+)@' + VERSION + r'(?:/.*)?', parsed.path)
        if match:
            name, version = match.groups()
            components[(name, version)] = {
                'ecosystem': 'npm', 'name': name, 'version': version,
                'confidence': 'medium', 'evidence': parsed._replace(query='', fragment='').geturl(),
                'basis': 'Explicit version in CDN reference; served package contents not independently verified.',
            }
    return list(components.values())


def lookup_advisories(client, components, enabled=False):
    report = {'provider': 'OSV', 'status': 'disabled', 'requests': 0, 'results': [],
              'queried_at': None, 'limitations': 'Package-version advisory matches are candidates, not confirmed exploitable website vulnerabilities.'}
    if not enabled:
        report['reason'] = 'Use --cve to query OSV with detected package names and versions.'
        return report
    if not components:
        report.update(status='not_applicable', reason='No supported exact package versions detected. Server names and bundle hashes are insufficient.')
        return report
    report.update(status='complete', queried_at=datetime.now(timezone.utc).isoformat())
    if len(components) > 10:
        report.update(status='partial', reason='At most ten package versions queried.')
    for component in components[:10]:
        result = {'component': component, 'status': 'ok', 'advisories': []}
        report['requests'] += 1
        try:
            with client.stream('POST', ENDPOINT, json={
                'package': {'ecosystem': component['ecosystem'], 'name': component['name']},
                'version': component['version'],
            }) as response:
                response.raise_for_status()
                raw = bytearray()
                for chunk in response.iter_bytes(chunk_size=16384):
                    if len(raw) + len(chunk) > 2 * 1024 * 1024:
                        raise ValueError('Advisory response exceeds 2 MiB limit.')
                    raw.extend(chunk)
                data = json.loads(raw)
            if not isinstance(data, dict) or not isinstance(data.get('vulns', []), list):
                raise ValueError('Invalid advisory response schema.')
            for vuln in data.get('vulns', []):
                if not isinstance(vuln, dict) or not isinstance(vuln.get('id'), str):
                    raise ValueError('Invalid advisory record.')
                if vuln.get('withdrawn'):
                    continue
                result['advisories'].append({
                    'id': vuln['id'], 'aliases': vuln.get('aliases', []),
                    'summary': vuln.get('summary', 'No summary supplied.'),
                    'severity': vuln.get('severity', []),
                    'references': vuln.get('references', []),
                    'modified': vuln.get('modified'),
                })
            if data.get('next_page_token'):
                result.update(status='partial', reason='OSV has further pages; results are incomplete.')
                report['status'] = 'partial'
        except (httpx.HTTPError, ValueError) as error:
            result.update(status='error', reason=str(error))
            report['status'] = 'partial'
        report['results'].append(result)
    return report
