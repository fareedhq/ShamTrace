"""Response indicators, not origin attribution or protection bypass."""


def inspect_edge(headers, status):
    signals = []
    if headers.get('server', '').lower() == 'cloudflare':
        signals.append('Server: cloudflare')
    for key in ('cf-ray', 'cf-cache-status', 'cf-mitigated'):
        if key in headers:
            signals.append(f'{key}: {headers[key]}')
    challenge = headers.get('cf-mitigated', '').lower() == 'challenge'
    blocked = challenge or status in {403, 429, 503}
    return {'cloudflare': {'state': 'indicated' if signals else 'not_observed',
                           'evidence': signals, 'challenge': challenge},
            'response_scope': 'interstitial_or_error' if blocked else 'application_response_unverified',
            'skip_followup': blocked,
            'reason': 'Challenge or HTTP 403/429/503; origin application cannot be assessed from this response.' if blocked else None,
            'limitations': 'Headers may be spoofed; absent indicators do not exclude a CDN/WAF. Third-party CDN resource URLs are not evidence about target hosting.'}
