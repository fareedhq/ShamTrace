"""Explicit proxy routing, rate limiting, bounded retries, and scoped redirects."""
import threading
import time
from contextlib import contextmanager
from urllib.parse import urljoin, urlsplit
import httpx
from .checks import is_in_scope, redact_url

REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def network_options(target, proxy):
    onion = (target.hostname or "").rstrip(".").lower().endswith(".onion")
    if onion and not proxy:
        raise ValueError(".onion requires --proxy socks5://127.0.0.1:9050 (a running Tor SOCKS service).")
    if proxy:
        parsed = urlsplit(proxy)
        if parsed.scheme not in {"socks5", "socks5h"} or not parsed.hostname or not parsed.port:
            raise ValueError("Proxy must be socks5://HOST:PORT or socks5h://HOST:PORT.")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("Proxy URL must not contain paths, query parameters, or fragments.")
    return {
        "route": "socks-proxy" if proxy else "direct",
        "target_type": "onion" if onion else "web",
        "local_target_dns": not bool(proxy),
        "tor_verified": False,
    }


class RateLimiter:
    """Thread-safe token bucket / interval rate limiter for polite scanning."""

    def __init__(self, rate_per_second=0.0):
        self.rate = float(rate_per_second or 0.0)
        self.min_interval = (1.0 / self.rate) if self.rate > 0 else 0.0
        self._lock = threading.Lock()
        self._last_request = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if self._last_request > 0 and elapsed < self.min_interval:
                sleep_for = self.min_interval - elapsed
                time.sleep(sleep_for)
            self._last_request = time.monotonic()


@contextmanager
def open_stream_with_retry(client, method, url, retries=0, rate_limiter=None, **kwargs):
    """Stream an HTTP request with rate limiting and bounded retries on transient transport errors."""
    max_attempts = max(1, int(retries or 0) + 1)
    attempt = 0
    while True:
        attempt += 1
        if rate_limiter is not None:
            rate_limiter.wait()
        try:
            with client.stream(method, url, **kwargs) as response:
                yield response
                return
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError):
            if attempt >= max_attempts:
                raise
            time.sleep(min(0.25 * attempt, 1.0))


@contextmanager
def stream_within_scope(
    client,
    url,
    scope_target,
    follow_scoped_redirects=False,
    max_redirects=5,
    retries=0,
    rate_limiter=None,
):
    """
    Stream a GET request and optionally follow redirects ONLY when the destination
    remains strictly within the authorized target scope.
    Yields (final_response, final_url, redirect_info).
    """
    current_url = url
    visited = {current_url}
    chain = []
    hops = 0

    while True:
        with open_stream_with_retry(
            client, "GET", current_url, retries=retries, rate_limiter=rate_limiter
        ) as response:
            location = response.headers.get("location")
            is_redirect = response.status_code in REDIRECT_STATUSES and bool(location)

            if not is_redirect or not follow_scoped_redirects:
                reason = None
                if is_redirect and not follow_scoped_redirects:
                    next_candidate = urljoin(current_url, location)
                    in_scope = is_in_scope(next_candidate, scope_target, allow_https_upgrade=True)
                    reason = "redirects_disabled_in_scope" if in_scope else "redirects_disabled_out_of_scope"
                yield response, current_url, {
                    "followed": len(chain) > 0,
                    "hops": len(chain),
                    "chain": chain,
                    "blocked_location": redact_url(urljoin(current_url, location)) if is_redirect else None,
                    "stop_reason": reason,
                }
                return

            next_url = urljoin(current_url, location)
            if not is_in_scope(next_url, scope_target, allow_https_upgrade=True):
                yield response, current_url, {
                    "followed": len(chain) > 0,
                    "hops": len(chain),
                    "chain": chain,
                    "blocked_location": redact_url(next_url),
                    "stop_reason": "out_of_scope_redirect_blocked",
                }
                return

            if next_url in visited:
                yield response, current_url, {
                    "followed": len(chain) > 0,
                    "hops": len(chain),
                    "chain": chain,
                    "blocked_location": redact_url(next_url),
                    "stop_reason": "redirect_loop_detected",
                }
                return

            if hops >= max_redirects:
                yield response, current_url, {
                    "followed": len(chain) > 0,
                    "hops": len(chain),
                    "chain": chain,
                    "blocked_location": redact_url(next_url),
                    "stop_reason": "max_redirects_reached",
                }
                return

            chain.append({
                "from": redact_url(current_url),
                "to": redact_url(next_url),
                "status": response.status_code,
            })
            visited.add(next_url)
            current_url = next_url
            hops += 1
