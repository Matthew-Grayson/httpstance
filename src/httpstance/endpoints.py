"""HTTP endpoint probing.

A domain has four endpoints, and the interesting findings come from how they
disagree with each other.

    http://domain        httpwww   -> http://www.domain
    https://domain       httpswww  -> https://www.domain

Each is probed independently without following redirects, then the redirect
graph is walked separately. Following redirects blindly loses the very
information we want to measure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from httpstance.tls import TLSResult

MAX_REDIRECTS = 10

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "x-xss-protection",
)

# Headers that leak implementation detail. Useful for ASM inventory.
FINGERPRINT_HEADERS = (
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-varnish", "via", "x-served-by",
)

_VERSION_RE = re.compile(r"[\d.]+")


@dataclass
class Endpoint:
    """One of the four endpoints, with everything observed about it."""

    scheme: str
    host: str
    url: str

    live: bool = False
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    notes: list[str] = field(default_factory=list)

    server_header: str | None = None
    server_version: str | None = None

    redirect: bool = False
    redirect_immediately_to: str | None = None
    redirect_eventually_to: str | None = None
    redirect_immediately_to_https: bool = False
    redirect_immediately_to_http: bool = False
    redirect_immediately_to_external: bool = False
    redirect_immediately_to_subdomain: bool = False
    redirect_chain: list[str] = field(default_factory=list)

    hsts: bool | None = None
    hsts_header: str | None = None
    hsts_max_age: int | None = None
    hsts_all_subdomains: bool = False
    hsts_preload: bool = False

    https_valid: bool | None = None
    https_full_connection: bool | None = None
    tls: TLSResult | None = None

    # ASM extras beyond pshtt.
    security_headers: dict[str, str] = field(default_factory=dict)
    missing_security_headers: list[str] = field(default_factory=list)
    fingerprint_headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    insecure_cookies: list[str] = field(default_factory=list)
    final_status: int | None = None
    title: str | None = None


def _parse_hsts(value: str | None) -> dict[str, Any]:
    if not value:
        return {"hsts": False, "max_age": None, "all_subdomains": False, "preload": False}
    lowered = value.lower()
    max_age = None
    match = re.search(r"max-age\s*=\s*\"?(\d+)\"?", lowered)
    if match:
        max_age = int(match.group(1))
    return {
        "hsts": max_age is not None,
        "max_age": max_age,
        "all_subdomains": "includesubdomains" in lowered,
        "preload": "preload" in lowered,
    }


def _parse_cookies(headers: httpx.Headers) -> tuple[list[dict], list[str]]:
    cookies, insecure = [], []
    for raw in headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        lowered = raw.lower()
        samesite = None
        match = re.search(r"samesite\s*=\s*(\w+)", lowered)
        if match:
            samesite = match.group(1)
        entry = {
            "name": name,
            "secure": "; secure" in lowered or lowered.endswith("; secure"),
            "httponly": "httponly" in lowered,
            "samesite": samesite,
        }
        cookies.append(entry)
        if not entry["secure"] or not entry["httponly"]:
            insecure.append(name)
    return cookies, insecure


def _server_version(server: str | None) -> str | None:
    if not server:
        return None
    match = _VERSION_RE.search(server)
    return match.group(0) if match else None


def _classify_redirect(endpoint: Endpoint, location: str, base_domain: str) -> None:
    target = httpx.URL(endpoint.url).join(location)
    endpoint.redirect_immediately_to = str(target)
    endpoint.redirect_immediately_to_https = target.scheme == "https"
    endpoint.redirect_immediately_to_http = target.scheme == "http"

    host = (target.host or "").lower()
    origin = urlparse(endpoint.url).hostname or ""
    endpoint.redirect_immediately_to_external = not (
        host == base_domain or host.endswith("." + base_domain)
    )
    endpoint.redirect_immediately_to_subdomain = (
        host.endswith("." + base_domain) and host != origin
        and host != "www." + base_domain
    )


async def probe_endpoint(
    client: httpx.AsyncClient,
    scheme: str,
    host: str,
    base_domain: str,
    timeout: float,
) -> Endpoint:
    url = f"{scheme}://{host}/"
    ep = Endpoint(scheme=scheme, host=host, url=url)

    try:
        resp = await client.get(url, follow_redirects=False, timeout=timeout)
    except httpx.HTTPError as exc:
        ep.error = f"{type(exc).__name__}: {exc}"
        return ep

    ep.live = True
    ep.status = resp.status_code
    ep.headers = {k.lower(): v for k, v in resp.headers.items()}
    ep.server_header = resp.headers.get("server")
    ep.server_version = _server_version(ep.server_header)

    ep.security_headers = {
        h: ep.headers[h] for h in SECURITY_HEADERS if h in ep.headers
    }
    ep.missing_security_headers = [
        h for h in (
            "content-security-policy", "x-frame-options",
            "x-content-type-options", "referrer-policy",
        ) if h not in ep.headers
    ]
    ep.fingerprint_headers = {
        h: ep.headers[h] for h in FINGERPRINT_HEADERS if h in ep.headers
    }
    ep.cookies, ep.insecure_cookies = _parse_cookies(resp.headers)

    if scheme == "https":
        hsts = _parse_hsts(resp.headers.get("strict-transport-security"))
        ep.hsts = hsts["hsts"]
        ep.hsts_header = resp.headers.get("strict-transport-security")
        ep.hsts_max_age = hsts["max_age"]
        ep.hsts_all_subdomains = hsts["all_subdomains"]
        ep.hsts_preload = hsts["preload"]

    if resp.is_redirect and "location" in resp.headers:
        ep.redirect = True
        _classify_redirect(ep, resp.headers["location"], base_domain)
        ep.redirect_chain, ep.redirect_eventually_to, ep.final_status = (
            await _walk_redirects(client, url, timeout)
        )
    else:
        ep.final_status = resp.status_code

    return ep


async def _walk_redirects(
    client: httpx.AsyncClient, url: str, timeout: float
) -> tuple[list[str], str | None, int | None]:
    chain: list[str] = []
    current = url
    status = None
    for _ in range(MAX_REDIRECTS):
        try:
            resp = await client.get(current, follow_redirects=False, timeout=timeout)
        except httpx.HTTPError:
            return chain, current, status
        status = resp.status_code
        if not resp.is_redirect or "location" not in resp.headers:
            return chain, current, status
        current = str(httpx.URL(current).join(resp.headers["location"]))
        if current in chain:
            chain.append(current)
            return chain, current, status  # loop
        chain.append(current)
    return chain, current, status
