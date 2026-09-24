"""Derivation of the result record.

Two layers:

  * The keys, reproduced with the same names and the same meanings as
    cisagov/pshtt so existing consumers (dashboards, Django models, CSV
    pipelines) keep working. Where this differs from upstream pshtt is noted
    inline.
  * ASM extensions, which are the fields pshtt never had but an attack-surface
    tool wants: certificate SANs, protocol matrix, security headers, cookie
    flags, technology fingerprints.

Everything is derived from the four probed endpoints. No network access here.
"""

from __future__ import annotations

from typing import Any

from httpstance.endpoints import Endpoint
from httpstance.tls import TLSResult, weak_protocols

STRONG_HSTS_MAX_AGE = 31_536_000  # one year, the preload requirement
PRELOAD_MIN_MAX_AGE = 31_536_000


def _canonical_https(https: Endpoint, httpswww: Endpoint) -> Endpoint | None:
    for ep in (https, httpswww):
        if _serves_content(ep) and ep.https_valid:
            return ep
    for ep in (https, httpswww):
        if ep.live and ep.https_valid:
            return ep
    for ep in (https, httpswww):
        if ep.live:
            return ep
    return None


def _canonical_http(http: Endpoint, httpwww: Endpoint) -> Endpoint | None:
    for ep in (http, httpwww):
        if _serves_content(ep):
            return ep
    for ep in (http, httpwww):
        if ep.live:
            return ep
    return None


def _serves_content(ep: Endpoint) -> bool:
    """Live and actually returning the site, rather than a CDN rejection."""
    return bool(ep.live and ep.status is not None and ep.status < 400)


def _first(*values):
    for v in values:
        if v is not None:
            return v
    return None


def derive(
    domain: str,
    base_domain: str,
    endpoints: dict[str, Endpoint],
    preload_list: set[str] | None = None,
    preload_pending: set[str] | None = None,
) -> dict[str, Any]:
    http = endpoints["http"]
    httpwww = endpoints["httpwww"]
    https = endpoints["https"]
    httpswww = endpoints["httpswww"]

    live = any(ep.live for ep in endpoints.values())
    canon_https = _canonical_https(https, httpswww)
    canon_http = _canonical_http(http, httpwww)
    canonical = canon_https or canon_http

    supports_https = bool(canon_https and canon_https.https_valid)

    # Defaults to HTTPS: the HTTP endpoint sends you to HTTPS, or there is no
    # HTTP endpoint at all and HTTPS works.
    if canon_http and canon_http.redirect:
        defaults_to_https = canon_http.redirect_immediately_to_https
    elif canon_http and _serves_content(canon_http):
        defaults_to_https = False
    else:
        defaults_to_https = supports_https

    # Strictly forces HTTPS: every HTTP endpoint that actually serves the site
    # redirects to HTTPS.
    #
    # Deviation from upstream pshtt: an endpoint answering 4xx/5xx is treated as
    # not serving content. A wildcard CDN returning 403 for http://www.example.com
    # is not an HTTP downgrade path, but upstream counts it as a live HTTP
    # endpoint and reports the domain as failing to force HTTPS. That is a false
    # positive on a large share of CDN-fronted sites.
    serving_http = [ep for ep in (http, httpwww) if _serves_content(ep)]
    strictly_forces = bool(serving_http) and all(
        ep.redirect and ep.redirect_immediately_to_https for ep in serving_http
    )
    if not serving_http and supports_https:
        strictly_forces = True

    # Downgrades: HTTPS sends you back to plain HTTP on the same domain.
    downgrades = any(
        ep.live and ep.redirect and ep.redirect_immediately_to_http
        and not ep.redirect_immediately_to_external
        for ep in (https, httpswww)
    )

    enforces_https = supports_https and (strictly_forces or defaults_to_https)

    hsts_source = canon_https if canon_https and canon_https.hsts else https
    hsts = bool(hsts_source.hsts) if hsts_source else False
    hsts_max_age = hsts_source.hsts_max_age if hsts_source else None
    hsts_all_subdomains = bool(hsts_source.hsts_all_subdomains) if hsts_source else False
    hsts_preload_flag = bool(hsts_source.hsts_preload) if hsts_source else False

    strong_hsts = bool(hsts_max_age and hsts_max_age >= STRONG_HSTS_MAX_AGE)
    preload_ready = bool(
        hsts_max_age and hsts_max_age >= PRELOAD_MIN_MAX_AGE
        and hsts_all_subdomains and hsts_preload_flag
    )

    if preload_list is None:
        preloaded = base_preloaded = None
    else:
        preloaded = domain in preload_list
        base_preloaded = base_domain in preload_list
    pending = None if preload_pending is None else domain in preload_pending

    tls: TLSResult | None = canon_https.tls if canon_https else None
    cert = (tls.cert if tls else {}) or {}

    redirect_to = None
    if canonical and canonical.redirect:
        redirect_to = canonical.redirect_eventually_to or canonical.redirect_immediately_to

    notes = [n for ep in endpoints.values() for n in ep.notes]

    result: dict[str, Any] = {
        # ---- pshtt-compatible ----
        "Domain": domain,
        "Base Domain": base_domain,
        "Canonical URL": canonical.url if canonical else f"https://{domain}",
        "Live": live,
        "HTTPS Live": bool(canon_https and canon_https.live),
        "Redirect": bool(canonical and canonical.redirect
                         and canonical.redirect_immediately_to_external),
        "Redirect To": redirect_to,
        "Valid HTTPS": supports_https,
        "Defaults to HTTPS": defaults_to_https,
        "Downgrades HTTPS": downgrades,
        "Strictly Forces HTTPS": strictly_forces,
        "Domain Supports HTTPS": supports_https,
        "Domain Enforces HTTPS": enforces_https,
        "Domain Uses Strong HSTS": strong_hsts,
        "HSTS": hsts,
        "HSTS Header": hsts_source.hsts_header if hsts_source else None,
        "HSTS Max Age": hsts_max_age,
        "HSTS Entire Domain": hsts_all_subdomains,
        "HSTS Preload Ready": preload_ready,
        "HSTS Preload Pending": pending,
        "HSTS Preloaded": preloaded,
        "Base Domain HSTS Preloaded": base_preloaded,
        "HTTPS Full Connection": bool(tls and tls.handshake_ok),
        "HTTPS Client Auth Required": bool(tls and tls.client_auth_required),
        "HTTPS Publicly Trusted": tls.publicly_trusted if tls else None,
        "HTTPS Custom Truststore Trusted": tls.custom_truststore_trusted if tls else None,
        "HTTPS Bad Chain": tls.bad_chain if tls else None,
        "HTTPS Bad Hostname": tls.bad_hostname if tls else None,
        "HTTPS Expired Cert": tls.expired_cert if tls else None,
        "HTTPS Self Signed Cert": tls.self_signed_cert if tls else None,
        "HTTPS Cert Chain Length": tls.chain_length if tls else None,
        "HTTPS Probably Missing Intermediate Cert": (
            tls.missing_intermediate if tls else None
        ),
        "IP": _first(*(ep.tls.ip for ep in endpoints.values() if ep.tls)),
        "Server Header": _first(*(ep.server_header for ep in
                                  (canon_https, canon_http, https, http) if ep)),
        "Server Version": _first(*(ep.server_version for ep in
                                   (canon_https, canon_http, https, http) if ep)),
        "Notes": "; ".join(notes),
        "Unknown Error": any(
            ep.error and "certificate" not in ep.error.lower()
            for ep in endpoints.values()
        ) and not live,

        # ---- ASM extensions ----
        "TLS Negotiated Version": tls.negotiated_version if tls else None,
        "TLS Negotiated Cipher": tls.negotiated_cipher if tls else None,
        "TLS ALPN": tls.alpn if tls else None,
        "TLS Protocol Matrix": tls.protocols if tls else {},
        "TLS Weak Protocols": weak_protocols(tls) if tls else [],
        "TLS Untestable Protocols": tls.untestable_protocols if tls else [],
        "Cert Subject": cert.get("subject"),
        "Cert Issuer": cert.get("issuer_common_name") or cert.get("issuer"),
        "Cert Serial": cert.get("serial_number"),
        "Cert SHA256": cert.get("sha256_fingerprint"),
        "Cert Not Before": cert.get("not_before"),
        "Cert Not After": cert.get("not_after"),
        "Cert Days To Expiry": cert.get("days_to_expiry"),
        "Cert Validity Days": cert.get("validity_days"),
        "Cert Key Type": cert.get("key_type"),
        "Cert Key Bits": cert.get("key_bits"),
        "Cert Signature Algorithm": cert.get("signature_algorithm"),
        "Cert Must Staple": cert.get("must_staple"),
        # SANs are the highest-value ASM field here: free subdomain discovery
        # from a host you were already contacting.
        "Cert Subject Alt Names": cert.get("subject_alt_names", []),
        "Security Headers": canonical.security_headers if canonical else {},
        "Missing Security Headers": (
            canonical.missing_security_headers if canonical else []
        ),
        "Technology Headers": canonical.fingerprint_headers if canonical else {},
        "Cookies": canonical.cookies if canonical else [],
        "Insecure Cookies": canonical.insecure_cookies if canonical else [],
        "Redirect Chain": canonical.redirect_chain if canonical else [],

        "endpoints": {name: _endpoint_dict(ep) for name, ep in endpoints.items()},
        "scanner": {"name": "httpstance", "version": _version()},
    }
    return result


def _version() -> str:
    from httpstance import __version__

    return __version__


def _endpoint_dict(ep: Endpoint) -> dict[str, Any]:
    return {
        "scheme": ep.scheme,
        "host": ep.host,
        "url": ep.url,
        "live": ep.live,
        "status": ep.status,
        "final_status": ep.final_status,
        "error": ep.error,
        "headers": ep.headers,
        "server_header": ep.server_header,
        "server_version": ep.server_version,
        "redirect": ep.redirect,
        "redirect_immediately_to": ep.redirect_immediately_to,
        "redirect_eventually_to": ep.redirect_eventually_to,
        "redirect_immediately_to_https": ep.redirect_immediately_to_https,
        "redirect_immediately_to_http": ep.redirect_immediately_to_http,
        "redirect_immediately_to_external": ep.redirect_immediately_to_external,
        "redirect_immediately_to_subdomain": ep.redirect_immediately_to_subdomain,
        "redirect_chain": ep.redirect_chain,
        "hsts": ep.hsts,
        "hsts_header": ep.hsts_header,
        "hsts_max_age": ep.hsts_max_age,
        "hsts_all_subdomains": ep.hsts_all_subdomains,
        "hsts_preload": ep.hsts_preload,
        "https_valid": ep.https_valid,
        "https_full_connection": ep.https_full_connection,
        "security_headers": ep.security_headers,
        "cookies": ep.cookies,
        "insecure_cookies": ep.insecure_cookies,
    }
