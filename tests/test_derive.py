"""Offline tests for the derivation layer. No network, no Postgres, no sockets."""

import pytest

from httpstance.derive import derive
from httpstance.endpoints import Endpoint, _parse_hsts, _parse_cookies
from httpstance.tls import TLSResult

import httpx


def ep(scheme, host, **kw):
    e = Endpoint(scheme=scheme, host=host, url=f"{scheme}://{host}/")
    for k, v in kw.items():
        setattr(e, k, v)
    return e


def build(http=None, httpwww=None, https=None, httpswww=None):
    return {
        "http": http or ep("http", "x.com"),
        "httpwww": httpwww or ep("http", "www.x.com"),
        "https": https or ep("https", "x.com"),
        "httpswww": httpswww or ep("https", "www.x.com"),
    }


def good_tls():
    return TLSResult(
        reachable=True, handshake_ok=True, publicly_trusted=True,
        bad_chain=False, bad_hostname=False, expired_cert=False,
        self_signed_cert=False, negotiated_version="TLSv1.3",
        protocols={"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False},
        cert={"days_to_expiry": 60, "subject_alt_names": ["x.com", "www.x.com"]},
    )


def test_enforces_https_when_http_redirects():
    r = derive("x.com", "x.com", build(
        http=ep("http", "x.com", live=True, status=301, redirect=True,
                redirect_immediately_to_https=True),
        https=ep("https", "x.com", live=True, status=200, https_valid=True,
                 hsts=True, hsts_max_age=31536000, hsts_all_subdomains=True,
                 hsts_header="max-age=31536000; includeSubDomains", tls=good_tls()),
    ))
    assert r["Valid HTTPS"] and r["Defaults to HTTPS"]
    assert r["Strictly Forces HTTPS"] and r["Domain Enforces HTTPS"]
    assert r["Domain Uses Strong HSTS"] and r["HSTS Entire Domain"]


def test_cdn_403_on_www_does_not_break_forcing():
    """The regression that motivated the _serves_content deviation."""
    r = derive("x.com", "x.com", build(
        http=ep("http", "x.com", live=True, status=301, redirect=True,
                redirect_immediately_to_https=True),
        httpwww=ep("http", "www.x.com", live=True, status=403),
        https=ep("https", "x.com", live=True, status=200, https_valid=True,
                 tls=good_tls()),
    ))
    assert r["Strictly Forces HTTPS"] is True


def test_downgrade_detected():
    r = derive("x.com", "x.com", build(
        https=ep("https", "x.com", live=True, status=302, redirect=True,
                 https_valid=True, redirect_immediately_to_http=True,
                 redirect_immediately_to_external=False, tls=good_tls()),
    ))
    assert r["Downgrades HTTPS"] is True


def test_no_https_at_all():
    r = derive("x.com", "x.com", build(
        http=ep("http", "x.com", live=True, status=200),
    ))
    assert r["Live"] is True
    assert r["Valid HTTPS"] is False
    assert r["Domain Enforces HTTPS"] is False


def test_expired_cert_flags_through():
    tls = TLSResult(reachable=True, publicly_trusted=False, expired_cert=True,
                    bad_chain=False, self_signed_cert=False)
    r = derive("x.com", "x.com", build(
        https=ep("https", "x.com", live=True, status=200, https_valid=False, tls=tls),
    ))
    assert r["HTTPS Expired Cert"] is True
    assert r["Valid HTTPS"] is False


def test_untestable_protocols_are_not_reported_as_clean():
    tls = good_tls()
    tls.protocols = {"SSLv3": None, "TLSv1.0": None, "TLSv1.1": False}
    tls.untestable_protocols = ["SSLv3", "TLSv1.0"]
    r = derive("x.com", "x.com", build(
        https=ep("https", "x.com", live=True, status=200, https_valid=True, tls=tls),
    ))
    assert r["TLS Weak Protocols"] == []
    assert r["TLS Untestable Protocols"] == ["SSLv3", "TLSv1.0"]


def test_sans_surface_for_asset_discovery():
    r = derive("x.com", "x.com", build(
        https=ep("https", "x.com", live=True, status=200, https_valid=True,
                 tls=good_tls()),
    ))
    assert r["Cert Subject Alt Names"] == ["x.com", "www.x.com"]


@pytest.mark.parametrize("header,expected_age,subs,preload", [
    ("max-age=31536000; includeSubDomains; preload", 31536000, True, True),
    ("max-age=0", 0, False, False),
    ('max-age="600"; includeSubDomains', 600, True, False),
    (None, None, False, False),
])
def test_hsts_parsing(header, expected_age, subs, preload):
    got = _parse_hsts(header)
    assert got["max_age"] == expected_age
    assert got["all_subdomains"] is subs
    assert got["preload"] is preload


def test_cookie_flags():
    h = httpx.Headers([
        ("set-cookie", "a=1; Secure; HttpOnly; SameSite=Lax"),
        ("set-cookie", "b=2; Path=/"),
    ])
    cookies, insecure = _parse_cookies(h)
    assert cookies[0]["secure"] and cookies[0]["samesite"] == "lax"
    assert insecure == ["b"]
