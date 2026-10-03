"""Live TLS probe tests. Skipped unless pytest is run with --live.

These make real connections to badssl.com, which exists to serve deliberately
outdated and broken TLS configurations for exactly this purpose. Nothing here
probes a host without standing permission to do so.

The assertions are deliberately loose about None. A local OpenSSL that refuses
to offer a deprecated protocol is a valid environment rather than a failure, so
_probe_version's tri-state contract is preserved instead of flattened into a
boolean. The assertion that actually guards against regression is the negative
one: a host that does not speak a given version must never come back True.
"""
import ssl
import pytest

from httpstance.tls import _probe_version


@pytest.mark.live
def test_probe_version_detects_tls10_endpoint():
    """badssl.com:1010 serves TLS 1.0 only. None means the local OpenSSL
    refused to offer it, which is a valid outcome, not a failure."""
    assert _probe_version("tls-v1-0.badssl.com", 1010, ssl.TLSVersion.TLSv1, 10.0) in (True, None)


@pytest.mark.live
def test_probe_version_rejects_unsupported_version():
    """Same endpoint, wrong version. Must be False, never True."""
    assert _probe_version("tls-v1-0.badssl.com", 1010, ssl.TLSVersion.TLSv1_3, 10.0) is False
