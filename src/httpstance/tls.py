"""TLS layer.

Everything here is synchronous and blocking. The caller runs it in a worker
thread. That keeps the TLS code free of async plumbing, which matters because
this is the part most likely to be swapped for an external probe binary later.

Deliberately built on the stdlib `ssl` module vs. sslyze/nassl. Those publish
version-locked CPython wheels. `ssl` ships with the interpreter and cannot be
left behind.
"""

from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAS_CRYPTOGRAPHY = False

# Ordered oldest to newest. SSLv2 is unreachable from the stdlib and long dead.
DEPRECATED_VERSIONS: list[tuple[str, Any]] = [
    ("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None)),
    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
]
CURRENT_VERSIONS: list[tuple[str, Any]] = [
    ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
]


@dataclass
class TLSResult:
    """Outcome of TLS inspection for one host:port."""

    reachable: bool = False
    handshake_ok: bool = False

    # Validation outcome against the default trust store.
    publicly_trusted: bool | None = None
    custom_truststore_trusted: bool | None = None
    bad_hostname: bool | None = None
    bad_chain: bool | None = None
    expired_cert: bool | None = None
    self_signed_cert: bool | None = None
    client_auth_required: bool = False
    validation_error: str | None = None

    # Negotiated connection.
    negotiated_version: str | None = None
    negotiated_cipher: str | None = None
    alpn: str | None = None

    # Certificate detail.
    cert: dict[str, Any] = field(default_factory=dict)
    chain_length: int | None = None
    missing_intermediate: bool | None = None

    # Protocol matrix. Keys are version labels, values are True (accepted),
    # False (rejected), or None (could not be tested locally).
    protocols: dict[str, bool | None] = field(default_factory=dict)
    untestable_protocols: list[str] = field(default_factory=list)

    ip: str | None = None
    error: str | None = None


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _base_context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:  # pragma: no cover
        pass
    return ctx


def _classify_validation_error(exc: ssl.SSLCertVerificationError) -> dict[str, bool]:
    reason = (exc.verify_message or str(exc)).lower()
    code = getattr(exc, "verify_code", None)
    return {
        "expired_cert": code == 10 or "expired" in reason,
        "self_signed_cert": code in (18, 19) or "self-signed" in reason or "self signed" in reason,
        "bad_chain": code in (2, 20, 21, 19) or "unable to get local issuer" in reason,
        "bad_hostname": "hostname mismatch" in reason or "doesn't match" in reason,
    }


def _parse_certificate(der: bytes) -> dict[str, Any]:
    """Certificate detail. Falls back to a thin dict without `cryptography`."""
    if not HAS_CRYPTOGRAPHY:  # pragma: no cover
        return {}

    cert = x509.load_der_x509_certificate(der)
    try:
        sans = [
            n.value for n in
            cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ]
    except x509.ExtensionNotFound:
        sans = []

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_bits = f"EC ({key.curve.name})", key.curve.key_size
    else:
        key_type, key_bits = type(key).__name__, getattr(key, "key_size", None)

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)

    try:
        eku = [
            o._name for o in
            cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ]
    except x509.ExtensionNotFound:
        eku = []

    try:
        must_staple = any(
            f.value == b"\x30\x03\x02\x01\x05" for f in [
                cert.extensions.get_extension_for_oid(
                    x509.ObjectIdentifier("1.3.6.1.5.5.7.1.24")
                ).value
            ]
        )
    except x509.ExtensionNotFound:
        must_staple = False

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_common_name": next(
            (a.value for a in cert.issuer.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME)), None
        ),
        "serial_number": format(cert.serial_number, "x"),
        "subject_alt_names": sans,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_to_expiry": (not_after - now).days,
        "days_since_issued": (now - not_before).days,
        "validity_days": (not_after - not_before).days,
        "key_type": key_type,
        "key_bits": key_bits,
        "signature_algorithm": getattr(cert.signature_hash_algorithm, "name", None),
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "is_ca": _is_ca(cert),
        "extended_key_usage": eku,
        "must_staple": must_staple,
        "pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
    }


def _is_ca(cert) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _probe_version(host: str, port: int, version: Any, timeout: float) -> bool | None:
    """Return True if accepted, False if rejected, None if untestable locally.

    None is the important case. Distributions compiled with `no-ssl3`, and
    systems under RHEL-style crypto-policies, refuse to *offer* old protocols
    at all. Reporting that as "not supported by the server" would be a false
    negative on every scan, so it is reported as unknown instead.
    """
    if version is None:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError, OSError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


def inspect_tls(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
    ca_file: str | None = None,
    enumerate_protocols: bool = True,
) -> TLSResult:
    res = TLSResult()
    res.ip = _resolve(host)
    if res.ip is None:
        res.error = "dns_resolution_failed"
        return res

    # Pass 1: validating handshake. Success means publicly trusted.
    try:
        ctx = _base_context(verify=True)
        if ca_file:
            ctx.load_verify_locations(cafile=ca_file)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                res.reachable = res.handshake_ok = True
                res.publicly_trusted = ca_file is None
                res.custom_truststore_trusted = ca_file is not None
                res.bad_hostname = res.bad_chain = False
                res.expired_cert = res.self_signed_cert = False
                res.negotiated_version = tls.version()
                cipher = tls.cipher()
                res.negotiated_cipher = cipher[0] if cipher else None
                res.alpn = tls.selected_alpn_protocol()
                res.cert = _parse_certificate(tls.getpeercert(binary_form=True))
    except ssl.SSLCertVerificationError as exc:
        res.reachable = True
        res.publicly_trusted = False
        res.validation_error = str(exc)
        for k, v in _classify_validation_error(exc).items():
            setattr(res, k, v)
    except ssl.SSLError as exc:
        res.reachable = True
        res.publicly_trusted = False
        res.validation_error = f"{type(exc).__name__}: {exc}"
        if "certificate required" in str(exc).lower():
            res.client_auth_required = True
    except OSError as exc:
        res.error = f"{type(exc).__name__}: {exc}"
        return res

    # Pass 2: if validation failed, handshake without it so the certificate
    # is still captured. A broken cert is the thing you most want to see.
    if not res.handshake_ok:
        try:
            ctx = _base_context(verify=False)
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    res.handshake_ok = True
                    res.negotiated_version = tls.version()
                    cipher = tls.cipher()
                    res.negotiated_cipher = cipher[0] if cipher else None
                    res.alpn = tls.selected_alpn_protocol()
                    res.cert = _parse_certificate(tls.getpeercert(binary_form=True))
        except (ssl.SSLError, OSError) as exc:
            res.error = f"{type(exc).__name__}: {exc}"

    # Chain length: available natively from 3.13, otherwise left unknown
    # rather than guessed.
    res.chain_length = None
    res.missing_intermediate = (
        res.bad_chain if res.bad_chain is not None else None
    )

    if enumerate_protocols and res.reachable:
        for label, version in DEPRECATED_VERSIONS + CURRENT_VERSIONS:
            accepted = _probe_version(host, port, version, timeout)
            res.protocols[label] = accepted
            if accepted is None:
                res.untestable_protocols.append(label)

    return res


def weak_protocols(res: TLSResult) -> list[str]:
    return [
        label for label, _ in DEPRECATED_VERSIONS
        if res.protocols.get(label) is True
    ]
