"""httpstance -- HTTPS deployment and TLS posture scanner.

Drop-in usage:

    from httpstance import inspect_domains
    results = inspect_domains(["example.com"], {"timeout": 30})

Async usage, if you are already in an event loop:

    results = await async_inspect_domains(["example.com"], {"timeout": 30})

Both return a list of dicts. Every pshtt output key is present with the same
name and meaning; ASM extensions are added alongside.

Forward-compatibility policy: no build-locked C extensions. httpx and anyio
are pure Python; cryptography ships abi3 wheels that work on every future
CPython 3.x; the TLS work uses the stdlib `ssl` module, which ships with the
interpreter. Adding support for a new Python release should require nothing.
"""

from __future__ import annotations

import asyncio
from typing import Any, Iterable

import anyio
import httpx

from httpstance.derive import derive
from httpstance.endpoints import Endpoint, probe_endpoint
from httpstance.tls import inspect_tls

__version__ = "0.1.0"
__all__ = [
    "inspect",
    "inspect_domains",
    "async_inspect",
    "async_inspect_domains",
    "DEFAULT_OPTIONS",
    "__version__",
]

DEFAULT_OPTIONS: dict[str, Any] = {
    "timeout": 15,
    "user_agent": f"httpstance/{__version__} (+https://github.com/you/httpstance)",
    "ca_file": None,
    "concurrency": 10,          # domains inspected in parallel
    "enumerate_protocols": True,  # four extra handshakes per host; disable to go fast
    "preload_list": None,       # set[str] of HSTS-preloaded domains, if you have one
    "preload_pending": None,
    "verify": False,            # httpx cert verification; TLS validity is measured
                                # separately in tls.py, so leave this off or a bad
                                # cert hides the HTTP-layer findings entirely
    "follow_redirects_limit": 10,
}


def _base_domain(domain: str) -> str:
    """Registrable domain, via the public suffix list when available."""
    try:
        from publicsuffixlist import PublicSuffixList

        psl = PublicSuffixList()
        return psl.privatesuffix(domain) or domain
    except Exception:
        parts = domain.split(".")
        return ".".join(parts[-2:]) if len(parts) > 2 else domain


def _merge(options: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(DEFAULT_OPTIONS)
    if options:
        for key, value in options.items():
            merged[key.replace("-", "_")] = value
    return merged


async def async_inspect(domain: str, options: dict[str, Any] | None = None) -> dict:
    """Inspect one domain. Returns a single result dict."""
    opts = _merge(options)
    domain = domain.strip().lower().rstrip(".").removeprefix("www.")
    base = _base_domain(domain)
    timeout = float(opts["timeout"])

    targets = {
        "http": ("http", domain),
        "httpwww": ("http", f"www.{domain}"),
        "https": ("https", domain),
        "httpswww": ("https", f"www.{domain}"),
    }

    limits = httpx.Limits(max_connections=8, max_keepalive_connections=4)
    async with httpx.AsyncClient(
        headers={"user-agent": opts["user_agent"]},
        verify=bool(opts["verify"]),
        limits=limits,
        timeout=timeout,
    ) as client:
        probes = await asyncio.gather(*(
            probe_endpoint(client, scheme, host, base, timeout)
            for scheme, host in targets.values()
        ))
    endpoints: dict[str, Endpoint] = dict(zip(targets, probes))

    # TLS inspection for the two HTTPS endpoints, in worker threads.
    for name in ("https", "httpswww"):
        ep = endpoints[name]
        tls = await anyio.to_thread.run_sync(
            lambda h=ep.host: inspect_tls(
                h,
                timeout=timeout,
                ca_file=opts["ca_file"],
                enumerate_protocols=bool(opts["enumerate_protocols"]),
            )
        )
        ep.tls = tls
        ep.https_valid = bool(
            tls.publicly_trusted or tls.custom_truststore_trusted
        )
        ep.https_full_connection = tls.handshake_ok
        if tls.validation_error:
            ep.notes.append(f"{name}: {tls.validation_error}")
        if tls.untestable_protocols:
            ep.notes.append(
                f"{name}: could not test {', '.join(tls.untestable_protocols)} "
                "(local OpenSSL refuses to offer them)"
            )

    return derive(
        domain, base, endpoints,
        preload_list=opts["preload_list"],
        preload_pending=opts["preload_pending"],
    )


async def async_inspect_domains(
    domains: Iterable[str], options: dict[str, Any] | None = None
) -> list[dict]:
    opts = _merge(options)
    sem = asyncio.Semaphore(int(opts["concurrency"]))

    async def one(domain: str) -> dict:
        async with sem:
            try:
                return await async_inspect(domain, options)
            except Exception as exc:  # never let one domain kill the batch
                return {
                    "Domain": domain,
                    "Live": False,
                    "Unknown Error": True,
                    "Notes": f"{type(exc).__name__}: {exc}",
                    "endpoints": {},
                }

    return list(await asyncio.gather(*(one(d) for d in domains)))


def inspect(domain: str, options: dict[str, Any] | None = None) -> dict:
    """Synchronous single-domain inspection. Mirrors pshtt.inspect."""
    return asyncio.run(async_inspect(domain, options))


def inspect_domains(
    domains: Iterable[str], options: dict[str, Any] | None = None
) -> list[dict]:
    """Synchronous batch inspection. Mirrors pshtt.inspect_domains.

    Drop-in for the XFD task: swap the import and delete the chunking loop,
    since concurrency is handled internally by the `concurrency` option.
    """
    return asyncio.run(async_inspect_domains(domains, options))
