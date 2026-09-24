# httpstance

HTTPS deployment and TLS posture scanner. A maintained replacement for
[pshtt](https://github.com/cisagov/pshtt), with pshtt-compatible output and
extensions for attack-surface management.

## Why this exists

pshtt cannot be installed on any currently supported Python. Its latest release
(0.7.6) declares `sslyze>=3.0.0,<5.0.0`, and the nassl builds that satisfies only
ever published `cp37`/`cp38` wheels. Every downstream project has dealt with this
by pinning Python 3.7, vendoring a patched sslyze, or giving up.

The root cause is a dependency on version-locked CPython C extensions. This
package avoids that category entirely:

| Dependency | Why it won't strand you |
|---|---|
| `ssl` (stdlib) | Ships with the interpreter. Does the TLS work. |
| `httpx`, `anyio` | Pure Python. |
| `cryptography` | Ships `cp37-abi3` wheels. One wheel works on every future CPython 3.x. |
| `publicsuffixlist` | Pure Python data package. |

Supporting a new Python release should require no changes here.

## Usage

Drop-in for pshtt's calling convention:

```python
from httpstance import inspect_domains

results = inspect_domains(["example.com", "www.example.gov"], {"timeout": 30})
for r in results:
    print(r["Domain"], r["Domain Enforces HTTPS"], r["HSTS Max Age"])
```

Already in an event loop:

```python
from httpstance import async_inspect_domains
results = await async_inspect_domains(domains, {"concurrency": 20})
```

CLI:

```bash
httpstance example.com example.org --compact
httpstance -f domains.txt --concurrency 20 --no-protocol-enumeration
```

### Options

| Option | Default | Notes |
|---|---|---|
| `timeout` | 15 | Per-request seconds. |
| `concurrency` | 10 | Domains in flight. Each uses up to 4 HTTP + 6 TLS connections. |
| `enumerate_protocols` | `True` | Deprecated-TLS probing. Four extra handshakes per host; turn off for speed. |
| `user_agent` | `httpstance/<version>` | Set this to something with an abuse contact. |
| `ca_file` | `None` | Custom truststore. Sets `HTTPS Custom Truststore Trusted`. |
| `preload_list` | `None` | `set[str]` of HSTS-preloaded domains. Without it, the three preload fields are `None` rather than a guess. |

Hyphenated pshtt-style keys (`cache-third-parties`) are accepted and normalised.

## Migrating the XFD task

The XFD `pshtt` task chunks subdomains into groups of ten and calls
`pshtt.inspect_domains(subdomain_list, options)`. Replace the import and delete
the chunking loop, since concurrency is handled internally:

```python
-from pshtt import pshtt
+import httpstance
...
-    chunked_sub_domains = list(chunk_list(sub_domains, 10))
-    for chunk in chunked_sub_domains:
-        subdomain_list = [s.sub_domain for s in chunk]
-        pshtt_results = pshtt.inspect_domains(subdomain_list, options)
+    subdomain_list = [s.sub_domain for s in sub_domains]
+    pshtt_results = httpstance.inspect_domains(
+        subdomain_list, {"timeout": 30, "concurrency": 10}
+    )
```

Every key the `PshttResults` model reads is present with the same name, including
the `endpoints` sub-dict with `http`, `https`, `httpwww` and `httpswww`. The
`"sslyze": True` option is unnecessary and ignored.

## What it reports beyond pshtt

- **`Cert Subject Alt Names`** — the highest-value addition. Free subdomain
  discovery from a host you were already contacting.
- **`TLS Protocol Matrix`** — SSLv3 through TLS 1.3, each `True`, `False`, or
  `None`. See below for why `None` matters.
- Certificate detail: issuer, serial, SHA-256 fingerprint, key type and size,
  signature algorithm, validity window, days to expiry, must-staple.
- **`Security Headers`** / **`Missing Security Headers`** — CSP, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP.
- **`Cookies`** / **`Insecure Cookies`** — Secure, HttpOnly, SameSite per cookie.
- **`Technology Headers`** — Server, X-Powered-By, X-AspNet-Version and friends,
  for inventory.
- **`Redirect Chain`** — the full walk, not just the first hop.

### Untestable is not the same as clean

`TLS Protocol Matrix` values are three-state on purpose. Distributions built with
`no-ssl3`, and systems under RHEL-style crypto-policies, refuse to *offer* old
protocols at all. A two-state check on such a host reports every target as free
of SSLv3 and TLS 1.0, which is a false negative on every scan in the fleet.

When the local OpenSSL cannot offer a version, the matrix records `None` and the
label appears in `TLS Untestable Protocols` with a note. If that list is
non-empty in production, your scanner host cannot answer the question and you
should fix the host rather than trust the result.

## Documented deviations from pshtt

- **4xx/5xx endpoints are not "serving content."** A wildcard CDN returning 403
  for `http://www.example.com` is not an HTTP downgrade path. Upstream counts it
  as a live HTTP endpoint and reports the domain as failing to force HTTPS, which
  is a false positive on a large share of CDN-fronted sites. Affects
  `Strictly Forces HTTPS`, `Defaults to HTTPS`, and canonical endpoint selection.
- **`HTTPS Cert Chain Length` is `None`.** Reading the served chain needs
  `SSLSocket.get_unverified_chain()`, added in Python 3.13. Rather than guess,
  it is reported as unknown. `HTTPS Probably Missing Intermediate Cert` still
  works, derived from the verify error.
- **HSTS preload fields are `None` unless you supply a list.** pshtt bundles a
  fetch of Chromium's preload list. Fetching a large remote file at scan time is
  a poor default for a library, so pass `preload_list` if you want those fields.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

The derivation layer is pure functions over dataclasses, so the suite runs with
no network, no sockets, and no fixtures beyond literal dicts. That is the layer
where the logic errors live.
