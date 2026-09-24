"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys

from httpstance import __version__, inspect_domains


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="httpstance",
        description="HTTPS deployment and TLS posture scanner.",
    )
    p.add_argument("domains", nargs="*", help="domains to scan")
    p.add_argument("-f", "--file", help="file with one domain per line")
    p.add_argument("--json", action="store_true", default=True,
                   help="emit JSON (default)")
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--user-agent", default=None)
    p.add_argument("--ca-file", default=None)
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--no-protocol-enumeration", action="store_true",
                   help="skip deprecated-TLS probing (4 fewer handshakes per host)")
    p.add_argument("--compact", action="store_true",
                   help="drop per-endpoint detail and raw headers")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    domains = list(args.domains)
    if args.file:
        with open(args.file) as fh:
            domains += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if not domains:
        p.error("no domains given")

    options = {
        "timeout": args.timeout,
        "concurrency": args.concurrency,
        "ca_file": args.ca_file,
        "enumerate_protocols": not args.no_protocol_enumeration,
    }
    if args.user_agent:
        options["user_agent"] = args.user_agent

    results = inspect_domains(domains, options)
    if args.compact:
        for r in results:
            r.pop("endpoints", None)

    json.dump(results, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
