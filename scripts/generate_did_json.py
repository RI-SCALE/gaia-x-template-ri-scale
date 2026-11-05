#!/usr/bin/env python3
"""
Generate did.json from an X.509 certificate chain, and sanity-check the chain
against the rules the GAIA-X Registry actually enforces.

Usage:
    python generate_did_json.py --domain your.domain.eu --cert path/to/cert.pem

Output:
    Prints did.json to stdout. Redirect to static/.well-known/did.json.
    Warnings go to stderr, so redirecting stdout stays safe.

Options:
    --strict   exit non-zero if any chain problem is found (use in CI)

The logic lives in automation/gx/chain.py, shared with the gx automation tool
(which runs this step for you: see automation/README.md).

Requirements:
    pip install cryptography
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "automation"))

try:
    from gx.chain import EV_PROBLEM, check_chain, did_document, has_ev_oid, load_chain, normalize_domain
    from gx.constants import DEFAULT_KEY_ID
    from gx.jws import default_alg
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")


def main():
    parser = argparse.ArgumentParser(description="Generate GAIA-X did.json from X.509 certificate")
    parser.add_argument("--domain", required=True, help="Your public domain, e.g. gaia-x.your-ri.eu")
    parser.add_argument("--cert", required=True, help="Path to PEM certificate chain file")
    parser.add_argument(
        "--key-id", default=DEFAULT_KEY_ID, help=f"Verification method key ID suffix (default: {DEFAULT_KEY_ID})"
    )
    parser.add_argument(
        "--cert-url",
        help="Public URL where cert.pem is hosted (default: https://<domain>/cert.pem)",
    )
    parser.add_argument(
        "--alg",
        help="JWS algorithm published in the JWK (default: RS256 for RSA, ES256/384/512 for EC)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any chain problem is found (for CI)",
    )
    args = parser.parse_args()

    domain = normalize_domain(args.domain)
    try:
        chain = load_chain(Path(args.cert).read_text())
    except ValueError as e:
        sys.exit(f"{args.cert}: {e}")

    problems = check_chain(chain)
    if not has_ev_oid(chain[0]):
        problems.append(EV_PROBLEM)
    for problem in problems:
        print(f"WARNING: {problem}", file=sys.stderr)
    if not problems:
        print("OK: chain checks passed — accepted by production GXDCH.", file=sys.stderr)

    leaf = chain[0]
    alg = args.alg or default_alg(leaf.public_key())
    print(json.dumps(did_document(domain, leaf, args.key_id, args.cert_url, alg), indent=2))

    if args.strict and problems:
        sys.exit(f"{len(problems)} chain problem(s) found; --strict was requested.")


if __name__ == "__main__":
    main()
