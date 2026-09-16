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

Requirements:
    pip install cryptography
"""

import argparse
import base64
import json
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.x509.oid import ExtensionOID
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")


# CA/Browser Forum Extended Validation certificate-policy identifier (an OID, not a
# version — OIDs are permanent). Copied from GAIA-X's own registry source, which
# rejects any leaf certificate without it whenever the registry's `evsslonly` flag
# is true — the case on every production GXDCH. If GAIA-X changes that rule, update
# this one line; the live registry check in the docs remains the authoritative gate.
#   https://gitlab.com/gaia-x/lab/compliance/gx-registry/-/blob/development/src/trust-anchor/services/trust-anchor.service.ts
OID_EV_SSL = "2.23.140.1.1"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def int_to_b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return b64url(n.to_bytes(length, "big"))


def public_key_to_jwk(cert: x509.Certificate, cert_url: str) -> dict:
    pub = cert.public_key()

    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        return {
            "kty": "RSA",
            "n": int_to_b64url(nums.n),
            "e": int_to_b64url(nums.e),
            "x5u": cert_url,
        }
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        size = (pub.key_size + 7) // 8
        crv_map = {256: "P-256", 384: "P-384", 521: "P-521"}
        return {
            "kty": "EC",
            "crv": crv_map.get(pub.key_size, f"P-{pub.key_size}"),
            "x": b64url(nums.x.to_bytes(size, "big")),
            "y": b64url(nums.y.to_bytes(size, "big")),
            "x5u": cert_url,
        }
    else:
        sys.exit(f"Unsupported key type: {type(pub).__name__}")


def load_chain(pem_path: Path) -> list:
    """Load every certificate in the PEM file, in file order (leaf first)."""
    pem_text = pem_path.read_text()
    blocks, current = [], []
    for line in pem_text.splitlines():
        if line.startswith("-----BEGIN CERTIFICATE-----"):
            current = [line]
        elif line.startswith("-----END CERTIFICATE-----"):
            current.append(line)
            blocks.append("\n".join(current))
            current = []
        elif current:
            current.append(line)

    if not blocks:
        sys.exit("No certificate found in the PEM file.")

    return [x509.load_pem_x509_certificate(b.encode()) for b in blocks]


def check_chain(chain: list) -> list:
    """Return the problems the GXDCH Registry would reject this chain for (empty = OK).

    Pure: no I/O, no shared state. The caller decides how to report.
    """
    problems = []
    leaf, root = chain[0], chain[-1]

    # 1. The chain must terminate in a self-signed root.
    #    Registry: 409 "Root certificate is not self-signed"
    if len(chain) == 1:
        problems.append(
            "cert.pem contains only one certificate. GAIA-X needs the FULL chain "
            "ending in a self-signed root."
        )
    elif root.subject != root.issuer:
        problems.append(
            "the last certificate in cert.pem is NOT self-signed "
            f"(subject={root.subject.rfc4514_string()!r}, "
            f"issuer={root.issuer.rfc4514_string()!r}).\n"
            "         The Registry will reply 409 'Root certificate is not self-signed'.\n"
            "         Append your CA's self-signed root, e.g. for Let's Encrypt:\n"
            "           curl -s https://letsencrypt.org/certs/isrgrootx1.pem >> cert.pem"
        )

    # 2. Every certificate must be issued by the next one in the file.
    #    Registry: 409 "... invalid signature" when a cross-signed link is missing.
    for i in range(len(chain) - 1):
        if chain[i].issuer != chain[i + 1].subject:
            problems.append(
                f"broken chain order at position {i}: issuer of "
                f"{chain[i].subject.rfc4514_string()!r} is "
                f"{chain[i].issuer.rfc4514_string()!r}, but the next certificate is "
                f"{chain[i + 1].subject.rfc4514_string()!r}.\n"
                "         Certificates must run leaf -> intermediate(s) -> root with no gaps "
                "(do not drop cross-signed intermediates)."
            )
            break

    # 3. Production GXDCH require the EV SSL policy OID on the leaf.
    try:
        policies = leaf.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
        oids = {p.policy_identifier.dotted_string for p in policies}
    except x509.ExtensionNotFound:
        oids = set()

    if OID_EV_SSL not in oids:
        problems.append(
            f"the leaf certificate does not carry policy OID {OID_EV_SSL} (EV SSL).\n"
            "         Fine for the lab '/development' and '/main' paths.\n"
            "         Every PRODUCTION GXDCH will reply 409 "
            "'The leaf certificate provided is not EV-SSL'.\n"
            "         See gaia-x-onboarding.md Step 1 before buying a certificate."
        )

    return problems


def main():
    parser = argparse.ArgumentParser(description="Generate GAIA-X did.json from X.509 certificate")
    parser.add_argument("--domain", required=True, help="Your public domain, e.g. gaia-x.your-ri.eu")
    parser.add_argument("--cert", required=True, help="Path to PEM certificate chain file")
    parser.add_argument("--key-id", default="key-1", help="Verification method key ID suffix (default: key-1)")
    parser.add_argument(
        "--cert-url",
        help="Public URL where cert.pem is hosted (default: https://<domain>/cert.pem)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any chain problem is found (for CI)",
    )
    args = parser.parse_args()

    domain = args.domain.strip()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.rstrip("/")
    cert_url = args.cert_url or f"https://{domain}/cert.pem"
    did = f"did:web:{domain}"
    vm_id = f"{did}#{args.key_id}"

    chain = load_chain(Path(args.cert))

    problems = check_chain(chain)
    for problem in problems:
        print(f"WARNING: {problem}", file=sys.stderr)
    if not problems:
        print("OK: chain checks passed — accepted by production GXDCH.", file=sys.stderr)

    jwk = public_key_to_jwk(chain[0], cert_url)

    did_doc = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
        "assertionMethod": [vm_id],
    }

    print(json.dumps(did_doc, indent=2))

    if args.strict and problems:
        sys.exit(f"{len(problems)} chain problem(s) found; --strict was requested.")


if __name__ == "__main__":
    main()
