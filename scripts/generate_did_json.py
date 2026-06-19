#!/usr/bin/env python3
"""
Generate did.json from an X.509 certificate (eIDAS seal or EV SSL).

Usage:
    python generate_did_json.py --domain your.domain.eu --cert path/to/cert.pem

Output:
    Prints the did.json to stdout. Redirect to static/.well-known/did.json.

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
    from cryptography.hazmat.primitives.serialization import Encoding
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")


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


def load_leaf_cert(pem_path: Path) -> x509.Certificate:
    pem_text = pem_path.read_text()
    # Split on PEM boundaries, take the first certificate (leaf)
    blocks = []
    current = []
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

    return x509.load_pem_x509_certificate(blocks[0].encode())


def main():
    parser = argparse.ArgumentParser(description="Generate GAIA-X did.json from X.509 certificate")
    parser.add_argument("--domain", required=True, help="Your public domain, e.g. gaia-x.your-ri.eu")
    parser.add_argument("--cert", required=True, help="Path to PEM certificate chain file")
    parser.add_argument("--key-id", default="key-1", help="Verification method key ID suffix (default: key-1)")
    parser.add_argument(
        "--cert-url",
        help="Public URL where cert.pem is hosted (default: https://<domain>/cert.pem)",
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

    cert = load_leaf_cert(Path(args.cert))
    jwk = public_key_to_jwk(cert, cert_url)

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


if __name__ == "__main__":
    main()
