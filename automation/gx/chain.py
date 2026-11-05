"""X.509 identity chain checks and did.json generation.

Shared by the gx tool and scripts/generate_did_json.py, so it depends on
`cryptography` only (no network: callers pass a `fetch(url) -> bytes`).
"""

from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any, Final

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from gx.constants import (
    CERT_FILE,
    DEFAULT_KEY_ID,
    DID_V1_CONTEXT,
    DID_WEB_PREFIX,
    JWS_2020_CONTEXT,
    LETS_ENCRYPT_ROOT_X1_URL,
    OID_EV_SSL,
)
from gx.jws import PublicKey, b64url, int_to_b64url

EV_PROBLEM: Final[str] = (
    f"the leaf certificate does not carry policy OID {OID_EV_SSL} (EV SSL).\n"
    "         Fine for the lab '/development' and '/main' paths.\n"
    "         Every PRODUCTION GXDCH will reply 409 "
    "'The leaf certificate provided is not EV-SSL'.\n"
    "         You need an EV SSL certificate; an eIDAS QTSP can issue one, but a\n"
    "         Qualified Certificate for eSeal cannot be used. "
    "See gaia-x-onboarding.md Step 1."
)

_CRV: Final[dict[int, str]] = {256: "P-256", 384: "P-384", 521: "P-521"}
_MAX_ISSUER_HOPS: Final[int] = 4  # issuers complete_chain() may append; real chains need 1-2


def normalize_domain(domain: str) -> str:
    domain = domain.strip()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.rstrip("/")


def load_chain(pem_text: str) -> list[x509.Certificate]:
    """Every certificate in a PEM bundle, in file order (leaf first)."""
    try:
        return x509.load_pem_x509_certificates(pem_text.encode())
    except ValueError:
        raise ValueError("no certificate found in the PEM data") from None


def order_chain(certs: list[x509.Certificate]) -> list[x509.Certificate]:
    """Leaf first, then each issuer, whatever order the file had.

    A .p12 export (or a CA's download) may list the CA certificates first. The leaf is
    a non-CA, non-self-signed certificate that issued none of the others; certificates
    off its path are dropped.
    """
    issued_others = {id(c) for c in certs if any(o is not c and _issued_by(o, c) for o in certs)}
    leaves = sorted((c for c in certs if id(c) not in issued_others and not is_self_signed(c)), key=_is_ca)
    chain = [leaves[0] if leaves else certs[0]]
    while not is_self_signed(chain[-1]):
        issuer = next((c for c in certs if c not in chain and _issued_by(chain[-1], c)), None)
        if issuer is None:
            break
        chain.append(issuer)
    return chain


def to_pem(chain: list[x509.Certificate]) -> str:
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in chain)


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    if cert.issuer != issuer.subject:
        return False
    try:
        cert.verify_directly_issued_by(issuer)
    except Exception:  # InvalidSignature, ValueError, TypeError (unsupported key/sig type)
        return False
    return True


def is_self_signed(cert: x509.Certificate) -> bool:
    return _issued_by(cert, cert)


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def check_chain(chain: list[x509.Certificate]) -> list[str]:
    """Return the problems the GXDCH Registry would reject this chain for (empty = OK).

    Structure only — the EV policy OID is checked separately (has_ev_oid), because
    it is required in production and irrelevant in the lab.
    Pure: no I/O, no shared state. The caller decides how to report.
    """
    problems = []
    root = chain[-1]

    # 1. The chain must terminate in a self-signed root.
    #    Registry: 409 "Root certificate is not self-signed"
    if len(chain) == 1:
        problems.append(
            "cert.pem contains only one certificate. GAIA-X needs the FULL chain "
            "ending in a self-signed root."
        )
    elif not is_self_signed(root):
        problems.append(
            "the last certificate in cert.pem is NOT self-signed "
            f"(subject={root.subject.rfc4514_string()!r}, "
            f"issuer={root.issuer.rfc4514_string()!r}).\n"
            "         The Registry will reply 409 'Root certificate is not self-signed'.\n"
            "         Append your CA's self-signed root, e.g. for Let's Encrypt:\n"
            f"           curl -s {LETS_ENCRYPT_ROOT_X1_URL} >> cert.pem"
        )

    # 2. Every certificate must be issued (and signed) by the next one in the file.
    #    Registry: 409 "... invalid signature" when a cross-signed link is missing.
    for i in range(len(chain) - 1):
        if not _issued_by(chain[i], chain[i + 1]):
            problems.append(
                f"broken chain at position {i}: "
                f"{chain[i].subject.rfc4514_string()!r} (issuer "
                f"{chain[i].issuer.rfc4514_string()!r}) is not signed by the next "
                f"certificate {chain[i + 1].subject.rfc4514_string()!r}.\n"
                "         Certificates must run leaf -> intermediate(s) -> root with no gaps "
                "(do not drop cross-signed intermediates)."
            )
            break

    return problems


def has_ev_oid(leaf: x509.Certificate) -> bool:
    """Production GXDCH require the EV SSL policy OID on the leaf."""
    try:
        policies = leaf.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
    except x509.ExtensionNotFound:
        return False
    return OID_EV_SSL in {p.policy_identifier.dotted_string for p in policies}


def days_left(cert: x509.Certificate, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    return (cert.not_valid_after_utc - now).days


def covers_domain(leaf: x509.Certificate, domain: str) -> bool:
    """True if the leaf's subjectAltName matches the domain (exactly or by one-label wildcard)."""
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    for name in names.get_values_for_type(x509.DNSName):
        name = name.lower()
        if name == domain or (name.startswith("*.") and domain.partition(".")[2] == name[2:]):
            return True
    return False


def _parse_any(data: bytes) -> list[x509.Certificate]:
    """Certificates from a PEM bundle, a DER certificate or a DER PKCS#7 (.p7c), as served by AIA."""
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_certificates(data)
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        return pkcs7.load_der_pkcs7_certificates(data)


def _aia_issuer_urls(cert: x509.Certificate) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []
    return [
        d.access_location.value
        for d in aia
        if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS
        and isinstance(d.access_location, x509.UniformResourceIdentifier)
    ]


def complete_chain(
    chain: list[x509.Certificate], fetch: Callable[[str], bytes], extra_roots: Iterable[str] = ()
) -> list[x509.Certificate]:
    """Append issuers until the chain ends in a self-signed root.

    Both certbot's fullchain.pem and Caddy's bundle stop below the root, which the
    Registry refuses. Issuers are found via the certificate's AIA "CA Issuers" URL,
    then via `extra_roots` (URLs of PEM roots from config). Each candidate is accepted
    only if it actually signed the current last certificate. Unresolvable chains are
    returned as far as they got; check_chain() then reports the gap.
    """
    chain = list(chain)
    for _ in range(_MAX_ISSUER_HOPS):
        last = chain[-1]
        if is_self_signed(last):
            break
        issuer = None
        for source in (_aia_issuer_urls(last), list(extra_roots)):
            for url in source:
                try:
                    candidates = _parse_any(fetch(url))
                except Exception:  # unreachable URL or unparsable payload: try the next one
                    continue
                issuer = next((c for c in candidates if _issued_by(last, c)), None)
                if issuer:
                    break
            if issuer:
                break
        if issuer is None:
            break
        chain.append(issuer)
    return chain


def public_key_to_jwk(public_key: PublicKey, cert_url: str, alg: str | None = None) -> dict[str, str]:
    if isinstance(public_key, rsa.RSAPublicKey):
        nums = public_key.public_numbers()
        jwk = {"kty": "RSA", "n": int_to_b64url(nums.n), "e": int_to_b64url(nums.e)}
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        nums = public_key.public_numbers()
        size = (public_key.key_size + 7) // 8
        jwk = {
            "kty": "EC",
            "crv": _CRV.get(public_key.key_size, f"P-{public_key.key_size}"),
            "x": b64url(nums.x.to_bytes(size, "big")),
            "y": b64url(nums.y.to_bytes(size, "big")),
        }
    else:
        raise ValueError(f"Unsupported key type: {type(public_key).__name__}")
    # `alg` is optional in a JWK, but browser (Web Crypto) verifiers need it to import
    # the key; the GXDCH Registry publishes it in its own did.json too.
    if alg:
        jwk["alg"] = alg
    jwk["x5u"] = cert_url
    return jwk


def did_document(domain: str, leaf: x509.Certificate, key_id: str = DEFAULT_KEY_ID,
                 cert_url: str | None = None, alg: str | None = None) -> dict[str, Any]:
    did = f"{DID_WEB_PREFIX}{domain}"
    vm_id = f"{did}#{key_id}"
    return {
        "@context": [DID_V1_CONTEXT, JWS_2020_CONTEXT],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_key_to_jwk(
                    leaf.public_key(), cert_url or f"https://{domain}/{CERT_FILE}", alg
                ),
            }
        ],
        "assertionMethod": [vm_id],
    }
