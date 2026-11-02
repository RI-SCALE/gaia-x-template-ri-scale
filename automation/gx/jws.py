"""Compact JWS (RFC 7515): encode over a pluggable signer, decode, verify.

Hand-rolled on purpose: remote signers (Vault Transit, HSM) only expose
sign(bytes) -> signature, which JOSE libraries don't model. Signing itself lives
in signers.py; this module never touches a private key.
"""

import base64
import json
from collections.abc import Callable
from typing import Any, Final, TypeAlias

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

PublicKey: TypeAlias = rsa.RSAPublicKey | ec.EllipticCurvePublicKey

_HASHES: Final[dict[str, type[hashes.HashAlgorithm]]] = {
    "256": hashes.SHA256,
    "384": hashes.SHA384,
    "512": hashes.SHA512,
}
_CURVES: Final[dict[str, type[ec.EllipticCurve]]] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}
_EC_ALGS: Final[dict[int, str]] = {256: "ES256", 384: "ES384", 521: "ES512"}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def int_to_b64url(n: int) -> str:
    return b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def _b64url_to_int(text: str) -> int:
    return int.from_bytes(b64url_decode(text), "big")


def hash_for(alg: str) -> hashes.HashAlgorithm:
    """RS256 / PS384 / ES512 ... -> the matching hash instance."""
    try:
        return _HASHES[alg[2:]]()
    except KeyError:
        raise ValueError(f"unsupported JWS alg {alg!r}") from None


def pss_padding(alg: str) -> padding.PSS:
    # JOSE PS* uses a salt as long as the digest (RFC 7518 3.5).
    h = hash_for(alg)
    return padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size)


def _json_bytes(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()


def encode(header: dict[str, Any], payload: dict[str, Any], sign: Callable[[bytes], bytes]) -> str:
    """Build a compact JWS. `sign(signing_input: bytes) -> bytes` is any signer's sign method."""
    signing_input = f"{b64url(_json_bytes(header))}.{b64url(_json_bytes(payload))}"
    return f"{signing_input}.{b64url(sign(signing_input.encode('ascii')))}"


def decode(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (header, payload) WITHOUT verifying. Raises ValueError on malformed input."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS (expected three dot-separated parts)")
    try:
        return json.loads(b64url_decode(parts[0])), json.loads(b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"not a compact JWS: {e}") from None


def verify(token: str, public_key: PublicKey) -> bool:
    """True if `token` is validly signed by `public_key` with the alg in its header."""
    header, _ = decode(token)
    signing_input, _, sig_b64 = token.strip().rpartition(".")
    alg, data, sig = header.get("alg", ""), signing_input.encode("ascii"), b64url_decode(sig_b64)
    try:
        if alg.startswith("RS") and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(sig, data, padding.PKCS1v15(), hash_for(alg))
        elif alg.startswith("PS") and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(sig, data, pss_padding(alg), hash_for(alg))
        elif alg.startswith("ES") and isinstance(public_key, ec.EllipticCurvePublicKey):
            half = len(sig) // 2
            der = encode_dss_signature(int.from_bytes(sig[:half], "big"), int.from_bytes(sig[half:], "big"))
            public_key.verify(der, data, ec.ECDSA(hash_for(alg)))
        else:
            return False
    except InvalidSignature:
        return False
    return True


def jwk_to_public_key(jwk: dict[str, str]) -> PublicKey:
    """Public JWK (RSA or EC, as found in a did.json) -> cryptography public key."""
    if jwk.get("kty") == "RSA":
        return rsa.RSAPublicNumbers(_b64url_to_int(jwk["e"]), _b64url_to_int(jwk["n"])).public_key()
    if jwk.get("kty") == "EC" and jwk.get("crv") in _CURVES:
        curve = _CURVES[jwk["crv"]]()
        return ec.EllipticCurvePublicNumbers(_b64url_to_int(jwk["x"]), _b64url_to_int(jwk["y"]), curve).public_key()
    raise ValueError(f"unsupported JWK (kty={jwk.get('kty')!r}, crv={jwk.get('crv')!r})")


def default_alg(public_key: PublicKey) -> str:
    """RS256 for RSA; ES256/ES384/ES512 by curve for EC. Both families pass the lab GXDCH."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RS256"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return _EC_ALGS[public_key.curve.key_size]
    raise ValueError(f"unsupported key type: {type(public_key).__name__}")
