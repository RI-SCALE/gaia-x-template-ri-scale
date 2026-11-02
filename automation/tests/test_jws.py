import pytest
from cryptography.hazmat.primitives.asymmetric import ec, padding

from gx import jws
from gx.chain import public_key_to_jwk

from .conftest import Pki


def signer_for(key, alg: str):
    if alg.startswith("RS"):
        return lambda data: key.sign(data, padding.PKCS1v15(), jws.hash_for(alg))
    if alg.startswith("PS"):
        return lambda data: key.sign(data, jws.pss_padding(alg), jws.hash_for(alg))
    raise AssertionError(alg)


@pytest.mark.parametrize("alg", ["RS256", "RS384", "PS256", "PS512"])
def test_rsa_round_trip(pki: Pki, alg: str) -> None:
    key = pki.keys["rsa"]
    token = jws.encode({"alg": alg}, {"hello": "wörld"}, signer_for(key, alg))
    assert jws.decode(token) == ({"alg": alg}, {"hello": "wörld"})
    assert jws.verify(token, key.public_key())


def test_tampered_payload_fails(pki: Pki) -> None:
    key = pki.keys["rsa"]
    header, payload, signature = jws.encode({"alg": "RS256"}, {"a": 1}, signer_for(key, "RS256")).split(".")
    forged_payload = jws.b64url(b'{"a":2}')
    forged = f"{header}.{forged_payload}.{signature}"
    assert not jws.verify(forged, key.public_key())


def test_wrong_key_or_family_fails(pki: Pki) -> None:
    token = jws.encode({"alg": "RS256"}, {"a": 1}, signer_for(pki.keys["rsa"], "RS256"))
    assert not jws.verify(token, pki.keys["rsa2"].public_key())
    assert not jws.verify(token, pki.keys["ec"].public_key())


def test_ec_signature_is_raw_r_s(pki: Pki) -> None:
    from gx.signers import PemFileSigner  # signing lives in the signer; jws only verifies

    for name, alg, size in (("ec", "ES256", 64), ("ec384", "ES384", 96)):
        key = pki.keys[name]
        signer = object.__new__(PemFileSigner)
        signer._key, signer.alg = key, alg
        token = jws.encode({"alg": alg}, {"a": 1}, signer.sign)
        assert len(jws.b64url_decode(token.split(".")[2])) == size
        assert jws.verify(token, key.public_key())


@pytest.mark.parametrize("bad", ["", "a.b", "a.b.c.d", "!!.@@.##"])
def test_decode_rejects_malformed(bad: str) -> None:
    with pytest.raises(ValueError):
        jws.decode(bad)


@pytest.mark.parametrize("name", ["rsa", "ec", "ec384"])
def test_jwk_round_trip(pki: Pki, name: str) -> None:
    public = pki.keys[name].public_key()
    restored = jws.jwk_to_public_key(public_key_to_jwk(public, "https://x/cert.pem"))
    assert restored.public_numbers() == public.public_numbers()


def test_unsupported_jwk() -> None:
    with pytest.raises(ValueError):
        jws.jwk_to_public_key({"kty": "OKP", "crv": "Ed25519", "x": "AA"})


def test_default_alg(pki: Pki) -> None:
    assert jws.default_alg(pki.keys["rsa"].public_key()) == "RS256"
    assert jws.default_alg(pki.keys["ec"].public_key()) == "ES256"
    assert jws.default_alg(pki.keys["ec384"].public_key()) == "ES384"
    assert jws.default_alg(ec.generate_private_key(ec.SECP521R1()).public_key()) == "ES512"


def test_b64url_has_no_padding() -> None:
    assert jws.b64url(b"\xff\xfe") == "__4"
    assert jws.b64url_decode("__4") == b"\xff\xfe"
    with pytest.raises(ValueError):
        jws.hash_for("HS1")
