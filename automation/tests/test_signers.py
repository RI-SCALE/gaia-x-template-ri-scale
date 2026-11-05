from pathlib import Path

import pytest

from gx import jws
from gx.constants import ENV_VAR_KEY_PASSPHRASE
from gx.errors import SignerError
from gx.signers import PemFileSigner, Signer, TransitSigner, make_signer

from .conftest import OPENBAO_KEY_NAME, FakeOpenBao, Pki, key_pem

# ── PemFileSigner (setup B: Caddy's key file) ─────────────────────────────────


def write_key(tmp_path: Path, key, passphrase: bytes | None = None) -> dict[str, str]:
    path = tmp_path / "identity.key"
    path.write_bytes(key_pem(key, passphrase))
    return {"backend": "pem", "key_file": str(path)}


@pytest.mark.parametrize("name, alg", [("rsa", "RS256"), ("ec", "ES256"), ("ec384", "ES384")])
def test_auto_alg_signs_verifiable_jws(tmp_path: Path, pki: Pki, name: str, alg: str) -> None:
    signer = make_signer(write_key(tmp_path, pki.keys[name]), "auto")
    assert isinstance(signer, PemFileSigner) and signer.alg == alg
    token = jws.encode({"alg": signer.alg}, {"a": 1}, signer.sign)
    assert jws.verify(token, signer.public_key())


def test_explicit_ps256(tmp_path: Path, pki: Pki) -> None:
    signer = make_signer(write_key(tmp_path, pki.keys["rsa"]), "PS256")
    assert jws.verify(jws.encode({"alg": "PS256"}, {"a": 1}, signer.sign), pki.keys["rsa"].public_key())


def test_alg_must_match_key(tmp_path: Path, pki: Pki) -> None:
    signer = make_signer(write_key(tmp_path, pki.keys["ec"]), "RS256")
    with pytest.raises(SignerError, match="does not match"):
        signer.sign(b"data")


def test_encrypted_key_needs_passphrase(tmp_path: Path, pki: Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = write_key(tmp_path, pki.keys["rsa"], b"s3cret")
    with pytest.raises(SignerError, match="cannot load"):
        make_signer(settings, "auto")
    monkeypatch.setenv(ENV_VAR_KEY_PASSPHRASE, "s3cret")
    assert make_signer(settings, "auto").alg == "RS256"


def test_missing_key_file(tmp_path: Path) -> None:
    with pytest.raises(SignerError, match="signing key not found"):
        make_signer({"backend": "pem", "key_file": str(tmp_path / "nope.key")}, "auto")


# ── TransitSigner (setup A: key in OpenBao) ───────────────────────────────────

def transit(tmp_path: Path, openbao: FakeOpenBao, alg: str = "auto", token: str | None = None) -> TransitSigner:
    token_file = tmp_path / "openbao-token"
    token_file.write_text(openbao.token if token is None else token)
    settings = {"address": "http://openbao.test:8200/", "mount": "transit", "key_name": OPENBAO_KEY_NAME,
                "token_file": str(token_file)}
    return TransitSigner(settings, alg, session=openbao)


@pytest.mark.parametrize("name, alg", [("rsa", "auto"), ("rsa", "PS256"), ("rsa", "RS384"),
                                       ("ec", "auto"), ("ec384", "auto")])
def test_transit_signatures_verify(tmp_path: Path, pki: Pki, name: str, alg: str) -> None:
    openbao = FakeOpenBao(keys={OPENBAO_KEY_NAME: [pki.keys[name]]})
    signer = transit(tmp_path, openbao, alg)
    assert signer.alg == (jws.default_alg(pki.keys[name].public_key()) if alg == "auto" else alg)
    token = jws.encode({"alg": signer.alg}, {"hello": "OpenBao"}, signer.sign)
    assert jws.verify(token, pki.keys[name].public_key())
    assert ("POST", "/v1/auth/token/renew-self") in openbao.calls   # keeps the periodic token alive


def test_transit_uses_the_latest_key_version(tmp_path: Path, pki: Pki) -> None:
    openbao = FakeOpenBao(keys={OPENBAO_KEY_NAME: [pki.keys["rsa"], pki.keys["rsa2"]]})
    signer = transit(tmp_path, openbao)
    assert signer.version == 2
    assert signer.public_key().public_numbers() == pki.keys["rsa2"].public_key().public_numbers()


@pytest.mark.parametrize("setup, expected", [
    (lambda bao: setattr(bao, "sealed", True), "OpenBao is sealed"),
    (lambda bao: bao.keys.clear(), "no key 'gx-identity' in OpenBao: import the identity first"),
    (lambda bao: setattr(bao, "token", "rotated"), "refused gx's token"),
])
def test_transit_errors_say_what_to_do(tmp_path: Path, pki: Pki, setup, expected: str) -> None:
    openbao = FakeOpenBao(keys={OPENBAO_KEY_NAME: [pki.keys["rsa"]]})
    token = openbao.token
    setup(openbao)
    with pytest.raises(SignerError, match=expected):
        transit(tmp_path, openbao, token=token)


def test_transit_without_token_file(tmp_path: Path) -> None:
    settings = {"address": "http://x", "mount": "transit", "key_name": "k", "token_file": str(tmp_path / "none")}
    with pytest.raises(SignerError, match="no OpenBao token"):
        TransitSigner(settings, "auto", session=FakeOpenBao())


def test_transit_alg_must_match_key(tmp_path: Path, pki: Pki) -> None:
    with pytest.raises(SignerError, match="does not match the ecdsa-p256 key"):
        transit(tmp_path, FakeOpenBao(keys={OPENBAO_KEY_NAME: [pki.keys["ec"]]}), alg="RS256")


def test_unreachable_openbao(tmp_path: Path) -> None:
    settings = {"address": "http://127.0.0.1:9", "mount": "transit", "key_name": "k",
                "token_file": str(tmp_path / "t")}
    (tmp_path / "t").write_text("x")
    with pytest.raises(SignerError, match="cannot reach OpenBao"):
        TransitSigner(settings, "auto")


# ── Both ──────────────────────────────────────────────────────────────────────

def test_unknown_backend() -> None:
    with pytest.raises(SignerError, match="unknown signer.backend"):
        make_signer({"backend": "hsm"}, "auto")


def test_backends_implement_the_protocol() -> None:
    assert Signer in PemFileSigner.__mro__ and Signer in TransitSigner.__mro__

    class Incomplete(Signer):
        alg = "RS256"

        def sign(self, data: bytes) -> bytes:
            return b""

    with pytest.raises(TypeError, match="public_key"):
        Incomplete()
