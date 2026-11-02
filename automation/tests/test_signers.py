from pathlib import Path

import pytest

from gx import jws
from gx.constants import ENV_VAR_KEY_PASSPHRASE
from gx.errors import SignerError
from gx.signers import PemFileSigner, Signer, VaultTransitSigner, make_signer

from .conftest import Pki, key_pem


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


def test_vault_is_a_stub_and_unknown_backends_fail() -> None:
    with pytest.raises(SignerError, match="not implemented yet"):
        make_signer({"backend": "vault"}, "auto")
    with pytest.raises(SignerError, match="unknown signer.backend"):
        make_signer({"backend": "hsm"}, "auto")


def test_backends_implement_the_protocol() -> None:
    assert Signer in PemFileSigner.__mro__ and Signer in VaultTransitSigner.__mro__

    class Incomplete(Signer):
        alg = "RS256"

        def sign(self, data: bytes) -> bytes:
            return b""

    with pytest.raises(TypeError, match="public_key"):
        Incomplete()
