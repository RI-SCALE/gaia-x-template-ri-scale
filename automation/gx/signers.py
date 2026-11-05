"""Signer backends: where the private key lives and how bytes get signed.

Every backend implements the Signer protocol, so the pipeline never knows where the
key is. The identity source in the config picks the backend (SIGNERS below):
  vault        TransitSigner   key in OpenBao; gx can only ask for signatures (default)
  letsencrypt  PemFileSigner   Caddy's key file (dev fallback without any own certificate)
"""

import base64
import os
from abc import abstractmethod
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, Protocol, TypeAlias

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from gx.constants import (
    ALG_AUTO,
    ENV_VAR_KEY_PASSPHRASE,
    OPENBAO_HASHES,
    OPENBAO_KEY,
    OPENBAO_KEY_TYPES,
    OPENBAO_RENEW_SELF,
    OPENBAO_SIGN,
    OPENBAO_TOKEN_HEADER,
    SIGNER_PEM,
    SIGNER_TRANSIT,
)
from gx.errors import SignerError
from gx.jws import PublicKey, b64url_decode, default_alg, hash_for, pss_padding

OPENBAO_TIMEOUT: Final[int] = 30   # seconds per request

# How TransitSigner opens its HTTP session; tests replace it with a simulated OpenBao.
session_factory: Callable[[], requests.Session] = requests.Session


class Signer(Protocol):
    """What the pipeline needs from a key, wherever it lives. Backends subclass it explicitly."""

    alg: str  # JWS alg, e.g. "RS256"

    @abstractmethod
    def public_key(self) -> PublicKey:
        """The public key, to cross-check against cert.pem."""

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """JWS-ready signature over `data` (for EC: raw r||s, not DER)."""


class PemFileSigner(Signer):
    """Let's Encrypt setup only: the key file Caddy generated for its certificate.

    Unencrypted, or protected with GX_SIGNING_KEY_PASSPHRASE. The config refuses this
    setup in prod, since the key is a readable file on the host.
    """

    def __init__(self, settings: dict[str, Any], alg: str) -> None:
        path = Path(settings.get("key_file", ""))
        if not path.is_file():
            raise SignerError(
                f"signing key not found at {path}: has Caddy obtained its certificate, and does .env "
                "select the Let's Encrypt setup (compose.letsencrypt.yml mounts Caddy's storage)?"
            )
        passphrase = os.environ.get(ENV_VAR_KEY_PASSPHRASE)
        try:
            key = serialization.load_pem_private_key(path.read_bytes(), passphrase.encode() if passphrase else None)
        except (ValueError, TypeError) as e:
            raise SignerError(f"cannot load the private key from {path}: {e}") from None
        if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise SignerError(f"unsupported key type in {path}: {type(key).__name__}")
        self._key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey = key
        self.alg = default_alg(key.public_key()) if alg == ALG_AUTO else alg

    def public_key(self) -> PublicKey:
        return self._key.public_key()

    def sign(self, data: bytes) -> bytes:
        key, alg = self._key, self.alg
        if alg.startswith("RS") and isinstance(key, rsa.RSAPrivateKey):
            return key.sign(data, padding.PKCS1v15(), hash_for(alg))
        if alg.startswith("PS") and isinstance(key, rsa.RSAPrivateKey):
            return key.sign(data, pss_padding(alg), hash_for(alg))
        if alg.startswith("ES") and isinstance(key, ec.EllipticCurvePrivateKey):
            # JWS wants raw r||s, each left-padded to the curve size, not DER.
            r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hash_for(alg))))
            size = (key.curve.key_size + 7) // 8
            return r.to_bytes(size, "big") + s.to_bytes(size, "big")
        raise SignerError(f"alg {alg} does not match the {type(key).__name__}")


class TransitSigner(Signer):
    """Default backend: the key lives in OpenBao's Transit engine and never leaves it.

    gx holds only a sign-only token, written by automation/openbao/admin.sh. Its policy
    allows reading the key's public part and signing with it, nothing else; the key is
    non-exportable even for the admin. The same calls work on HashiCorp Vault.

    Formats verified against OpenBao 2.7.1 (2026-11-05): signatures come back as
    "vault:v<N>:<value>", standard base64 for RSA and, with marshaling_algorithm=jws,
    base64url raw r||s for EC. A sealed server answers 503 to every request.
    """

    def __init__(self, settings: dict[str, Any], alg: str, session: requests.Session | None = None) -> None:
        self._base = settings["address"].rstrip("/")
        self.key_name: str = settings["key_name"]
        self._mount: str = settings["mount"]
        self._session = session or session_factory()
        self._session.headers[OPENBAO_TOKEN_HEADER] = self._read_token(Path(settings["token_file"]))

        info = self._call("GET", OPENBAO_KEY.format(mount=self._mount, name=self.key_name))
        if info.get("type") not in OPENBAO_KEY_TYPES:
            raise SignerError(f"OpenBao key {self.key_name!r} has type {info.get('type')!r}; "
                              f"an identity key must be one of {', '.join(OPENBAO_KEY_TYPES)}")
        self.version: int = int(info["latest_version"])
        public = serialization.load_pem_public_key(info["keys"][str(self.version)]["public_key"].encode())
        if not isinstance(public, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise SignerError(f"unsupported public key in OpenBao key {self.key_name!r}")
        self._public: PublicKey = public
        self.alg = default_alg(public) if alg == ALG_AUTO else alg
        if self.alg[:2] not in (("RS", "PS") if isinstance(public, rsa.RSAPublicKey) else ("ES",)):
            raise SignerError(f"alg {self.alg} does not match the {info['type']} key in OpenBao")
        self._renew_token()

    @staticmethod
    def _read_token(path: Path) -> str:
        token = path.read_text(encoding="utf-8").strip() if path.is_file() else ""
        if not token:
            raise SignerError(f"no OpenBao token at {path}: create it with `automation/openbao/admin.sh setup` "
                              "(or `admin.sh token` to issue a new one)")
        return token

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            response = self._session.request(method, self._base + path, json=body, timeout=OPENBAO_TIMEOUT)
        except requests.RequestException as e:
            raise SignerError(f"cannot reach OpenBao at {self._base} ({e}); is the openbao service running?") from None
        if response.status_code == 503:
            raise SignerError("OpenBao is sealed (locked after a restart): unlock it with "
                              "`automation/openbao/admin.sh unseal`")
        if response.status_code == 403:
            raise SignerError("OpenBao refused gx's token (expired, revoked or not allowed for key "
                              f"{self.key_name!r}): issue a new one with `automation/openbao/admin.sh token`")
        if response.status_code == 404:
            raise SignerError(f"no key {self.key_name!r} in OpenBao: import the identity first with "
                              "`automation/openbao/admin.sh import <file.p12>`")
        if response.status_code >= 300:
            raise SignerError(f"OpenBao answered HTTP {response.status_code} to {method} {path}: "
                              f"{response.text.strip()[:500]}")
        if not response.content:
            return {}
        return response.json().get("data") or {}

    def _renew_token(self) -> None:
        """Extend the periodic token on every use, so it only expires after a long idle period."""
        try:
            self._call("POST", OPENBAO_RENEW_SELF, {})
        except SignerError:
            pass   # a non-renewable token still works until it expires

    def public_key(self) -> PublicKey:
        return self._public

    def sign(self, data: bytes) -> bytes:
        family = self.alg[:2]
        body: dict[str, Any] = {"input": base64.b64encode(data).decode()}
        if family == "RS":
            body["signature_algorithm"] = "pkcs1v15"   # OpenBao's RSA default is PSS
        elif family == "PS":
            body.update(signature_algorithm="pss", salt_length="hash")   # JOSE: salt = digest size
        else:
            body["marshaling_algorithm"] = "jws"      # raw r||s, as JWS needs
        try:
            hash_name = OPENBAO_HASHES[self.alg[2:]]
        except KeyError:
            raise SignerError(f"unsupported JWS alg {self.alg}") from None
        path = OPENBAO_SIGN.format(mount=self._mount, name=self.key_name, hash=hash_name)
        value = self._call("POST", path, body)["signature"].split(":", 2)[2]
        return b64url_decode(value) if family == "ES" else base64.b64decode(value)


# Constructor signature every backend shares: (config [signer] section, configured alg).
SignerFactory: TypeAlias = Callable[[dict[str, Any], str], Signer]

SIGNERS: Final[dict[str, SignerFactory]] = {SIGNER_PEM: PemFileSigner, SIGNER_TRANSIT: TransitSigner}


def make_signer(settings: dict[str, Any], alg: str) -> Signer:
    backend = settings.get("backend", "")
    if backend not in SIGNERS:
        raise SignerError(f"unknown signer.backend {backend!r}; expected one of {', '.join(SIGNERS)}")
    return SIGNERS[backend](settings, alg)
