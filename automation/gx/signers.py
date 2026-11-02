"""Signer backends: where the private key lives and how bytes get signed.

This is the one seam between dev and prod. Every backend implements the Signer
protocol, so the pipeline never knows where the key is. Backends are chosen by
`signer.backend` in the config (SIGNERS below).
"""

import os
from abc import abstractmethod
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, Protocol, TypeAlias

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from gx.constants import ALG_AUTO, ENV_VAR_KEY_PASSPHRASE
from gx.errors import SignerError
from gx.jws import PublicKey, default_alg, hash_for, pss_padding


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
    """Dev backend: an unencrypted (or GX_SIGNING_KEY_PASSPHRASE-protected) PEM key file.

    In dev this is the key Caddy generated for its Let's Encrypt certificate. Refused
    in prod by the config guard, since the key would be a readable file on the host.
    """

    def __init__(self, settings: dict[str, Any], alg: str) -> None:
        path = Path(settings.get("key_file", ""))
        if not path.is_file():
            raise SignerError(
                f"signing key not found at {path} (dev: has Caddy obtained its certificate, and "
                "is caddy_data mounted? Or set GX_SIGNING_KEY_FILE)"
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


class VaultTransitSigner(Signer):
    """Prod backend (NOT IMPLEMENTED YET): HashiCorp Vault / OpenBao Transit engine.

    The key is created inside Vault as non-exportable; this process only holds a
    token whose policy allows `transit/sign/<key>` and `transit/keys/<key>` (read).
    Planned calls (https://developer.hashicorp.com/vault/api-docs/secret/transit):

      public_key(): GET  {vault_addr}/v1/{mount}/keys/{key_name}
                    -> data.keys[<latest>].public_key (PEM)
      sign(data):   POST {vault_addr}/v1/{mount}/sign/{key_name}/sha2-256
                    {"input": base64(data),
                     "signature_algorithm": "pkcs1v15",   # RS256 (Vault's RSA default is PSS)
                     "marshaling_algorithm": "jws"}       # ES256: raw r||s, base64url
                    -> data.signature = "vault:v<N>:<signature>"
      CSR for the EV certificate: POST {vault_addr}/v1/{mount}/keys/{key_name}/csr

    Settings (config [signer]): vault_addr, mount (default "transit"), key_name;
    token from VAULT_TOKEN or a file named by VAULT_TOKEN_FILE.
    """

    def __init__(self, settings: dict[str, Any], alg: str) -> None:
        raise SignerError(
            "the Vault signer is planned but not implemented yet (see VaultTransitSigner in "
            "automation/gx/signers.py and automation/README.md)"
        )

    def public_key(self) -> PublicKey:
        raise NotImplementedError

    def sign(self, data: bytes) -> bytes:
        raise NotImplementedError


# Constructor signature every backend shares: (config [signer] section, configured alg).
SignerFactory: TypeAlias = Callable[[dict[str, Any], str], Signer]

SIGNERS: Final[dict[str, SignerFactory]] = {"pem": PemFileSigner, "vault": VaultTransitSigner}


def make_signer(settings: dict[str, Any], alg: str) -> Signer:
    backend = settings.get("backend", "")
    if backend not in SIGNERS:
        raise SignerError(f"unknown signer.backend {backend!r}; expected one of {', '.join(SIGNERS)}")
    return SIGNERS[backend](settings, alg)
