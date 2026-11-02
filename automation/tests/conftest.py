"""Shared fixtures: a throwaway PKI, a dev deployment in a temp directory, and a fake GXDCH.

Tests marked `live` talk to the Gaia-X lab and other public services. They are skipped
unless pytest runs with --live.
"""

import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Final

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from gx import jws
from gx.chain import public_key_to_jwk
from gx.config import Config, load_config
from gx.constants import (
    ENV_OVERRIDES,
    ENV_VAR_CONFIG_DIR,
    ENV_VAR_ENV,
    ENV_VAR_HOSTING_DIR,
    ENV_VAR_KEY_PASSPHRASE,
    OID_EV_SSL,
)
from gx.errors import StepError
from gx.gxdch import Gxdch
from gx.steps import digest_sri

AUTOMATION_DIR: Final[Path] = Path(__file__).resolve().parent.parent
DOMAIN: Final[str] = "gx.test"
ROOT_URL: Final[str] = "http://ca.test/root.der"
COMPLIANCE_DID: Final[str] = "did:web:compliance.lab.gaia-x.eu:development"
NOTARY_DID: Final[str] = "did:web:registrationnumber.notary.lab.gaia-x.eu:development"
GXDCH_KID: Final[str] = "X509-JWK"
OTHER_TANDC_HASH: Final[str] = "067dcac5efd18c1927deb1ffed3feab6d0ad044c0a9a263e6d5d8bdc43224515"

PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


# ── Live tests ────────────────────────────────────────────────────────────────

def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--live", action="store_true", help="also run tests against the Gaia-X lab and public services")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--live"):
        return
    skip = pytest.mark.skip(reason="talks to live services; run with --live")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never see the operator's GX_* variables."""
    for var in (*ENV_OVERRIDES, ENV_VAR_ENV, ENV_VAR_CONFIG_DIR, ENV_VAR_HOSTING_DIR, ENV_VAR_KEY_PASSPHRASE):
        monkeypatch.delenv(var, raising=False)


# ── PKI ───────────────────────────────────────────────────────────────────────

def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(subject: str, issuer: str, public_key: Any, signing_key: PrivateKey, *, ca: bool,
              aia: str | None = None, san: list[str] | None = None, days: int = 80,
              ev: bool = False) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if aia:
        builder = builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(aia))]), critical=False)
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
    if ev:
        builder = builder.add_extension(x509.CertificatePolicies(
            [x509.PolicyInformation(x509.ObjectIdentifier(OID_EV_SSL), None)]), critical=False)
    return builder.sign(signing_key, hashes.SHA256())


def pem(*certs: x509.Certificate) -> str:
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)


def key_pem(key: PrivateKey, passphrase: bytes | None = None) -> bytes:
    encryption = (serialization.BestAvailableEncryption(passphrase) if passphrase
                  else serialization.NoEncryption())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


@dataclass
class Pki:
    """Root -> intermediate (AIA points at the root) -> leaves, like Let's Encrypt."""

    root_key: rsa.RSAPrivateKey
    root: x509.Certificate
    intermediate_key: rsa.RSAPrivateKey
    intermediate: x509.Certificate
    keys: dict[str, PrivateKey]   # pre-generated leaf keys: "rsa", "ec", "rsa2", "ec384"
    gxdch_key: rsa.RSAPrivateKey  # signs the fake Notary and Compliance credentials

    def leaf(self, key: PrivateKey, domain: str = DOMAIN, days: int = 80, ev: bool = False) -> x509.Certificate:
        return make_cert(domain, "Test Intermediate", key.public_key(), self.intermediate_key,
                         ca=False, san=[domain], days=days, ev=ev)


@pytest.fixture(scope="session")
def pki() -> Pki:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return Pki(
        root_key=root_key,
        root=make_cert("Test Root", "Test Root", root_key.public_key(), root_key, ca=True, days=3650),
        intermediate_key=intermediate_key,
        intermediate=make_cert("Test Intermediate", "Test Root", intermediate_key.public_key(), root_key,
                               ca=True, aia=ROOT_URL, days=3650),
        keys={
            "rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "rsa2": rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "ec": ec.generate_private_key(ec.SECP256R1()),
            "ec384": ec.generate_private_key(ec.SECP384R1()),
        },
        gxdch_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


# ── Deployment ────────────────────────────────────────────────────────────────

LEGAL_TOML: Final[str] = '''
[legal]
name = "Test Org"
registration_type = "vat-id"
registration_number = "NL000000000B01"
[legal.headquarters_address]
"gx:countryCode" = "NL"
"vcard:locality" = "Amsterdam"
[legal.legal_address]
"gx:countryCode" = "NL"
'''


@dataclass
class Deployment:
    """A gaia-x-hosting checkout in a temp directory, with Caddy's certificate files simulated."""

    root: Path
    pki: Pki
    key: PrivateKey
    extra_toml: str = ""    # appended tables; must not repeat [identity], [legal], [cert] or [signer]
    signer_toml: str = ""   # extra lines inside [signer]

    @property
    def config_dir(self) -> Path:
        return self.root / "automation" / "config"

    @property
    def chain_file(self) -> Path:
        return self.root / "caddy" / f"{DOMAIN}.crt"

    @property
    def key_file(self) -> Path:
        return self.root / "caddy" / f"{DOMAIN}.key"

    def write_config(self, legal: str = LEGAL_TOML) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        for name in ("base.toml", "dev.toml", "prod.toml"):
            shutil.copy(AUTOMATION_DIR / "config" / name, self.config_dir / name)
        (self.config_dir / "site.toml").write_text(
            f'[identity]\ndomain = "{DOMAIN}"\n{legal}\n'
            f'[cert]\nchain_file = "{self.chain_file.as_posix()}"\n'
            f'[signer]\nkey_file = "{self.key_file.as_posix()}"\n{self.signer_toml}\n{self.extra_toml}',
            encoding="utf-8",
        )

    def install_certificate(self, key: PrivateKey | None = None, days: int = 80) -> x509.Certificate:
        """What Caddy does on (re)issuance: leaf + intermediate (no root), and the key."""
        self.key = key or self.key
        leaf = self.pki.leaf(self.key, days=days)
        self.chain_file.parent.mkdir(parents=True, exist_ok=True)
        self.chain_file.write_text(pem(leaf, self.pki.intermediate), encoding="utf-8")
        self.key_file.write_bytes(key_pem(self.key))
        return leaf

    def config(self, env: str = "dev") -> Config:
        return load_config(env, self.config_dir)

    def published(self, cfg: Config) -> dict[str, str | None]:
        names = ("lrn", "legal_person", "tandc", "compliance")
        return {n: cfg.path(n).read_text() if cfg.path(n).is_file() else None for n in names}


@pytest.fixture
def make_deployment(tmp_path: Path, pki: Pki, monkeypatch: pytest.MonkeyPatch) -> Callable[..., Deployment]:
    def make(key: str = "rsa", extra_toml: str = "", signer_toml: str = "") -> Deployment:
        monkeypatch.setenv(ENV_VAR_HOSTING_DIR, str(tmp_path))
        deployment = Deployment(tmp_path, pki, pki.keys[key], extra_toml, signer_toml)
        deployment.write_config()
        deployment.install_certificate()
        return deployment
    return make


@pytest.fixture
def deployment(make_deployment: Callable[..., Deployment]) -> Deployment:
    return make_deployment()


# ── Fake GXDCH ────────────────────────────────────────────────────────────────

def sign_ps256(key: rsa.RSAPrivateKey, header: dict[str, Any], payload: dict[str, Any]) -> str:
    return jws.encode(header, payload, lambda data: key.sign(data, jws.pss_padding("PS256"), jws.hash_for("PS256")))


def iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class FakeGxdch(Gxdch):
    """The GXDCH, Caddy's CA and our own nginx, in memory.

    Formats mirror what the lab returned on 2026-11-02: PS256 LRN with `iss`/`kid` headers,
    a gx:ParticipantComplianceCredential listing {id, gx:credentialType, digestSRI}.
    `submit` verifies the VP and our VCs the way gx-compliance does (iss/kid, did.json key).
    """

    cfg: Config
    pki: Pki
    refuse: str | None = None          # make submit fail with this message
    corrupt_digest: bool = False       # return a Compliance VC whose digests don't match
    submitted: list[str] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        super().__init__(self.cfg, sleep=lambda _: None)

    def _static(self, url: str) -> Path | None:
        prefix = f"https://{self.cfg.domain}/"
        return self.cfg.static_dir / url[len(prefix):] if url.startswith(prefix) else None

    def fetch(self, url: str) -> bytes:
        if url == ROOT_URL:
            return self.pki.root.public_bytes(serialization.Encoding.DER)
        path = self._static(url)
        if path is None or not path.is_file():
            raise StepError(f"GET {url} returned HTTP 404")
        return path.read_bytes()

    def registration_number_vc(self, vc_id: str, subject_id: str) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/gaia-x/development#"],
            "type": ["VerifiableCredential", "gx:VatID"],
            "id": vc_id,
            "issuer": NOTARY_DID,
            "validFrom": iso(now),
            "validUntil": iso(now + timedelta(days=90)),
            "credentialSubject": {"id": subject_id, "gx:vatID": self.cfg.legal["registration_number"],
                                  "gx:countryCode": "NL"},
        }
        header = {"alg": "PS256", "iss": NOTARY_DID, "kid": f"{NOTARY_DID}#{GXDCH_KID}",
                  "typ": "vc+ld+jwt", "cty": "vc+ld"}
        return sign_ps256(self.pki.gxdch_key, header, payload)

    def chain_accepted(self, cert_url: str) -> tuple[bool, str]:
        try:
            self.fetch(cert_url)
        except StepError as e:
            return False, str(e)
        return True, 'HTTP 200: {"result":true}'

    def ev_only(self) -> bool | None:
        return False

    def accepted_tandc_hashes(self) -> set[str]:
        return {self.cfg.credentials["tandc_hash"], OTHER_TANDC_HASH}

    def _verify(self, token: str) -> dict[str, Any]:
        header, payload = jws.decode(token)
        assert header.get("iss") and header.get("kid"), "gx-compliance requires iss and kid headers"
        doc = self.resolve_did_web(header["iss"])
        method = next(m for m in doc["verificationMethod"] if m["id"] == header["kid"])
        assert jws.verify(token, jws.jwk_to_public_key(method["publicKeyJwk"])), f"bad signature: {header}"
        return payload

    def submit(self, vp_jwt: str, vc_id: str) -> str:
        self.submitted.append(vp_jwt)
        if self.refuse:
            raise StepError(f"the Compliance Service refused the presentation (HTTP 409): {self.refuse}")
        vcs = [e["id"].split(",", 1)[1] for e in self._verify(vp_jwt)["verifiableCredential"]]
        compliant = []
        for token in vcs:
            payload = self._verify(token)
            digest = "sha256-" + "0" * 64 if self.corrupt_digest else digest_sri(token)
            gx_type = next(t for t in payload["type"] if t.startswith("gx:"))
            compliant.append({"id": payload["id"], "gx:credentialType": gx_type, "digestSRI": digest})
        now = datetime.now(timezone.utc)
        payload = {
            "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/gaia-x/development#"],
            "type": ["VerifiableCredential", "gx:ParticipantComplianceCredential"],
            "id": vc_id,
            "issuer": COMPLIANCE_DID,
            "validFrom": iso(now),
            "validUntil": iso(now + timedelta(days=90)),
            "credentialSubject": {"id": f"{vc_id}#cs", "gx:labelLevel": "SC", "gx:compliantCredentials": compliant},
        }
        header = {"alg": "PS256", "iss": COMPLIANCE_DID, "kid": f"{COMPLIANCE_DID}#{GXDCH_KID}",
                  "typ": "vc+jwt", "cty": "vc"}
        return sign_ps256(self.pki.gxdch_key, header, payload)

    def push_event(self, event: dict[str, Any]) -> None:
        self.events.append(event)

    def resolve_did_web(self, did: str) -> dict[str, Any]:
        if did in (COMPLIANCE_DID, NOTARY_DID):
            jwk = public_key_to_jwk(self.pki.gxdch_key.public_key(), "https://gxdch.test/cert.pem", "PS256")
            return {"id": did, "verificationMethod": [{"id": f"{did}#{GXDCH_KID}", "publicKeyJwk": jwk}]}
        if did == self.cfg.did:
            return json.loads(self.fetch_text(self.cfg.did_url))
        return {}


@pytest.fixture
def fake_gxdch(deployment: Deployment, pki: Pki) -> FakeGxdch:
    return FakeGxdch(deployment.config(), pki)
