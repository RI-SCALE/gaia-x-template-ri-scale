"""Setup A for real: OpenBao in Docker, the admin tool, and gx signing through it.

Runs the server with automation/openbao/config.hcl and the openbao-admin image built
from automation/openbao, and drives admin-task.sh the way admin.sh does, answering
its prompts through stdin. Needs Docker; run from WSL or Linux:

    pytest --openbao

The tests in this module build on each other (init, then import, then ...), like an
admin's first session.
"""

import os
import re
import socket
import subprocess
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from gx import jws
from gx.chain import load_chain, order_chain
from gx.constants import ENV_VAR_HOSTING_DIR, SOURCE_VAULT
from gx.errors import SignerError
from gx.pipeline import AutoGate, Context, run_steps
from gx.signers import TransitSigner
from gx.steps import STEPS

from .conftest import AUTOMATION_DIR, DOMAIN, Deployment, FakeGxdch, Pki, PrivateKey

pytestmark = pytest.mark.openbao

OPENBAO_DIR = AUTOMATION_DIR / "openbao"
COMPOSE_FILE = AUTOMATION_DIR.parent / "docker-compose.yml"
ADMIN_IMAGE = "gx-openbao-admin:test"
P12_PASSWORD = "p12-pass phrase"


def openbao_image() -> str:
    """The exact image docker-compose.yml runs, so the tests can't drift from it."""
    match = re.search(r"image:\s*(openbao/openbao:\S+)", COMPOSE_FILE.read_text(encoding="utf-8"))
    assert match, "no openbao image in docker-compose.yml"
    return match.group(1)


# An empty client config: anonymous pulls, no credential helper (Docker Desktop's breaks in WSL).
DOCKER_ENV = {**os.environ, "DOCKER_CONFIG": tempfile.mkdtemp(prefix="gx-test-docker-")}


def docker(*args: str, stdin: str = "", check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], input=stdin, capture_output=True, text=True, check=check, env=DOCKER_ENV)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_p12(pki: Pki, key: PrivateKey, domain: str = DOMAIN, password: str = P12_PASSWORD) -> bytes:
    """What a CA hands over: key + certificate + intermediate, password-protected."""
    return pkcs12.serialize_key_and_certificates(
        b"identity", key, pki.leaf(key, domain=domain), [pki.intermediate],
        serialization.BestAvailableEncryption(password.encode()))


@dataclass
class Bao:
    """One OpenBao server container plus the admin tool's certs/ and secrets/ directories."""

    name: str
    port: int
    work: Path
    unseal_key: str = ""
    admin_token: str = ""

    @property
    def address(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def certs(self) -> Path:
        return self.work / "certs"

    @property
    def secrets(self) -> Path:
        return self.work / "secrets"

    def admin(self, command: str, stdin: str = "", p12: bytes | None = None) -> subprocess.CompletedProcess[str]:
        args = ["run", "--rm", "-i", "--network", f"container:{self.name}",
                "-e", "BAO_ADDR=http://127.0.0.1:8200", "-e", f"GX_DOMAIN={DOMAIN}",
                "-v", f"{self.certs}:/certs", "-v", f"{self.secrets}:/secrets", "--tmpfs", "/work:mode=0700"]
        if p12 is not None:
            p12_file = self.work / "upload.p12"
            p12_file.write_bytes(p12)
            args += ["-v", f"{p12_file}:/in/identity.p12:ro"]
        return docker(*args, ADMIN_IMAGE, command, stdin=stdin, check=False)

    def gx_token(self) -> str:
        """secrets/openbao-token is root-only (as on the host); read it the way gx's container does."""
        return docker("run", "--rm", "-v", f"{self.secrets}:/s:ro", "--entrypoint", "cat",
                      ADMIN_IMAGE, "/s/openbao-token").stdout.strip()

    def signer(self, alg: str = "auto", token: str | None = None) -> TransitSigner:
        token_file = self.work / "gx-token-copy"
        token_file.write_text(token if token is not None else self.gx_token())
        settings = {"address": self.address, "mount": "transit", "key_name": "gx-identity",
                    "token_file": str(token_file)}
        return TransitSigner(settings, alg)

    def api(self, method: str, path: str, token: str) -> requests.Response:
        return requests.request(method, self.address + path, headers={"X-Vault-Token": token}, timeout=30)

    def wait_until_up(self) -> None:
        for _ in range(60):
            try:
                if requests.get(self.address + "/v1/sys/seal-status", timeout=2).ok:
                    return
            except requests.RequestException:
                pass
            time.sleep(0.5)
        raise AssertionError(docker("logs", self.name, check=False).stdout)


@pytest.fixture(scope="session")
def admin_image() -> str:
    try:
        docker("version")
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("Docker is not available here (run from WSL or Linux)")
    docker("pull", "-q", openbao_image())
    docker("build", "-q", "-t", ADMIN_IMAGE, str(OPENBAO_DIR))
    return ADMIN_IMAGE


def start_openbao(work: Path) -> Bao:
    for directory in ("certs", "secrets"):
        (work / directory).mkdir(parents=True, exist_ok=True)
    bao = Bao(f"gx-test-openbao-{uuid.uuid4().hex[:8]}", free_port(), work)
    docker("run", "-d", "--name", bao.name, "-p", f"127.0.0.1:{bao.port}:8200",
           "-v", f"{OPENBAO_DIR / 'config.hcl'}:/openbao/config/config.hcl:ro", openbao_image(), "server")
    bao.wait_until_up()
    return bao


def initialise(bao: Bao) -> subprocess.CompletedProcess[str]:
    result = bao.admin("init", stdin="\n")   # Enter: "both values saved"
    bao.unseal_key = re.search(r"Unseal key\s*:\s*(\S+)", result.stderr).group(1)
    bao.admin_token = re.search(r"Admin token\s*:\s*(\S+)", result.stderr).group(1)
    return result


@pytest.fixture(scope="module")
def bao(admin_image: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Bao]:
    server = start_openbao(tmp_path_factory.mktemp("openbao"))
    try:
        yield server
    finally:
        docker("rm", "-f", server.name, check=False)


# ── An admin's first session ──────────────────────────────────────────────────

def test_init_shows_the_secrets_once_and_writes_gx_token(bao: Bao) -> None:
    result = initialise(bao)
    assert result.returncode == 0, result.stderr
    assert "Save these two values NOW" in result.stderr
    assert "gx's sign-only token written" in result.stdout
    assert bao.gx_token()
    assert requests.get(bao.address + "/v1/sys/seal-status", timeout=5).json()["sealed"] is False
    # secrets/ is root-only, like on the host: search it from a container.
    stored = docker("run", "--rm", "-v", f"{bao.work}:/w:ro", "--entrypoint", "grep", ADMIN_IMAGE,
                    "-rlF", "-e", bao.admin_token, "-e", bao.unseal_key, "/w", check=False)
    assert stored.returncode == 1 and stored.stdout == "", f"admin secrets must not be stored: {stored.stdout}"
    again = bao.admin("init", stdin="\n")
    assert again.returncode != 0 and "already initialised" in again.stderr


def test_import_puts_the_key_into_openbao(bao: Bao, pki: Pki) -> None:
    result = bao.admin("import", stdin=f"{bao.admin_token}\n{P12_PASSWORD}\n", p12=make_p12(pki, pki.keys["rsa"]))
    assert result.returncode == 0, result.stderr
    assert "Key (rsa-2048) imported as 'gx-identity' (version 1), not exportable" in result.stdout
    chain_text = (bao.certs / "identity-chain.pem").read_text()
    assert "PRIVATE KEY" not in chain_text
    chain = order_chain(load_chain(chain_text))
    assert len(chain) == 2 and chain[0].public_key().public_numbers() == pki.keys["rsa"].public_key().public_numbers()


def test_nobody_can_take_the_key_out(bao: Bao) -> None:
    gx = bao.gx_token()
    export = "/v1/transit/export/signing-key/gx-identity"
    assert bao.api("GET", export, bao.admin_token).status_code == 400   # not exportable, even for the admin
    assert bao.api("GET", export, gx).status_code == 403
    assert bao.api("DELETE", "/v1/transit/keys/gx-identity", gx).status_code == 403
    assert bao.api("POST", "/v1/transit/keys/gx-identity/config", gx).status_code == 403
    assert bao.api("GET", "/v1/sys/policies/acl", gx).status_code == 403


@pytest.mark.parametrize("alg", ["auto", "PS256"])
def test_gx_signs_through_openbao(bao: Bao, pki: Pki, alg: str) -> None:
    signer = bao.signer(alg)
    token = jws.encode({"alg": signer.alg}, {"signed": "in OpenBao"}, signer.sign)
    assert jws.verify(token, pki.keys["rsa"].public_key())


def test_full_pipeline_with_real_openbao(bao: Bao, pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_VAR_HOSTING_DIR, str(tmp_path))
    deployment = Deployment(tmp_path, pki, pki.keys["rsa"], SOURCE_VAULT, openbao_address=bao.address)
    deployment.write_config()
    deployment.chain_file.parent.mkdir(parents=True)
    deployment.chain_file.write_text((bao.certs / "identity-chain.pem").read_text())
    deployment.token_file.parent.mkdir(parents=True)
    deployment.token_file.write_text(bao.gx_token())
    fake = FakeGxdch(deployment.config(), pki)
    report = run_steps(Context(fake.cfg, fake), STEPS, AutoGate(), out=lambda line: None)
    assert report.ok and report.renewed, report.to_json()
    assert jws.verify(deployment.published(fake.cfg)["legal_person"], pki.keys["rsa"].public_key())


def test_bad_imports_are_refused_and_change_nothing(bao: Bao, pki: Pki) -> None:
    wrong_password = bao.admin("import", stdin=f"{bao.admin_token}\nnope\n", p12=make_p12(pki, pki.keys["rsa2"]))
    assert wrong_password.returncode != 0 and "cannot open the .p12" in wrong_password.stderr
    other_domain = bao.admin("import", stdin=f"{bao.admin_token}\n{P12_PASSWORD}\n",
                             p12=make_p12(pki, pki.keys["rsa2"], domain="other.test"))
    assert other_domain.returncode != 0 and f"not issued for {DOMAIN}" in other_domain.stderr
    bad_admin = bao.admin("import", stdin=f"not-a-token\n{P12_PASSWORD}\n", p12=make_p12(pki, pki.keys["rsa2"]))
    assert bad_admin.returncode != 0 and "admin token is not valid" in bad_admin.stderr
    assert bao.signer().version == 1


def test_renewal_with_a_new_key_adds_a_version(bao: Bao, pki: Pki) -> None:
    result = bao.admin("import", stdin=f"{bao.admin_token}\n{P12_PASSWORD}\n", p12=make_p12(pki, pki.keys["rsa2"]))
    assert result.returncode == 0, result.stderr
    assert "added as a new version of 'gx-identity' (version 2)" in result.stdout
    signer = bao.signer()
    assert signer.version == 2
    assert signer.public_key().public_numbers() == pki.keys["rsa2"].public_key().public_numbers()


def test_new_gx_token_revokes_the_old_one(bao: Bao) -> None:
    old = bao.gx_token()
    result = bao.admin("token", stdin=f"{bao.admin_token}\n")
    assert result.returncode == 0, result.stderr
    assert bao.gx_token() != old
    with pytest.raises(SignerError, match="refused gx's token"):
        bao.signer(token=old)
    assert bao.signer().version == 2


def test_status(bao: Bao) -> None:
    out = bao.admin("status").stdout
    assert "OpenBao: unlocked" in out
    assert "Key gx-identity: rsa-2048, version 2, exportable: false" in out
    assert "gx token: valid for 89 more days" in out or "gx token: valid for 90 more days" in out
    assert "Certificate: subject=CN=gx.test" in out


def test_restart_seals_and_unseal_reopens(bao: Bao) -> None:
    docker("restart", bao.name)
    bao.wait_until_up()
    with pytest.raises(SignerError, match="OpenBao is sealed"):
        bao.signer()
    assert "SEALED" in bao.admin("status").stdout
    wrong = bao.admin("unseal", stdin="AAAAwrongAAAA\n")
    assert wrong.returncode != 0
    result = bao.admin("unseal", stdin=f"{bao.unseal_key}\n")
    assert result.returncode == 0 and "OpenBao unlocked" in result.stdout, result.stderr
    assert bao.signer().version == 2


# ── EC identity keys ──────────────────────────────────────────────────────────

def test_ec_identity_end_to_end(admin_image: str, pki: Pki, tmp_path: Path) -> None:
    bao = start_openbao(tmp_path)
    try:
        assert initialise(bao).returncode == 0
        result = bao.admin("import", stdin=f"{bao.admin_token}\n{P12_PASSWORD}\n", p12=make_p12(pki, pki.keys["ec"]))
        assert result.returncode == 0 and "Key (ecdsa-p256) imported" in result.stdout, result.stderr
        signer = bao.signer()
        assert signer.alg == "ES256"
        assert jws.verify(jws.encode({"alg": "ES256"}, {"ec": True}, signer.sign), pki.keys["ec"].public_key())
    finally:
        docker("rm", "-f", bao.name, check=False)
