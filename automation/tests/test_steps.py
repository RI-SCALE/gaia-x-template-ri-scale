"""Step helpers and the Compliance VC check (formats as returned by the lab, 2026-11-02)."""

import hashlib
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gx import credentials, jws
from gx.errors import StepError
from gx.pipeline import Context
from gx.steps import check_compliance_vc, digest_sri, import_wizard_zip, renewal_reasons, write_atomic

from .conftest import COMPLIANCE_DID, GXDCH_KID, Deployment, FakeGxdch, sign_ps256


def test_write_atomic(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b.jwt"
    write_atomic(target, "one")
    write_atomic(target, "two")
    assert target.read_text() == "two"
    assert [p.name for p in target.parent.iterdir()] == ["b.jwt"]


def test_digest_sri_is_sha256_of_jcs_payload() -> None:
    token = jws.encode({"alg": "none"}, {"b": "ä", "a": [1, {"d": 2, "c": 3}]}, lambda data: b"sig")
    canonical = '{"a":[1,{"c":3,"d":2}],"b":"ä"}'.encode()
    assert digest_sri(token) == "sha256-" + hashlib.sha256(canonical).hexdigest()


def test_digest_sri_matches_a_real_lab_value() -> None:
    """The T&C credential from the 2026-11-02 lab run and the digest the Compliance VC listed for it."""
    payload = {
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/gaia-x/development#"],
        "type": ["VerifiableCredential", "gx:Issuer"],
        "id": "https://gx-dev.test/gaia-x/tandc.jwt",
        "issuer": "did:web:vc-jwt.io",
        "validFrom": "2026-11-02T09:33:30.934+00:00",
        "credentialSubject": {
            "id": "https://gx-dev.test/gaia-x/tandc.jwt#cs",
            "gaiaxTermsAndConditions": "4bd7554097444c960292b4726c2efa1373485e8a5565d94d41195214c5e0ceb3",
        },
        "validUntil": "2027-01-31T09:33:30.934+00:00",
    }
    token = jws.encode({"alg": "none"}, payload, lambda data: b"")
    assert digest_sri(token) == "sha256-a94fb50ca4504e9fa60479dbcc87d9b9819e3d171684c6b78db5571151bcff31"


# ── check_compliance_vc ───────────────────────────────────────────────────────

def unsigned(payload: dict) -> str:
    """check_compliance_vc doesn't verify our own credentials, so no signature is needed."""
    return jws.encode({"alg": "none"}, payload, lambda data: b"")


def staged(fake_gxdch: FakeGxdch) -> Context:
    cfg = fake_gxdch.cfg
    ctx = Context(cfg, fake_gxdch)
    now = datetime.now(timezone.utc)
    ctx.staged = {
        "lrn": fake_gxdch.registration_number_vc(cfg.url("lrn"), cfg.url("lrn") + "#cs"),
        "legal_person": unsigned(credentials.legal_person(cfg, now, now + timedelta(days=90))),
        "tandc": unsigned(credentials.terms_and_conditions(cfg, now, now + timedelta(days=90))),
    }
    return ctx


def compliance_vc(ctx: Context, fake_gxdch: FakeGxdch, **changes) -> str:
    cfg = ctx.cfg
    listed = [{"id": cfg.url(n), "digestSRI": digest_sri(ctx.staged[n])} for n in ("lrn", "legal_person", "tandc")]
    payload = {"id": cfg.url("compliance"), "validUntil": "2099-01-01T00:00:00.000Z",
               "credentialSubject": {"gx:compliantCredentials": listed}}
    header = {"alg": "PS256", "iss": COMPLIANCE_DID, "kid": f"{COMPLIANCE_DID}#{GXDCH_KID}"}
    header.update(changes.pop("header", {}))
    payload.update(changes)
    return sign_ps256(fake_gxdch.pki.gxdch_key, header, payload)


def test_compliance_vc_accepted(fake_gxdch: FakeGxdch) -> None:
    ctx = staged(fake_gxdch)
    summary = check_compliance_vc(ctx, compliance_vc(ctx, fake_gxdch))
    assert "attests 3 credentials with matching digests" in summary


@pytest.mark.parametrize("changes, expected", [
    ({"id": "https://elsewhere/vc.jwt"}, "its id is"),
    ({"header": {"iss": "did:web:evil.test"}}, "not by compliance.lab.gaia-x.eu"),
    ({"validUntil": None}, "no readable validUntil"),
    ({"credentialSubject": {"gx:compliantCredentials": []}}, "does not list"),
])
def test_compliance_vc_refused(fake_gxdch: FakeGxdch, changes: dict, expected: str) -> None:
    ctx = staged(fake_gxdch)
    with pytest.raises(StepError, match=expected):
        check_compliance_vc(ctx, compliance_vc(ctx, fake_gxdch, **changes))


def test_compliance_vc_with_another_credentials_digest(fake_gxdch: FakeGxdch) -> None:
    ctx = staged(fake_gxdch)
    token = compliance_vc(ctx, fake_gxdch)
    ctx.staged["tandc"] = ctx.staged["legal_person"]
    with pytest.raises(StepError, match="digest for .*tandc.jwt does not match"):
        check_compliance_vc(ctx, token)


def test_compliance_vc_bad_signature(fake_gxdch: FakeGxdch, pki) -> None:
    ctx = staged(fake_gxdch)
    header, payload = jws.decode(compliance_vc(ctx, fake_gxdch))
    forged = sign_ps256(pki.keys["rsa2"], header, payload)
    with pytest.raises(StepError, match="signature does not verify"):
        check_compliance_vc(ctx, forged)


# ── renewal_reasons ───────────────────────────────────────────────────────────

def test_nothing_published(deployment: Deployment) -> None:
    assert renewal_reasons(deployment.config()) == (["no Compliance VC published yet"], "")


def test_expiring_compliance_vc(deployment: Deployment) -> None:
    cfg = deployment.config()
    soon = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    write_atomic(cfg.path("compliance"), jws.encode({"alg": "none"}, {"validUntil": soon}, lambda d: b""))
    reasons, info = renewal_reasons(cfg)
    assert any("expires in" in r for r in reasons) and "valid for" in info
    assert any("legal-person.jwt is missing" in r for r in reasons)


# ── Wizard zip ────────────────────────────────────────────────────────────────

def test_import_wizard_zip(deployment: Deployment, tmp_path: Path) -> None:
    cfg = deployment.config()
    ours = jws.encode({"alg": "none", "iss": cfg.did}, {"id": cfg.url("tandc")}, lambda d: b"")
    foreign = jws.encode({"alg": "none", "iss": "did:web:vc-jwt.io"}, {"id": cfg.url("legal_person")}, lambda d: b"")
    other = jws.encode({"alg": "none"}, {"id": "https://wizard.test/x.jwt"}, lambda d: b"")
    archive = tmp_path / "credentials.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("Terms and conditions.jwt", ours)
        z.writestr("Legal Person.jwt", foreign)
        z.writestr("Other.jwt", other)
        z.writestr("readme.json", json.dumps({}))
    lines = import_wizard_zip(cfg, archive)
    assert cfg.path("tandc").read_text() == ours
    assert not cfg.path("legal_person").exists()
    assert "imported gaia-x/tandc.jwt" in lines and sum("skipped" in line for line in lines) == 2


def test_import_wizard_zip_without_our_credentials(deployment: Deployment, tmp_path: Path) -> None:
    archive = tmp_path / "credentials.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("x.jwt", jws.encode({"alg": "none"}, {"id": "https://wizard.test/x"}, lambda d: b""))
    with pytest.raises(StepError, match="Path A"):
        import_wizard_zip(deployment.config(), archive)
