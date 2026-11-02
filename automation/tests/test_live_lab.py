"""Checks against the Gaia-X lab and public services. Run with: pytest --live

They use EGI Foundation's public registration data (VIES) and a placeholder domain, so
they need no host: the full Compliance run signs with the vc-jwt.io test identity, as the
Wizard's test mode does. Expect occasional failures caused by the services themselves.
"""

import socket
import ssl
from datetime import datetime, timedelta, timezone

import pytest
import requests
from cryptography import x509

from gx import credentials, jws
from gx.chain import check_chain, complete_chain, to_pem
from gx.config import Config
from gx.constants import CREDENTIALS_V2_CONTEXT, VC_JWT
from gx.gxdch import Gxdch
from gx.pipeline import Context
from gx.steps import check_compliance_vc

pytestmark = pytest.mark.live

EGI_LEGAL = '''
[legal]
name = "EGI Foundation"
registration_type = "vat-id"
registration_number = "NL821984986B01"
[legal.headquarters_address]
"gx:countryCode" = "NL"
"vcard:street-address" = "Science Park 140"
"vcard:postal-code" = "1098 XG"
"vcard:locality" = "Amsterdam"
"vcard:region" = "NL32"
[legal.legal_address]
"gx:countryCode" = "NL"
"vcard:street-address" = "Science Park 140"
"vcard:postal-code" = "1098 XG"
"vcard:locality" = "Amsterdam"
"vcard:region" = "NL32"
'''
VC_JWT_IO = "https://vc-jwt.io/api/verifiable-credentials"
LETS_ENCRYPT_SITES = ["letsencrypt.org", "certbot.eff.org"]   # ECDSA and RSA chains (2026-11-02)


@pytest.fixture
def lab(deployment) -> tuple[Config, Gxdch]:
    deployment.write_config(legal=EGI_LEGAL)
    cfg = deployment.config()
    return cfg, Gxdch(cfg)


def test_notary_issues_the_lrn(lab) -> None:
    cfg, http = lab
    header, payload = jws.decode(http.registration_number_vc(cfg.url("lrn"), cfg.url("lrn") + "#cs"))
    assert header["iss"] == "did:web:registrationnumber.notary.lab.gaia-x.eu:development"
    assert payload["id"] == cfg.url("lrn")
    assert payload["credentialSubject"] == {"id": cfg.url("lrn") + "#cs", "gx:vatID": "NL821984986B01",
                                            "gx:countryCode": "NL"}


def test_registry_reads(lab) -> None:
    cfg, http = lab
    assert http.ev_only() is False
    assert cfg.credentials["tandc_hash"] in http.accepted_tandc_hashes()
    compliance = http.resolve_did_web("did:web:compliance.lab.gaia-x.eu:development")
    assert compliance["verificationMethod"]


@pytest.mark.parametrize("host", LETS_ENCRYPT_SITES)
def test_registry_accepts_a_completed_lets_encrypt_chain(host: str) -> None:
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=15) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            leaf = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
    chain = complete_chain([leaf], lambda url: requests.get(url, timeout=30).content)
    assert check_chain(chain) == []
    url = "https://registry.lab.gaia-x.eu/development/api/trustAnchor/chain"
    accepted = requests.post(url, json={"certs": to_pem(chain)}, timeout=60)
    assert accepted.status_code == 200 and accepted.json() == {"result": True}, accepted.text
    refused = requests.post(url, json={"certs": to_pem(chain[:2])}, timeout=60)
    assert refused.status_code == 409


def test_full_compliance_run(lab) -> None:
    """gx payloads + the real LRN, signed by vc-jwt.io, submitted and checked by gx."""
    cfg, http = lab
    now = datetime.now(timezone.utc)
    until = now + timedelta(days=90)
    lrn = http.registration_number_vc(cfg.url("lrn"), credentials.registration_number_subject(cfg))
    body = [
        {"@context": CREDENTIALS_V2_CONTEXT, "id": f"data:{VC_JWT},{lrn}", "type": "EnvelopedVerifiableCredential"},
        credentials.legal_person(cfg, now, until),
        credentials.terms_and_conditions(cfg, now, until),
    ]
    signed = requests.post(VC_JWT_IO, json=body, timeout=60)
    signed.raise_for_status()
    vp = signed.text.strip().strip('"')
    vcs = [e["id"].split(",", 1)[1] for e in jws.decode(vp)[1]["verifiableCredential"]]

    token = http.submit(vp, cfg.url("compliance"))
    ctx = Context(cfg, http)
    ctx.staged = dict(zip(("lrn", "legal_person", "tandc"), vcs, strict=True))
    assert "matching digests" in check_compliance_vc(ctx, token)
    assert "gx:ParticipantComplianceCredential" in jws.decode(token)[1]["type"]
