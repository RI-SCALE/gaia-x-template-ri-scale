"""Payload formats, as modelled on the lab Registry's own credentials (see gx/credentials.py)."""

import re
from datetime import datetime, timedelta, timezone

from gx import credentials
from gx.config import Config

from .conftest import DOMAIN, Deployment

NOW = datetime(2026, 11, 2, 9, 30, tzinfo=timezone.utc)
UNTIL = NOW + timedelta(days=90)
TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")


def config(deployment: Deployment) -> Config:
    return deployment.config()


def test_headers(deployment: Deployment) -> None:
    cfg = config(deployment)
    assert credentials.header(cfg, "RS256") == {
        "alg": "RS256", "typ": "vc+jwt", "cty": "vc", "iss": cfg.did, "kid": cfg.vm_id}
    vp = credentials.header(cfg, "ES256", "vp")
    assert vp["typ"] == "vp+jwt" and vp["cty"] == "vp"


def test_legal_person(deployment: Deployment) -> None:
    cfg = config(deployment)
    lp = credentials.legal_person(cfg, NOW, UNTIL)
    subject = lp["credentialSubject"]
    assert lp["id"] == f"https://{DOMAIN}/gaia-x/legal-person.jwt"
    assert lp["issuer"] == cfg.did
    assert lp["type"] == ["VerifiableCredential", "gx:LegalPerson"]
    assert lp["validFrom"] == "2026-11-02T09:30:00.000Z" and TIMESTAMP.match(lp["validUntil"])
    assert subject["id"] == lp["id"] + "#cs"
    assert subject["schema:name"] == "Test Org"
    assert subject["gx:registrationNumber"] == {"id": f"https://{DOMAIN}/gaia-x/lrn.jwt#cs"}
    assert subject["gx:headquartersAddress"] == {
        "type": "gx:Address", "gx:countryCode": "NL", "vcard:locality": "Amsterdam"}
    assert subject["gx:legalAddress"] == {"type": "gx:Address", "gx:countryCode": "NL"}
    assert "https://w3id.org/gaia-x/development#" in lp["@context"]


def test_terms_and_conditions(deployment: Deployment) -> None:
    cfg = config(deployment)
    tc = credentials.terms_and_conditions(cfg, NOW, UNTIL)
    assert tc["type"] == ["VerifiableCredential", "gx:Issuer"]
    assert tc["credentialSubject"]["gaiaxTermsAndConditions"] == cfg.credentials["tandc_hash"]


def test_presentation_envelopes(deployment: Deployment) -> None:
    cfg = config(deployment)
    vp = credentials.presentation(cfg, ["a.b.c", "d.e.f"], NOW, UNTIL)
    assert vp["holder"] == vp["issuer"] == vp["id"] == cfg.did
    assert vp["verifiableCredential"][1] == {
        "@context": "https://www.w3.org/ns/credentials/v2",
        "id": "data:application/vc+jwt,d.e.f",
        "type": "EnvelopedVerifiableCredential",
    }


def test_cloud_event(deployment: Deployment) -> None:
    event = credentials.cloud_event(config(deployment), "x.y.z", "id-1", NOW)
    assert event["source"] == f"https://{DOMAIN}/"
    assert event["type"] == "eu.gaia-x.credential" and event["data_base64"] == "x.y.z"
