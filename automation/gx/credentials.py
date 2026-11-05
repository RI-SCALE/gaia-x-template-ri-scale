"""Payloads and JOSE headers for our self-signed credentials (Loire / v2, VC-JOSE-COSE).

Modelled on what the lab GXDCH itself publishes (2026-10-27):
  - the Registry's own Legal Person, T&C and VP:
      https://registry.lab.gaia-x.eu/development/api/registry-identity/{legal-person,terms-and-conditions,verifiable-presentation}
  - gx-compliance src/jwt/service/jwt-signature-validation.service.ts: `iss` and `kid` are
    mandatory PROTECTED HEADERS; VCs travel in the VP as EnvelopedVerifiableCredential
    with id "data:application/vc+jwt,<jwt>".
  - gx:AddressShape is closed: gx:countryCode (+ optional vcard fields), nothing else.
No JWT claims (iat/exp) are added: validity lives in validFrom/validUntil, as in the
Registry's own credentials.
"""

from datetime import datetime
from typing import Any, Final, Literal

from gx.config import Config
from gx.constants import CES_EVENT_TYPE, CREDENTIALS_V2_CONTEXT, VC_JWT

SUBJECT_FRAGMENT: Final[str] = "#cs"  # credentialSubject id = credential id + this


def _ts(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def header(cfg: Config, alg: str, kind: Literal["vc", "vp"] = "vc") -> dict[str, str]:
    """Protected header for a VC-JWT (kind="vc") or VP-JWT (kind="vp")."""
    return {"alg": alg, "typ": f"{kind}+jwt", "cty": kind, "iss": cfg.did, "kid": cfg.vm_id}


def registration_number_subject(cfg: Config) -> str:
    """credentialSubject id the Notary puts on the LRN VC; the Legal Person points at it."""
    return f"{cfg.url('lrn')}{SUBJECT_FRAGMENT}"


def _address(fields: dict[str, str]) -> dict[str, str]:
    return {"type": "gx:Address", **fields}


def legal_person(cfg: Config, valid_from: datetime, valid_until: datetime) -> dict[str, Any]:
    vc_id, legal = cfg.url("legal_person"), cfg.legal
    return {
        "@context": cfg.credentials["contexts_legal_person"],
        "type": ["VerifiableCredential", "gx:LegalPerson"],
        "id": vc_id,
        "issuer": cfg.did,
        "validFrom": _ts(valid_from),
        "validUntil": _ts(valid_until),
        "credentialSubject": {
            "id": f"{vc_id}{SUBJECT_FRAGMENT}",
            "type": "gx:LegalPerson",
            "schema:name": legal["name"],
            "gx:registrationNumber": {"id": registration_number_subject(cfg)},
            "gx:headquartersAddress": _address(legal["headquarters_address"]),
            "gx:legalAddress": _address(legal["legal_address"]),
        },
    }


def terms_and_conditions(cfg: Config, valid_from: datetime, valid_until: datetime) -> dict[str, Any]:
    vc_id = cfg.url("tandc")
    return {
        "@context": cfg.credentials["contexts_tandc"],
        "type": ["VerifiableCredential", "gx:Issuer"],
        "id": vc_id,
        "issuer": cfg.did,
        "validFrom": _ts(valid_from),
        "validUntil": _ts(valid_until),
        "credentialSubject": {
            "id": f"{vc_id}{SUBJECT_FRAGMENT}",
            "gaiaxTermsAndConditions": cfg.credentials["tandc_hash"],
        },
    }


def presentation(cfg: Config, vc_jwts: list[str], valid_from: datetime, valid_until: datetime) -> dict[str, Any]:
    return {
        "@context": [CREDENTIALS_V2_CONTEXT],
        "type": ["VerifiablePresentation"],
        "id": cfg.did,
        "holder": cfg.did,
        "issuer": cfg.did,
        "validFrom": _ts(valid_from),
        "validUntil": _ts(valid_until),
        "verifiableCredential": [
            {"@context": CREDENTIALS_V2_CONTEXT, "id": f"data:{VC_JWT},{jwt}",
             "type": "EnvelopedVerifiableCredential"}
            for jwt in vc_jwts
        ],
    }


def cloud_event(cfg: Config, compliance_jwt: str, event_id: str, now: datetime) -> dict[str, str]:
    """CES CloudEvent. Lower-case field names; data_base64 carries the JWT verbatim (see onboarding doc)."""
    return {
        "specversion": "1.0",
        "id": event_id,
        "type": CES_EVENT_TYPE,
        "source": cfg.public_url(""),
        "time": _ts(now),
        "datacontenttype": "application/json",
        "data_base64": compliance_jwt,
    }
