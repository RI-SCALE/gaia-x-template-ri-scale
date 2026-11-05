"""Fixed names the gx tool depends on, in one place: local paths, published file paths,
URLs and URL paths, media types, environment variable names and other external identifiers.

Values that change per deployment belong in the TOML configuration, not here. This
module uses the standard library only, so scripts/generate_did_json.py can import
the chain helpers with nothing but `cryptography` installed.
"""

from pathlib import Path
from typing import Final

# ── Environments ──────────────────────────────────────────────────────────────

ENVS: Final[tuple[str, ...]] = ("dev", "prod")
DEFAULT_ENV: Final[str] = "dev"

# Dev may only use these lab deployments: /v2 on the lab is a production one (EV only).
LAB_HOST: Final[str] = "lab.gaia-x.eu"
LAB_PATHS: Final[tuple[str, ...]] = ("/development", "/main")

# ── Environment variables ─────────────────────────────────────────────────────

ENV_VAR_ENV: Final[str] = "GX_ENV"
ENV_VAR_CONFIG_DIR: Final[str] = "GX_CONFIG_DIR"
ENV_VAR_HOSTING_DIR: Final[str] = "GX_HOSTING_DIR"
ENV_VAR_KEY_PASSPHRASE: Final[str] = "GX_SIGNING_KEY_PASSPHRASE"

# Variable -> (section, key). Applied last, so they win over every config file.
ENV_OVERRIDES: Final[dict[str, tuple[str, str]]] = {
    "GX_DOMAIN": ("identity", "domain"),
    "GX_IDENTITY": ("identity", "source"),
    "GX_STATIC_DIR": ("paths", "static_dir"),
}

# ── Identity sources ──────────────────────────────────────────────────────────
# Where the identity certificate and its key come from (config identity.source).

SOURCE_VAULT: Final[str] = "vault"              # own certificate, key in OpenBao (default, prod)
SOURCE_LETSENCRYPT: Final[str] = "letsencrypt"  # Caddy's certificate and key file (dev fallback)
IDENTITY_SOURCES: Final[tuple[str, ...]] = (SOURCE_VAULT, SOURCE_LETSENCRYPT)

SIGNER_TRANSIT: Final[str] = "transit"          # signer backend for SOURCE_VAULT
SIGNER_PEM: Final[str] = "pem"                  # signer backend for SOURCE_LETSENCRYPT
# Keys of the [vault] config section handed to the Transit signer.
TRANSIT_SETTINGS: Final[tuple[str, ...]] = ("address", "mount", "key_name", "token_file")

# ── OpenBao (HashiCorp Vault API), paths below the server address ─────────────

OPENBAO_TOKEN_HEADER: Final[str] = "X-Vault-Token"
OPENBAO_KEY: Final[str] = "/v1/{mount}/keys/{name}"
OPENBAO_SIGN: Final[str] = "/v1/{mount}/sign/{name}/{hash}"
OPENBAO_RENEW_SELF: Final[str] = "/v1/auth/token/renew-self"
# Transit key types an identity certificate can have, and their hash names for /sign.
OPENBAO_KEY_TYPES: Final[tuple[str, ...]] = (
    "rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521")
OPENBAO_HASHES: Final[dict[str, str]] = {"256": "sha2-256", "384": "sha2-384", "512": "sha2-512"}

# ── Configuration files ───────────────────────────────────────────────────────

DEFAULT_CONFIG_DIR: Final[Path] = Path(__file__).resolve().parent.parent / "config"
BASE_CONFIG_FILE: Final[str] = "base.toml"
ENV_CONFIG_FILE: Final[str] = "{env}.toml"
SITE_CONFIG_FILE: Final[str] = "site.toml"

# ── Published files ───────────────────────────────────────────────────────────
# Relative to the static directory, and served at the same path under https://<domain>/.

DEFAULT_STATIC_DIR: Final[str] = "static"
DEFAULT_STAGING_DIR: Final[str] = "static/.staging"
WELL_KNOWN: Final[str] = ".well-known"
DID_DOCUMENT: Final[str] = "did.json"
DID_FILE: Final[str] = f"{WELL_KNOWN}/{DID_DOCUMENT}"
CERT_FILE: Final[str] = "cert.pem"
VP_STAGING_FILE: Final[str] = "vp.jwt"

# Keys of [files] in the config, in publish order: the Compliance VC goes last
# because it pins digests of the other three.
CREDENTIAL_ORDER: Final[tuple[str, ...]] = ("lrn", "legal_person", "tandc", "compliance")
# The credentials the Compliance VC lists in gx:compliantCredentials, each with its digest.
ATTESTED_CREDENTIALS: Final[tuple[str, ...]] = ("lrn", "legal_person", "tandc")

# ── Identity ──────────────────────────────────────────────────────────────────

DID_WEB_PREFIX: Final[str] = "did:web:"
DEFAULT_KEY_ID: Final[str] = "key-1"
ALG_AUTO: Final[str] = "auto"  # config value: derive the JWS alg from the key type

# CA/Browser Forum Extended Validation certificate-policy identifier (an OID, not a
# version — OIDs are permanent). Copied from GAIA-X's own registry source, which
# rejects any leaf certificate without it whenever the registry's `evsslonly` flag
# is true — the case on every production GXDCH.
#
# This is about the certificate PRODUCT, not the issuer: an eIDAS QTSP can issue an
# EV SSL certificate (which passes), while a Qualified Certificate for Electronic
# Seal from the same QTSP is a document-signing certificate that never carries this
# OID and is rejected. See gaia-x-onboarding.md Step 1.
#
# If GAIA-X changes the rule, update this one line; the live registry check in the
# docs remains the authoritative gate.
#   https://gitlab.com/gaia-x/lab/compliance/gx-registry/-/blob/development/src/trust-anchor/services/trust-anchor.service.ts
OID_EV_SSL: Final[str] = "2.23.140.1.1"

# ── GXDCH APIs (paths below each service's base URL; verified 2026-10-27) ─────

REGISTRATION_TYPES: Final[tuple[str, ...]] = ("lei-code", "vat-id", "eori", "tax-id", "country-company-number")
NOTARY_REGISTRATION_NUMBER: Final[str] = "/registration-numbers/{type}/{value}"
REGISTRY_CHAIN_CHECK: Final[str] = "/api/trustAnchor/chain/file"
REGISTRY_CREDENTIALS_CONFIG: Final[str] = "/configurations/credentials"
REGISTRY_SHAPES: Final[str] = "/shapes/{version}"
COMPLIANCE_SUBMIT: Final[str] = "/api/credential-offers/standard-compliance"
CES_EVENTS: Final[str] = "/v2/credentials-events"
CES_EVENT_TYPE: Final[str] = "eu.gaia-x.credential"

# ── Media types ───────────────────────────────────────────────────────────────

VC_JWT: Final[str] = "application/vc+jwt"
VP_JWT: Final[str] = "application/vp+jwt"
CLOUDEVENTS_JSON: Final[str] = "application/cloudevents+json"

# ── JSON-LD contexts ──────────────────────────────────────────────────────────

CREDENTIALS_V2_CONTEXT: Final[str] = "https://www.w3.org/ns/credentials/v2"
DID_V1_CONTEXT: Final[str] = "https://www.w3.org/ns/did/v1"
JWS_2020_CONTEXT: Final[str] = "https://w3id.org/security/suites/jws-2020/v1"

# ── Certificate authorities ───────────────────────────────────────────────────

LETS_ENCRYPT_ROOT_X1_URL: Final[str] = "https://letsencrypt.org/certs/isrgrootx1.pem"
