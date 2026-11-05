"""Layered configuration: base.toml -> <env>.toml -> site.toml -> GX_* environment variables.

base/dev/prod.toml are committed and hold no organisation data. site.toml is
git-ignored and holds this deployment's domain and legal data. Secrets never go
into any TOML file: they come from files or environment variables.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib

from gx.chain import normalize_domain
from gx.constants import (
    ALG_AUTO,
    BASE_CONFIG_FILE,
    CERT_FILE,
    DEFAULT_CONFIG_DIR,
    DEFAULT_ENV,
    DEFAULT_KEY_ID,
    DEFAULT_STAGING_DIR,
    DEFAULT_STATIC_DIR,
    DID_FILE,
    DID_WEB_PREFIX,
    ENV_CONFIG_FILE,
    ENV_OVERRIDES,
    ENV_VAR_CONFIG_DIR,
    ENV_VAR_ENV,
    ENV_VAR_HOSTING_DIR,
    ENVS,
    IDENTITY_SOURCES,
    LAB_HOST,
    LAB_PATHS,
    REGISTRATION_TYPES,
    SIGNER_PEM,
    SIGNER_TRANSIT,
    SITE_CONFIG_FILE,
    SOURCE_VAULT,
    TRANSIT_SETTINGS,
)
from gx.errors import ConfigError


@dataclass(frozen=True)
class Config:
    env: str
    domain: str
    key_id: str
    alg: str                        # ALG_AUTO or an explicit JWS alg
    source: str                     # identity source: SOURCE_VAULT or SOURCE_LETSENCRYPT
    root: Path                     # the gaia-x-hosting directory; relative paths resolve against it
    static_dir: Path
    staging_dir: Path
    files: dict[str, str]           # credential name -> path under static_dir (== URL path)
    chain_file: Path                # where the identity certificate chain comes from
    extra_roots: tuple[str, ...]    # URLs of PEM roots to complete the chain with
    require_ev: bool
    gxdch: dict[str, str]           # notary / registry / compliance / ces base URLs
    signer: dict[str, Any]          # backend + backend-specific settings
    legal: dict[str, Any]
    credentials: dict[str, Any]
    renewal: dict[str, int]
    ces_enabled: bool

    @property
    def did(self) -> str:
        return f"{DID_WEB_PREFIX}{self.domain}"

    @property
    def vm_id(self) -> str:
        return f"{self.did}#{self.key_id}"

    @property
    def cert_url(self) -> str:
        return self.public_url(CERT_FILE)

    @property
    def did_url(self) -> str:
        return self.public_url(DID_FILE)

    @property
    def cert_path(self) -> Path:
        return self.static_dir / CERT_FILE

    @property
    def did_path(self) -> Path:
        return self.static_dir / DID_FILE

    def public_url(self, path: str) -> str:
        """URL at which nginx serves `path` (relative to the static directory)."""
        return f"https://{self.domain}/{path}"

    def url(self, name: str) -> str:
        return self.public_url(self.files[name])

    def path(self, name: str) -> Path:
        return self.static_dir / self.files[name]


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        out[key] = _merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) else value
    return out


def _read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        return tomllib.load(f)


def load_config(env: str | None = None, config_dir: Path | None = None) -> Config:
    config_dir = Path(config_dir or os.environ.get(ENV_VAR_CONFIG_DIR) or DEFAULT_CONFIG_DIR)
    env = env or os.environ.get(ENV_VAR_ENV) or DEFAULT_ENV
    if env not in ENVS:
        raise ConfigError(f"unknown environment {env!r}; expected one of {', '.join(ENVS)}")
    env_file = ENV_CONFIG_FILE.format(env=env)

    data = _read_toml(config_dir / BASE_CONFIG_FILE)
    data = _merge(data, _read_toml(config_dir / env_file))
    site = config_dir / SITE_CONFIG_FILE
    if site.is_file():
        data = _merge(data, _read_toml(site))
    for var, (section, key) in ENV_OVERRIDES.items():
        if os.environ.get(var):
            data.setdefault(section, {})[key] = os.environ[var]

    root = Path(os.environ.get(ENV_VAR_HOSTING_DIR) or config_dir.parent.parent).resolve()
    domain = normalize_domain(data.get("identity", {}).get("domain", ""))

    def path(value: str) -> Path:
        p = Path(value.replace("{domain}", domain))
        return p if p.is_absolute() else root / p

    identity, paths = data.get("identity", {}), data.get("paths", {})
    source = identity.get("source", SOURCE_VAULT)
    settings = dict(data.get(source, {}))   # the [vault] or [letsencrypt] section
    if source == SOURCE_VAULT:
        signer = {"backend": SIGNER_TRANSIT, **{k: settings.get(k, "") for k in TRANSIT_SETTINGS}}
        signer["token_file"] = str(path(signer["token_file"])) if signer["token_file"] else ""
    else:
        key_file = settings.get("key_file", "")
        signer = {"backend": SIGNER_PEM, "key_file": str(path(key_file)) if key_file else ""}

    cfg = Config(
        env=env,
        domain=domain,
        key_id=identity.get("key_id", DEFAULT_KEY_ID),
        alg=identity.get("alg", ALG_AUTO),
        source=source,
        root=root,
        static_dir=path(paths.get("static_dir", DEFAULT_STATIC_DIR)),
        staging_dir=path(paths.get("staging_dir", DEFAULT_STAGING_DIR)),
        files=dict(data["files"]),
        chain_file=path(settings.get("chain_file", "")),
        extra_roots=tuple(settings.get("extra_roots", ())),
        require_ev=bool(data.get("cert", {}).get("require_ev", env == "prod")),
        gxdch={k: v.rstrip("/") for k, v in data.get("gxdch", {}).items()},
        signer=signer,
        legal=data.get("legal", {}),
        credentials=data.get("credentials", {}),
        renewal=data.get("renewal", {}),
        ces_enabled=bool(data.get("ces", {}).get("enabled", False)),
    )
    problems = validate(cfg, has_chain_file=bool(settings.get("chain_file")))
    if problems:
        where = f"{config_dir / SITE_CONFIG_FILE} (or {config_dir / env_file})"
        raise ConfigError("invalid configuration, fix it in " + where + ":\n  - " + "\n  - ".join(problems))
    return cfg


def validate(cfg: Config, has_chain_file: bool = True) -> list[str]:
    """Completeness checks plus the dev/prod guard rails. Returns all problems at once."""
    problems = []
    if not cfg.domain or cfg.domain.endswith("example.eu"):
        problems.append("identity.domain is not set")
    if cfg.source not in IDENTITY_SOURCES:
        problems.append(f"identity.source must be one of {', '.join(IDENTITY_SOURCES)}, got {cfg.source!r}")
        return problems
    if not has_chain_file:
        problems.append(f"{cfg.source}.chain_file is not set")
    if cfg.source == SOURCE_VAULT:
        problems += [f"vault.{k} is not set" for k in TRANSIT_SETTINGS if not cfg.signer.get(k)]
    elif not cfg.signer.get("key_file"):
        problems.append("letsencrypt.key_file is not set")

    legal = cfg.legal
    for key in ("name", "registration_type", "registration_number"):
        if not legal.get(key):
            problems.append(f"legal.{key} is not set")
    if legal.get("registration_type") and legal["registration_type"] not in REGISTRATION_TYPES:
        problems.append(f"legal.registration_type must be one of {', '.join(REGISTRATION_TYPES)}")
    for key in ("headquarters_address", "legal_address"):
        if not legal.get(key, {}).get("gx:countryCode"):
            problems.append(f'legal.{key} needs at least "gx:countryCode" (ISO 3166-1, e.g. "NL")')
    if not cfg.credentials.get("tandc_hash"):
        problems.append("credentials.tandc_hash is not set")

    for key in ("notary", "registry", "compliance"):
        if not cfg.gxdch.get(key):
            problems.append(f"gxdch.{key} is not set")

    endpoints = [v for k, v in cfg.gxdch.items() if v and k != "ces"]
    if cfg.env == "dev":
        # Lab paths only: /v2 is a production deployment and rejects non-EV certificates.
        bad = [u for u in endpoints if LAB_HOST not in u or not u.endswith(LAB_PATHS)]
        if bad:
            problems.append(f"dev must use lab {' or '.join(LAB_PATHS)} endpoints, got: {', '.join(bad)}")
        if cfg.ces_enabled:
            problems.append("ces.enabled must be false in dev: the lab CES is world-readable")
    else:
        bad = [u for u in endpoints if u.endswith(LAB_PATHS)]
        if bad:
            problems.append(f"prod must not use lab test paths: {', '.join(bad)}")
        if not cfg.require_ev:
            problems.append("cert.require_ev must be true in prod")
        if cfg.source != SOURCE_VAULT:
            problems.append(
                "identity.source = 'letsencrypt' is refused in prod: production needs an EV certificate "
                "whose key is kept in OpenBao (identity.source = 'vault', see automation/README.md)"
            )
    return problems
