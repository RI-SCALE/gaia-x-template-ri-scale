from pathlib import Path

import pytest

from gx.config import load_config
from gx.errors import ConfigError

from .conftest import DOMAIN, Deployment


def test_layering_and_derived_values(deployment: Deployment) -> None:
    cfg = deployment.config()
    assert cfg.env == "dev"
    assert cfg.did == f"did:web:{DOMAIN}"
    assert cfg.vm_id == f"did:web:{DOMAIN}#key-1"
    assert cfg.url("lrn") == f"https://{DOMAIN}/gaia-x/lrn.jwt"
    assert cfg.did_url == f"https://{DOMAIN}/.well-known/did.json"
    assert cfg.static_dir == deployment.root / "static"
    assert cfg.path("compliance") == deployment.root / "static" / "gaia-x" / "compliance-vc.jwt"
    assert cfg.legal["registration_type"] == "vat-id"            # from site.toml
    assert cfg.renewal["vc_renew_days"] == 21                    # from base.toml
    assert cfg.gxdch["compliance"].endswith("/development")       # from dev.toml


def test_environment_variables_win(deployment: Deployment, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GX_DOMAIN", "https://other.test/")
    monkeypatch.setenv("GX_STATIC_DIR", "public")
    cfg = deployment.config()
    assert cfg.domain == "other.test"
    assert cfg.static_dir == tmp_path / "public"


def test_domain_placeholder_in_paths(make_deployment, tmp_path: Path) -> None:
    deployment = make_deployment(extra_toml='[paths]\nstatic_dir = "sites/{domain}"\n')
    assert deployment.config().static_dir == tmp_path / "sites" / DOMAIN


def test_unknown_environment(deployment: Deployment) -> None:
    with pytest.raises(ConfigError, match="unknown environment"):
        load_config("staging", deployment.config_dir)


def test_missing_legal_data_lists_every_problem(deployment: Deployment) -> None:
    deployment.write_config(legal="[legal]\nregistration_type = \"euid\"\n")
    with pytest.raises(ConfigError) as error:
        deployment.config()
    message = str(error.value)
    for expected in ("legal.name is not set", "legal.registration_number is not set",
                     "registration_type must be one of", "legal.legal_address needs"):
        assert expected in message


@pytest.mark.parametrize("override, expected", [
    ('[gxdch]\ncompliance = "https://compliance.lab.gaia-x.eu/v2"\n', "dev must use lab"),
    ('[gxdch]\nnotary = "https://notary.example.eu/development"\n', "dev must use lab"),
    ('[ces]\nenabled = true\n', "ces.enabled must be false in dev"),
])
def test_dev_guard_rails(make_deployment, override: str, expected: str) -> None:
    deployment = make_deployment(extra_toml=override)
    with pytest.raises(ConfigError, match=expected):
        deployment.config()


PROD_ENDPOINTS = '''
[gxdch]
notary = "https://notary.operator.eu/v2"
registry = "https://registry.operator.eu/v2"
compliance = "https://compliance.operator.eu/v2"
'''


def test_prod_refuses_a_key_file(make_deployment) -> None:
    deployment = make_deployment(extra_toml=PROD_ENDPOINTS, signer_toml='backend = "pem"')
    with pytest.raises(ConfigError, match="refused in prod"):
        deployment.config("prod")


def test_prod_refuses_lab_endpoints(make_deployment) -> None:
    lab = PROD_ENDPOINTS.replace("operator.eu/v2", "lab.gaia-x.eu/development")
    with pytest.raises(ConfigError, match="prod must not use lab test paths"):
        make_deployment(extra_toml=lab).config("prod")


def test_prod_accepts_vault(make_deployment) -> None:
    deployment = make_deployment(extra_toml=PROD_ENDPOINTS)
    # site.toml's [signer] key_file is ignored by the vault backend set in prod.toml
    cfg = deployment.config("prod")
    assert cfg.require_ev and cfg.ces_enabled and cfg.signer["backend"] == "vault"
