"""The whole pipeline and the CLI against the fake GXDCH: what an operator sees over time."""

import json

import pytest

import gx.__main__ as cli
from gx import jws
from gx.constants import SOURCE_LETSENCRYPT, SOURCE_VAULT
from gx.pipeline import AutoGate, Context, InteractiveGate, RunReport, run_steps
from gx.steps import STEPS

from .conftest import Deployment, FakeGxdch, Pki


def run(fake: FakeGxdch, force: bool = False, steps=STEPS) -> RunReport:
    return run_steps(Context(fake.cfg, fake, force=force), steps, AutoGate(), out=lambda line: None)


def statuses(report: RunReport) -> dict[str, str]:
    return {o.step: o.status for o in report.outcomes}


@pytest.fixture(params=[("rsa", SOURCE_VAULT), ("ec", SOURCE_VAULT), ("rsa", SOURCE_LETSENCRYPT),
                        ("ec", SOURCE_LETSENCRYPT)], ids=lambda p: f"{p[1]}-{p[0]}")
def setup(request, make_deployment, pki: Pki) -> tuple[Deployment, FakeGxdch]:
    key, source = request.param
    deployment = make_deployment(key=key, source=source)
    return deployment, FakeGxdch(deployment.config(), pki)


@pytest.fixture
def vault_setup(make_deployment, pki: Pki) -> tuple[Deployment, FakeGxdch]:
    deployment = make_deployment(source=SOURCE_VAULT)
    return deployment, FakeGxdch(deployment.config(), pki)


def test_setup_a_has_no_key_file_anywhere(vault_setup) -> None:
    deployment, fake = vault_setup
    assert run(fake).renewed
    assert not deployment.key_file.exists()
    assert not any("PRIVATE KEY" in p.read_text(errors="ignore")
                   for p in deployment.root.rglob("*") if p.is_file())


def test_setup_a_sealed_openbao_stops_before_gaia_x(vault_setup) -> None:
    deployment, fake = vault_setup
    deployment.openbao.sealed = True
    report = run(fake)
    assert statuses(report)["preflight"] == "failed" and "OpenBao is sealed" in report.outcomes[-1].detail
    assert fake.submitted == [] and not any(deployment.published(fake.cfg).values())


def test_setup_a_wrong_key_in_openbao(vault_setup, pki: Pki) -> None:
    deployment, fake = vault_setup
    deployment.openbao.keys["gx-identity"].append(pki.keys["rsa2"])   # imported, but cert.pem not renewed
    report = run(fake)
    assert statuses(report)["preflight"] == "failed"
    assert "does not belong to the identity certificate" in report.outcomes[-1].detail


def test_first_run_publishes_everything(setup) -> None:
    deployment, fake = setup
    report = run(fake)
    assert report.ok and report.renewed, report.to_json()
    assert statuses(report)["ces"] == "skipped"
    cfg = fake.cfg
    published = deployment.published(cfg)
    assert all(published.values())
    did = json.loads(cfg.did_path.read_text())
    key = jws.jwk_to_public_key(did["verificationMethod"][0]["publicKeyJwk"])
    assert jws.verify(published["legal_person"], key) and jws.verify(published["tandc"], key)
    assert cfg.cert_path.read_text().count("BEGIN CERTIFICATE") == 3   # root appended


def test_second_run_does_nothing(setup) -> None:
    deployment, fake = setup
    run(fake)
    before = deployment.published(fake.cfg)
    report = run(fake)
    assert report.ok and not report.renewed
    assert statuses(report) == {"cert": "skipped", "did": "skipped", "preflight": "done", "issue": "skipped",
                                "submit": "skipped", "publish": "skipped", "ces": "skipped"}
    assert deployment.published(fake.cfg) == before and len(fake.submitted) == 1


def test_force_reissues(setup) -> None:
    deployment, fake = setup
    run(fake)
    before = deployment.published(fake.cfg)
    assert run(fake, force=True).renewed
    assert deployment.published(fake.cfg)["compliance"] != before["compliance"]


def test_certificate_renewal_with_the_same_key(setup) -> None:
    """Caddy renews with reuse_private_keys: new cert.pem, same did.json, credentials stay valid."""
    deployment, fake = setup
    run(fake)
    did_before = fake.cfg.did_path.read_text()
    deployment.install_certificate(days=85)
    report = run(fake)
    assert statuses(report)["cert"] == "done" and statuses(report)["did"] == "skipped"
    assert not report.renewed and fake.cfg.did_path.read_text() == did_before


def test_key_change_reissues_everything(setup, pki: Pki) -> None:
    deployment, fake = setup
    run(fake)
    deployment.install_certificate(key=pki.keys["rsa2"])
    report = run(fake)
    assert statuses(report)["did"] == "done" and report.renewed
    key = pki.keys["rsa2"].public_key()
    assert jws.verify(deployment.published(fake.cfg)["legal_person"], key)


def test_refusal_leaves_the_live_files_alone(setup) -> None:
    deployment, fake = setup
    run(fake)
    before = deployment.published(fake.cfg)
    fake.refuse = '{"message":"VC does not conform to shape"}'
    report = run(fake, force=True)
    assert statuses(report)["submit"] == "failed" and "conform to shape" in report.outcomes[-1].detail
    assert deployment.published(fake.cfg) == before
    assert (fake.cfg.staging_dir / "vp.jwt").is_file()


def test_mismatching_digests_are_not_published(setup) -> None:
    deployment, fake = setup
    fake.corrupt_digest = True
    report = run(fake)
    assert statuses(report)["submit"] == "failed" and "digest" in report.outcomes[-1].detail
    assert not any(deployment.published(fake.cfg).values())


def test_dry_run(setup) -> None:
    deployment, fake = setup
    report = run(fake, steps=STEPS[:4])   # --until issue
    assert report.ok and fake.submitted == []
    assert not any(deployment.published(fake.cfg).values())
    assert {p.name for p in fake.cfg.staging_dir.iterdir()} >= {"vp.jwt", "legal-person.jwt", "tandc.jwt", "lrn.jwt"}


def test_expiring_certificate_stops_the_run(make_deployment, pki: Pki) -> None:
    deployment = make_deployment()
    deployment.install_certificate(days=5)
    report = run(FakeGxdch(deployment.config(), pki))
    assert statuses(report) == {"cert": "failed"} and "expires in" in report.outcomes[0].detail


# ── CLI ───────────────────────────────────────────────────────────────────────

@pytest.fixture
def cli_env(deployment: Deployment, pki: Pki, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    monkeypatch.setattr(cli, "Gxdch", lambda cfg: FakeGxdch(cfg, pki))
    return ["--config-dir", str(deployment.config_dir)]


def test_cli_status_run_status(cli_env: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([*cli_env, "status"]) == cli.ExitCode.FAILED
    assert cli.main([*cli_env, "run"]) == cli.ExitCode.OK
    assert "Result: renewed" in capsys.readouterr().out
    assert cli.main([*cli_env, "status"]) == cli.ExitCode.OK
    assert "Everything is up to date." in capsys.readouterr().out


def test_cli_status_shows_the_openbao_key(make_deployment, pki: Pki, monkeypatch: pytest.MonkeyPatch,
                                          capsys: pytest.CaptureFixture[str]) -> None:
    deployment = make_deployment(source=SOURCE_VAULT)
    monkeypatch.setattr(cli, "Gxdch", lambda cfg: FakeGxdch(cfg, pki))
    cli.main(["--config-dir", str(deployment.config_dir), "status"])
    out = capsys.readouterr().out
    assert "identity=vault" in out and "OpenBao key 'gx-identity' v1 (RS256) matches the certificate" in out
    deployment.openbao.sealed = True
    assert cli.main(["--config-dir", str(deployment.config_dir), "status"]) == cli.ExitCode.FAILED
    assert "key    PROBLEM  OpenBao is sealed" in capsys.readouterr().out


def test_cli_interactive_quit(cli_env: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "InteractiveGate", lambda: InteractiveGate(ask=lambda prompt: "q"))
    assert cli.main([*cli_env, "run", "-i"]) == cli.ExitCode.ABORTED


def test_cli_report_file(cli_env: list[str], tmp_path) -> None:
    report = tmp_path / "report.json"
    assert cli.main([*cli_env, "run", "--until", "did", "--report", str(report)]) == cli.ExitCode.OK
    assert json.loads(report.read_text())["ok"] is True


def test_cli_configuration_error(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--config-dir", str(tmp_path), "status"]) == cli.ExitCode.CONFIG
    assert "configuration error" in capsys.readouterr().err
