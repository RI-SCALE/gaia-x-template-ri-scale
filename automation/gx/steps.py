"""The onboarding/renewal steps, in pipeline order (see STEPS at the bottom).

cert -> did -> preflight -> issue -> submit -> publish -> ces

Nothing reaches static/gaia-x/ before the Compliance Service answers 201: issue and
submit write to the staging directory, publish swaps all four files in at once.
That matters because the Compliance VC pins digests of the other three — publishing
new ones next to an old Compliance VC would break the one that is live.
"""

import hashlib
import json
import os
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import serialization

from gx import credentials, jws
from gx.chain import (
    EV_PROBLEM,
    check_chain,
    complete_chain,
    covers_domain,
    days_left,
    did_document,
    has_ev_oid,
    load_chain,
    to_pem,
)
from gx.config import Config
from gx.constants import ALG_AUTO, ATTESTED_CREDENTIALS, CREDENTIAL_ORDER, DID_WEB_PREFIX, VP_STAGING_FILE
from gx.errors import SignerError, StepError
from gx.jws import PublicKey
from gx.pipeline import Context, Decision, Step

# ── Small helpers ─────────────────────────────────────────────────────────────

def read_text(path: Path) -> str | None:
    return path.read_text(encoding="utf-8") if path.is_file() else None


def write_atomic(path: Path, text: str) -> None:
    """Write via a temp file + rename, so nginx never serves a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8", newline="")   # byte-exact: no CRLF translation on Windows
    tmp.chmod(0o644)
    os.replace(tmp, path)


def valid_until(token: str) -> datetime | None:
    """validUntil of a VC-JWT payload (all Loire credentials carry it), or None."""
    try:
        value = jws.decode(token)[1].get("validUntil")
        return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
    except (ValueError, AttributeError):
        return None


def days_until(moment: datetime) -> int:
    return (moment - datetime.now(timezone.utc)).days


def _spki(public_key: PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def published_key(cfg: Config) -> PublicKey | None:
    """Public key from the local did.json (no private key needed), or None."""
    text = read_text(cfg.did_path)
    if text is None:
        return None
    try:
        jwk = json.loads(text)["verificationMethod"][0]["publicKeyJwk"]
        return jws.jwk_to_public_key(jwk)
    except (ValueError, KeyError, IndexError):
        return None


def renewal_reasons(cfg: Config) -> tuple[list[str], str]:
    """Why the published credentials must be re-issued (empty list = they are fine), plus a status line."""
    token = read_text(cfg.path("compliance"))
    if token is None:
        return ["no Compliance VC published yet"], ""
    reasons, info = [], ""
    until = valid_until(token)
    if until is None:
        reasons.append("the published Compliance VC has no readable validUntil")
    else:
        left = days_until(until)
        info = f"Compliance VC valid for {left} more days (until {until.date()})"
        if left < int(cfg.renewal.get("vc_renew_days", 21)):
            reasons.append(f"Compliance VC expires in {left} days")
    key = published_key(cfg)
    for name in ("legal_person", "tandc"):
        vc = read_text(cfg.path(name))
        if vc is None:
            reasons.append(f"{cfg.files[name]} is missing")
        elif key is None or not jws.verify(vc, key):
            reasons.append(f"{cfg.files[name]} is not signed by the key in did.json (key or certificate changed)")
    return reasons, info


# ── Steps ─────────────────────────────────────────────────────────────────────

class CertStep(Step):
    name = "cert"
    title = "identity certificate chain -> static/cert.pem"

    def plan(self, ctx: Context) -> Decision:
        cfg = ctx.cfg
        source = read_text(cfg.chain_file)
        if source is None:
            raise StepError(
                f"no certificate chain at {cfg.chain_file}. Dev: is Caddy running for {cfg.domain} and has it "
                "obtained its certificate? Prod: place the CA's chain file there."
            )
        try:
            chain = complete_chain(load_chain(source), ctx.http.fetch, cfg.extra_roots)
        except ValueError as e:
            raise StepError(f"{cfg.chain_file}: {e}") from None
        leaf = chain[0]
        problems = check_chain(chain)
        if cfg.require_ev and not has_ev_oid(leaf):
            problems.append(EV_PROBLEM)
        if not covers_domain(leaf, cfg.domain):
            problems.append(f"the certificate is not issued for {cfg.domain}")
        left, minimum = days_left(leaf), int(cfg.renewal.get("cert_min_days", 14))
        if left < minimum:
            problems.append(f"the certificate expires in {left} days (minimum {minimum}); renew it first")
        if problems:
            raise StepError("the identity certificate is not usable:\n   - " + "\n   - ".join(problems))

        ctx.scratch["chain_pem"] = to_pem(chain)
        ev = "EV" if has_ev_oid(leaf) else "non-EV"
        info = f"{ev}, {len(chain)} certificates, expires in {left} days"
        current = read_text(cfg.cert_path)
        if current == ctx.scratch["chain_pem"]:
            return Decision(False, f"cert.pem is current ({info})")
        why = "cert.pem does not exist yet" if current is None else "the source certificate changed (renewed)"
        return Decision(True, f"{why} ({info})")

    def run(self, ctx: Context) -> str:
        write_atomic(ctx.cfg.cert_path, ctx.scratch["chain_pem"])
        return f"wrote {ctx.cfg.cert_path}"


class DidStep(Step):
    name = "did"
    title = "did.json from cert.pem"

    def plan(self, ctx: Context) -> Decision:
        cfg = ctx.cfg
        pem = read_text(cfg.cert_path)
        if pem is None:
            raise StepError(f"{cfg.cert_path} does not exist; run the cert step first")
        leaf = load_chain(pem)[0]
        alg = jws.default_alg(leaf.public_key()) if cfg.alg == ALG_AUTO else cfg.alg
        doc = did_document(cfg.domain, leaf, cfg.key_id, cfg.cert_url, alg)
        ctx.scratch["did_json"] = json.dumps(doc, indent=2) + "\n"
        current = read_text(cfg.did_path)
        try:
            same = current is not None and json.loads(current) == doc
        except ValueError:
            same = False
        if same:
            return Decision(False, f"did.json matches cert.pem ({cfg.vm_id}, {alg})")
        return Decision(True, "did.json does not exist yet" if current is None else "did.json does not match cert.pem")

    def run(self, ctx: Context) -> str:
        write_atomic(ctx.cfg.did_path, ctx.scratch["did_json"])
        return f"wrote {ctx.cfg.did_path}"


class PreflightStep(Step):
    name = "preflight"
    title = "live checks: published files, Registry trust anchor, T&C hash"

    def plan(self, ctx: Context) -> Decision:
        return Decision(True, "read-only checks, run every time before anything is requested")

    def run(self, ctx: Context) -> str:
        cfg, http = ctx.cfg, ctx.http
        problems, notes = [], []
        pem = read_text(cfg.cert_path)
        if pem is None:
            raise StepError(f"{cfg.cert_path} does not exist; run the cert and did steps first")

        # The Compliance Service fetches these two over HTTPS while it validates.
        try:
            if http.fetch_text(cfg.cert_url) != pem:
                problems.append(f"{cfg.cert_url} does not serve the current static/cert.pem")
            if json.loads(http.fetch_text(cfg.did_url)) != json.loads(read_text(cfg.did_path) or "null"):
                problems.append(f"{cfg.did_url} does not serve the current static/.well-known/did.json")
        except (StepError, ValueError) as e:
            problems.append(f"the site is not reachable as expected ({e}); is nginx (and Caddy) running?")

        ok, detail = http.chain_accepted(cfg.cert_url)
        if not ok:
            problems.append(f"the Registry does not accept the chain at {cfg.cert_url}: {detail}")

        leaf = load_chain(pem)[0]
        ev_only = http.ev_only()
        if ev_only and not has_ev_oid(leaf):
            problems.append("this Registry requires an EV SSL certificate (evsslonly=true) and ours is not EV")
        elif ev_only is None:
            notes.append("could not read the Registry's evsslonly flag")

        accepted, ours = http.accepted_tandc_hashes(), cfg.credentials["tandc_hash"]
        if not accepted:
            notes.append("could not read the accepted T&C hashes from the Registry shapes")
        elif ours not in accepted:
            # Accepting new terms is a legal decision: never switch the hash automatically.
            problems.append(
                f"the configured T&C hash {ours} is no longer accepted. Accepted now: {', '.join(sorted(accepted))}. "
                "Someone must review and accept the new Gaia-X terms, then update credentials.tandc_hash."
            )

        if problems:
            raise StepError("\n   - ".join(["pre-flight checks failed:", *problems]))
        return "live files current, chain accepted, T&C hash accepted" + "".join(f"; note: {n}" for n in notes)


class IssueStep(Step):
    name = "issue"
    title = "LRN from the Notary; sign Legal Person, T&C and the VP"

    def plan(self, ctx: Context) -> Decision:
        reasons, info = renewal_reasons(ctx.cfg)
        if ctx.force:
            return Decision(True, "forced with --force" + (f" ({info})" if info else ""))
        return Decision(bool(reasons), "; ".join(reasons) or info)

    def run(self, ctx: Context) -> str:
        cfg = ctx.cfg
        pem = read_text(cfg.cert_path)
        if pem is None:
            raise StepError(f"{cfg.cert_path} does not exist; run the cert and did steps first")
        try:
            signer = ctx.signer
            if _spki(signer.public_key()) != _spki(load_chain(pem)[0].public_key()):
                raise StepError("the signing key does not match static/cert.pem; refusing to sign")
        except SignerError as e:
            raise StepError(str(e)) from None

        now = datetime.now(timezone.utc)
        until = now + timedelta(days=int(cfg.renewal.get("vc_validity_days", 90)))

        lrn = ctx.http.registration_number_vc(cfg.url("lrn"), credentials.registration_number_subject(cfg))
        if jws.decode(lrn)[1].get("id") != cfg.url("lrn"):
            raise StepError(f"the Notary returned an LRN VC with an unexpected id (expected {cfg.url('lrn')})")

        vc_header = credentials.header(cfg, signer.alg, "vc")
        lp = jws.encode(vc_header, credentials.legal_person(cfg, now, until), signer.sign)
        tc = jws.encode(vc_header, credentials.terms_and_conditions(cfg, now, until), signer.sign)
        vp_payload = credentials.presentation(cfg, [lrn, lp, tc], now, until)
        vp = jws.encode(credentials.header(cfg, signer.alg, "vp"), vp_payload, signer.sign)
        if not all(jws.verify(t, signer.public_key()) for t in (lp, tc, vp)):
            raise StepError("self-check failed: a freshly signed credential does not verify")

        ctx.staged.update(lrn=lrn, legal_person=lp, tandc=tc, vp=vp)
        for name, token in ctx.staged.items():
            write_atomic(cfg.staging_dir / Path(cfg.files.get(name, VP_STAGING_FILE)).name, token)
        return f"LRN obtained; Legal Person, T&C and VP signed with {signer.alg}; staged in {cfg.staging_dir}"


class SubmitStep(Step):
    name = "submit"
    title = "POST the VP to the Compliance Service"

    def plan(self, ctx: Context) -> Decision:
        if "vp" not in ctx.staged:
            return Decision(False, "nothing was issued in this run")
        return Decision(True, f"submit to {ctx.cfg.gxdch['compliance']}")

    def run(self, ctx: Context) -> str:
        cfg = ctx.cfg
        token = ctx.http.submit(ctx.staged["vp"], cfg.url("compliance"))
        write_atomic(cfg.staging_dir / Path(cfg.files["compliance"]).name, token)
        summary = check_compliance_vc(ctx, token)
        ctx.staged["compliance"] = token
        return summary


def digest_sri(token: str) -> str:
    """The digest the Compliance VC lists for a credential: sha256 over the JCS (RFC 8785)
    canonical form of the decoded payload (gx-compliance compliant-credential-subject-mapper.ts).
    Sorted compact JSON equals JCS here: our payloads hold no floats and only BMP keys."""
    payload = jws.decode(token)[1]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256-" + hashlib.sha256(canonical.encode()).hexdigest()


def check_compliance_vc(ctx: Context, token: str) -> str:
    """Checks the Compliance VC before anything is published. Any failure stops the run."""
    cfg = ctx.cfg
    try:
        header, payload = jws.decode(token)
    except ValueError as e:
        raise StepError(f"the Compliance response is not a JWT: {e}") from None

    problems, notes = [], []
    if payload.get("id") != cfg.url("compliance"):
        problems.append(f"its id is {payload.get('id')!r}, expected {cfg.url('compliance')}")
    issuer = header.get("iss") or payload.get("issuer", "")
    compliance_host = cfg.gxdch["compliance"].split("/")[2]
    if not issuer.startswith(f"{DID_WEB_PREFIX}{compliance_host}"):
        problems.append(f"it was issued by {issuer!r}, not by {compliance_host}")
    else:
        doc = ctx.http.resolve_did_web(issuer)
        method = next((m for m in doc.get("verificationMethod", []) if m.get("id") == header.get("kid")), None)
        if method is None:
            notes.append("could not resolve the issuer's key to verify the signature")
        elif not jws.verify(token, jws.jwk_to_public_key(method["publicKeyJwk"])):
            problems.append("its signature does not verify against the issuer's did.json")
    until = valid_until(token)
    if until is None:
        problems.append("it has no readable validUntil")

    # It must attest exactly the credentials we are about to publish.
    listed = {c.get("id"): c for c in payload.get("credentialSubject", {}).get("gx:compliantCredentials", [])}
    for name in ATTESTED_CREDENTIALS:
        url, entry = cfg.url(name), listed.get(cfg.url(name))
        if entry is None:
            problems.append(f"it does not list {url} in gx:compliantCredentials")
        elif entry.get("digestSRI") != digest_sri(ctx.staged[name]):
            problems.append(f"its digest for {url} does not match the credential we would publish")
    if problems:
        raise StepError("the Compliance VC is not acceptable:\n   - " + "\n   - ".join(problems))
    return (f"Compliance VC issued by {issuer}, valid until {until.date()}, "
            f"attests {len(ATTESTED_CREDENTIALS)} credentials with matching digests"
            + "".join(f"; note: {n}" for n in notes))


class PublishStep(Step):
    name = "publish"
    title = "swap the four credentials into static/gaia-x/"

    def plan(self, ctx: Context) -> Decision:
        if "compliance" not in ctx.staged:
            return Decision(False, "no new Compliance VC in this run")
        return Decision(True, "publish the new credential set")

    def run(self, ctx: Context) -> str:
        cfg = ctx.cfg
        for name in CREDENTIAL_ORDER:   # Compliance VC last: it refers to the other three
            write_atomic(cfg.path(name), ctx.staged[name])
        try:
            live = ctx.http.fetch_text(cfg.url("compliance")).strip() == ctx.staged["compliance"]
        except StepError:
            live = False
        return "published " + ", ".join(cfg.files[n] for n in CREDENTIAL_ORDER) + (
            "" if live else f"; WARNING: {cfg.url('compliance')} does not serve the new file yet")


class CesStep(Step):
    name = "ces"
    title = "announce the Compliance VC on the Credential Event Service"

    def plan(self, ctx: Context) -> Decision:
        if not ctx.cfg.ces_enabled:
            return Decision(False, f"CES is disabled for {ctx.cfg.env}")
        if "compliance" not in ctx.staged and not ctx.force:
            return Decision(False, "no new Compliance VC in this run")
        return Decision(True, f"push to {ctx.cfg.gxdch.get('ces')}")

    def run(self, ctx: Context) -> str:
        cfg = ctx.cfg
        if not cfg.gxdch.get("ces"):
            raise StepError("ces.enabled is true but gxdch.ces is not set (ask the GXDCH operator for its CES URL)")
        token = ctx.staged.get("compliance") or read_text(cfg.path("compliance"))
        if token is None:
            raise StepError("there is no Compliance VC to announce")
        event_id = str(uuid.uuid4())
        ctx.http.push_event(credentials.cloud_event(cfg, token.strip(), event_id, datetime.now(timezone.utc)))
        return f"CES event {event_id} accepted"


STEPS: Final[tuple[Step, ...]] = (
    CertStep(), DidStep(), PreflightStep(), IssueStep(), SubmitStep(), PublishStep(), CesStep(),
)
STATUS_STEPS: Final[tuple[Step, ...]] = tuple(s for s in STEPS if s.name in ("cert", "did", "issue"))


# ── Wizard fallback ───────────────────────────────────────────────────────────

def import_wizard_zip(cfg: Config, zip_path: Path) -> list[str]:
    """Place the credentials from a Wizard `credentials.zip` by their own id URL.

    Only credentials whose id is one of our URLs are taken, so a Path A zip (dummy
    vc-jwt.io identity, ids on the Wizard's server) imports nothing.
    """
    by_url = {cfg.url(name): name for name in CREDENTIAL_ORDER}
    found, lines = {}, []
    with zipfile.ZipFile(zip_path) as archive:
        for entry in archive.namelist():
            if not entry.endswith(".jwt"):
                continue
            token = archive.read(entry).decode("utf-8", errors="replace").strip()
            try:
                header, payload = jws.decode(token)
            except ValueError:
                lines.append(f"skipped {entry}: not a JWT")
                continue
            name = by_url.get(payload.get("id"))
            if name is None:
                lines.append(f"skipped {entry}: id {payload.get('id')!r} is not one of our URLs")
            elif name in ("legal_person", "tandc") and header.get("iss") != cfg.did:
                lines.append(f"skipped {entry}: issued by {header.get('iss')!r}, not {cfg.did}")
            else:
                found[name] = token
    if not found:
        raise StepError(f"no credential in {zip_path} belongs to {cfg.domain}. A Path A (dummy key) zip "
                        "cannot be hosted; use it only as a format reference.")
    for name in CREDENTIAL_ORDER:
        if name in found:
            write_atomic(cfg.path(name), found[name])
            lines.append(f"imported {cfg.files[name]}")
    return lines
