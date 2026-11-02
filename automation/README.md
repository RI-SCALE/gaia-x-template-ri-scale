# gx: Gaia-X identity automation

`gx` creates and renews everything `gaia-x-hosting` publishes:
- the certificate chain (`cert.pem`) and `did.json`
- the Legal Registration Number, Legal Person and T&C credentials
- the Compliance VC

It runs on the hosting machine as a service of this repository's compose project.

**Status (2026-11-02):** dev (Gaia-X lab) only. Implemented and validated against the live lab, except the parts that need our own public host:
- Caddy obtaining the certificate
- Gaia-X fetching our `did.json` and `cert.pem`

The first full run on a real host is still to do. Production isn't usable yet: the Vault signer is a stub.

For background on the manual workflow the tool replaces, see [`../gaia-x-dev-test.md`](../gaia-x-dev-test.md).

---

## Getting started (dev)

### What you need

- **A Linux host with Docker and Docker Compose**, and a clone of this repository on it.
- **A public DNS name for that host, with ports 80 and 443 open.** Let's Encrypt validates the name over these ports, and Gaia-X fetches `did.json` and `cert.pem` from it. The DID and every credential URL derive from this name, so pick one you intend to keep.
- **The organisation's legal data:**
  - legal name
  - one registration number: VAT ID, LEI, EORI, tax ID or national company number
  - the country of the legal address and of the headquarters

In dev you don't need a certificate or a key of your own. Caddy obtains a Let's Encrypt certificate, and `gx` uses that certificate and its key as the identity.

### 1. Set the domain

```bash
cp .env.example .env
```

Set `GX_DOMAIN` in `.env`. Keep the other two lines:
- `GX_ENV=dev`
- `COMPOSE_PROFILES=caddy`, which starts Caddy for HTTPS

### 2. Enter the legal data

```bash
cp automation/config/site.toml.example automation/config/site.toml
```

Edit the `[legal]` section:

```toml
[legal]
name = "EGI Foundation"
registration_type = "vat-id"          # lei-code | vat-id | eori | tax-id | country-company-number
registration_number = "NL821984986B01"

[legal.headquarters_address]
"gx:countryCode" = "NL"               # required, ISO 3166-1
"vcard:street-address" = "Science Park 140"   # optional, like the next three
"vcard:postal-code" = "1098 XG"
"vcard:locality" = "Amsterdam"
"vcard:region" = "NL32"               # NUTS-2 code, not ISO 3166-2

[legal.legal_address]
# same fields
```

The registration number is checked against the real register (e.g. VIES), even in dev. No other fields are allowed in an address.

`site.toml` and `.env` are git-ignored. Nothing else needs to be configured for dev.

### 3. Start the web server and get the certificate

```bash
docker compose up -d
docker compose logs caddy | grep -i "certificate obtained"
```

`docker compose up -d` starts nginx and Caddy. Wait until the log shows the certificate was obtained; this usually takes under a minute.

### 4. Build the tool and check the setup

```bash
docker compose build gx
docker compose run --rm gx status
```

`status` changes nothing and never touches the key. On a fresh setup it reports `ACTION` for every step. `PROBLEM` means something is missing, and the message says what.

### 5. First run

Recommended: a dry run first, then step by step.

```bash
docker compose run --rm gx run --until issue
docker compose run --rm gx run -i
```

- **`--until issue`** is a dry run. It signs the credentials into `static/.staging/` and sends nothing to the Compliance Service.
- **`-i`** shows each step's decision and asks `[Y/n/q]`.

When it finishes with `Result: renewed`, the identity is live:
- `https://<domain>/.well-known/did.json`
- `https://<domain>/cert.pem`
- `https://<domain>/gaia-x/{lrn,legal-person,tandc,compliance-vc}.jwt`

### 6. Keep it current

```bash
docker compose run --rm gx run
```

Run this daily (cron or a systemd timer). It does nothing until something is due:
- the Compliance VC has fewer than 21 days left, or
- Caddy's certificate or key changed.

Example crontab line:

```
0 4 * * *  cd /path/to/gaia-x-hosting && docker compose run --rm gx run >> /var/log/gx.log 2>&1
```

### When something fails

- The run stops at the failing step and prints the reason; for Gaia-X refusals, that's the service's own error message.
- Published files are never half-replaced: nothing reaches `static/gaia-x/` until the Compliance Service accepts the submission.
- The signed drafts stay in `static/.staging/` for inspection.
- Fix the cause and run again; finished steps are skipped automatically.

**Wizard fallback:** if you obtained the credentials with the Gaia-X Wizard instead, copy its `credentials.zip` to `static/.staging/` (the container sees only `static/`) and run `docker compose run --rm gx import-zip static/.staging/credentials.zip`. It imports only credentials issued for your domain.

---

## Commands

```
gx [--env dev|prod] [--config-dir DIR] COMMAND
```

| Command | Purpose |
|---|---|
| `status` | What is current and what a run would do. Read-only, never needs the key. |
| `run` | Bring everything up to date, unattended. Safe to repeat. |
| `run -i` | The same steps, asking before each one |
| `run --until STEP` / `--from STEP` | Run only part of the pipeline; `--until issue` is the dry run |
| `run --force` | Re-issue the credentials even though they are still valid |
| `import-zip FILE` | Place credentials from a Wizard `credentials.zip` |

Exit codes:

| Code | Meaning |
|---|---|
| 0 | OK, including "nothing to do" |
| 1 | A step failed, or `status` found something to do |
| 2 | Configuration error |
| 3 | Aborted by the operator |

---

## What a run does

```
cert -> did -> preflight -> issue -> submit -> publish -> ces
```

| Step | Does | Runs when |
|---|---|---|
| `cert` | Takes Caddy's certificate, adds the self-signed root and checks the chain, domain and expiry. Writes `static/cert.pem`. | the certificate changed |
| `did` | Writes `static/.well-known/did.json` from `cert.pem` | `cert.pem` changed |
| `preflight` | Checks that the live site serves the current files, that the Registry accepts the chain, and that the T&C hash is still accepted | always (read-only) |
| `issue` | Gets the registration-number credential (LRN) from the Notary and signs the Legal Person, the T&C and the presentation (VP) into `static/.staging/` | renewal is due or the key changed; **only this step reads the key** |
| `submit` | Sends the VP to the Compliance Service and checks the Compliance VC that comes back | something was issued |
| `publish` | Moves all four credentials into `static/gaia-x/` at once | a new Compliance VC was accepted |
| `ces` | Announces the Compliance VC on the Credential Event Service | never in dev |

Each step decides from the files on disk whether it has work to do; there is no state database.

If the Gaia-X terms change, `preflight` stops with a message. Accepting new terms is a human decision: update `credentials.tandc_hash` in the config.

---

## Configuration

Normally you edit only `.env` (the domain) and `config/site.toml` (the legal data). The rest is committed defaults.

| File | Holds |
|---|---|
| `config/base.toml` | Shared defaults: credential URLs, renewal windows (14 / 21 / 90 days), T&C hash |
| `config/dev.toml`, `config/prod.toml` | Per environment: Gaia-X endpoints, certificate and key location, signer, CES |
| `config/site.toml` | This deployment: legal data, plus any override of the files above |
| environment variables | Last word: `GX_DOMAIN`, `GX_ENV`, `GX_CHAIN_FILE`, `GX_SIGNING_KEY_FILE`, `GX_SIGNING_KEY_PASSPHRASE`, `VAULT_ADDR` |

**Dev safeguards.** The config is refused when dev points at anything other than the lab `/development` or `/main` endpoints, or when CES is enabled.

**Prod safeguards.** The config is refused when prod uses lab endpoints, doesn't require an EV certificate, or reads the key from a file.

**Running without Docker.** You can run `pip install ./automation`, then `gx ...` with certbot instead of Caddy. Point `cert.chain_file` and `signer.key_file` in `site.toml` at `/etc/letsencrypt/live/{domain}/`, and renew with `certbot --reuse-key`.

### Why the Caddyfile looks the way it does

`caddy/Caddyfile` sets three options:

| Option | Reason |
|---|---|
| `issuer acme` | Let's Encrypt only. Otherwise Caddy may fall back to ZeroSSL, which gives a different chain. |
| `key_type rsa2048` | Gives RS256 signatures, like the expected production EV certificate |
| `reuse_private_keys` | Keeps the key across renewals. Without it, every renewal would invalidate `did.json` and all credentials. |

Caddy's docs say `reuse_private_keys` may be removed. If that happens, `gx` detects the key change and re-issues automatically.

`gx` reads the files from Caddy's volume at `caddy/certificates/acme-v02.api.letsencrypt.org-directory/<domain>/<domain>.{crt,key}`. They are root-only (`0600`), which is why the `gx` container runs as root.

---

## Production (not ready)

The steps and the code are the same as in dev. Only the configuration and the signer differ:
- `GX_ENV=prod`.
- Endpoints of a production GXDCH operator, set in `site.toml`.
- An EV SSL certificate chain in `certs/`.
- Signing through HashiCorp Vault (`signer.backend = "vault"`): the private key never exists as a file on the host.

Missing:
- **The Vault signer:** `VaultTransitSigner` in `gx/signers.py`; the planned API calls are in its docstring.
- **EGI's decision** on where Vault runs.
- **The certificate import**, which depends on the form the EV certificate arrives in.

---

## For developers

```
automation/
  Dockerfile, pyproject.toml   python:3.12-slim; dependencies: cryptography, requests
  config/                      see Configuration
  gx/
    __main__.py      CLI
    constants.py     fixed paths, URLs, API paths, media types, env var names
    errors.py        exceptions
    config.py        config loading and the dev/prod safeguards
    pipeline.py      Step and Gate protocols, Context, run_steps
    steps.py         the seven steps, Wizard zip import
    signers.py       Signer protocol: PemFileSigner (dev), VaultTransitSigner (stub)
    jws.py           compact JWS over any signer
    chain.py         chain completion and checks, did.json (also used by scripts/generate_did_json.py)
    credentials.py   credential payloads and headers
    gxdch.py         HTTP calls to the Notary, Registry, Compliance and CES
```

- **Interactive and automatic runs** differ only in the `Gate`.
- **Dev and prod** differ only in the config and the `Signer` backend.
- **The Gaia-X formats used** are documented with their sources in the docstrings of `credentials.py` and `gxdch.py`.

Gaia-X behaviours the code depends on (gx-compliance source and live lab, 2026-11-02):

- **The Compliance VC** is a `gx:ParticipantComplianceCredential`. It lists each submitted credential as `{id, gx:credentialType, digestSRI}`, where `digestSRI` is `sha256-` plus the SHA-256 of the decoded payload in JCS (RFC 8785) form. `submit` refuses a Compliance VC that doesn't list our three credentials with matching digests.
- **Signatures before shapes.** The Compliance Service checks signatures and resolves DIDs before it checks credential shapes. Its shape check uses only the `credentialSubject`s, merged into one graph, with RDFS inference and then SHACL using the Registry's `/development` shapes.
- **Notary retries.** The Notary returns 502 when the external register it queries (e.g. VIES) is rate-limiting it. `gx` retries after 10, 30 and 60 seconds.
- **Let's Encrypt's current hierarchy** (`YR1`/`YE2` → `Root YR`/`Root YE` → cross-signed by ISRG X1/X2) is completed through AIA links and accepted by the Registry.

### Tests

```bash
cd automation
pip install -e ".[test]"
pytest                        # offline: unit tests + full pipeline runs against a fake GXDCH (~10 s)
pytest --live                 # also against the Gaia-X lab and public services (~1 min)
pip install -e ".[shacl]"     # optional, for the live shape test
```

| File | Covers |
|---|---|
| `conftest.py` | Fixtures: a throwaway CA, a deployment in a temp directory with Caddy's files simulated, and `FakeGxdch`. `FakeGxdch` mirrors the lab's formats and verifies what it receives the way the Compliance Service does. |
| `test_jws.py`, `test_chain.py`, `test_config.py`, `test_signers.py`, `test_credentials.py`, `test_gxdch.py`, `test_pipeline.py`, `test_steps.py` | One file per module |
| `test_end_to_end.py` | RSA and EC runs over time: first run, idle run, `--force`, certificate renewal with the same key, key change, Compliance refusal, digest mismatch, dry run, expiring certificate; the CLI and its exit codes |
| `test_live_lab.py` (`--live`) | Lab Notary with EGI's VAT ID; Registry reads; real Let's Encrypt chains checked by the Registry; a full Compliance run of `gx`'s payloads signed by the vc-jwt.io test identity (the Wizard's test mode) |
| `test_live_shapes.py` (`--live`, needs `pyshacl`) | EGI's credentials against the lab SHACL shapes, built the way the Compliance Service builds its graph; broken variants are rejected |

The suite passes on Python 3.10 (Windows) and 3.12 (Linux, the container's version).

One check isn't automated: verifying `gx`'s JWTs with the Compliance Service's own library (jose 4.15.9, Node). It was run once by hand on 2026-11-02, and all JWTs verified.

### Open points

| Item | State |
|---|---|
| First full run on a real host | Needs a host with a public DNS name |
| Legal name | Use `EGI Foundation` (as provided) or `STICHTING EGI` (registered name in VIES)? |
| `--report FILE` | Writes inside the container; only a path under `static/` reaches the host. Needs a mounted log directory. |
| Notifications | Not built. Hook points: the exit code of `gx status` / `gx run` and the JSON from `--report`. |
| Production | See above |
