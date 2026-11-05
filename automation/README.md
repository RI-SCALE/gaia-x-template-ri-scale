# gx: Gaia-X identity automation

`gx` creates and renews everything `gaia-x-hosting` publishes:
- the certificate chain (`cert.pem`) and `did.json`
- the Legal Registration Number, Legal Person and T&C credentials
- the Compliance VC

It runs on the hosting machine as a service of this repository's compose project.

**Status (2026-11-05):** dev (Gaia-X lab "Playground"). Both setups below are implemented. Setup A has been tested against a real OpenBao; everything Gaia-X-facing has been validated against the live lab. The first full run on a real host is still to do. Production uses the same code and setup A. It still needs an EV certificate and a production operator.

For background on the manual workflow the tool replaces, see [`../gaia-x-dev-test.md`](../gaia-x-dev-test.md).

---

## Choose your setup

The identity certificate's private key signs every credential, so where that key lives is the main choice. It is made in **`.env`**.

**[OpenBao](https://openbao.org/)** is an open-source secrets vault (a Linux Foundation fork of HashiCorp Vault). In setup A it runs as one more container next to nginx: it keeps the private key encrypted and signs on `gx`'s behalf, so the key never leaves it.

| | **Setup A: own certificate + OpenBao** (default) | **Setup B: Let's Encrypt** (fallback) |
|---|---|---|
| For | An organisation with its own certificate, e.g. from HARICA. Also the production setup. | An organisation with no certificate at all. Dev only. |
| Identity certificate | Yours, handed over as a `.p12` file | Caddy's Let's Encrypt certificate |
| Private key | Imported once into **OpenBao**, never exportable. `gx` can only ask OpenBao to sign; no key file exists on the host. | A file in Caddy's storage, read by `gx` |
| Runs | nginx, OpenBao, Caddy (optional) | nginx, Caddy |
| `.env` | `COMPOSE_PROFILES=caddy,vault` | `COMPOSE_PROFILES=caddy`<br>`COMPOSE_FILE=docker-compose.yml:compose.letsencrypt.yml` |

**HTTPS** is a separate matter: Caddy serves it with an automatic Let's Encrypt certificate in both setups. If the host already terminates HTTPS with its own proxy, drop `caddy` from `COMPOSE_PROFILES` and point that proxy at `127.0.0.1:8080`. That works in setup A only; setup B needs Caddy's certificate.

`.env.example` contains all three variants; keep exactly one active. `compose.letsencrypt.yml` gives `gx` access to Caddy's storage and sets `GX_IDENTITY=letsencrypt`. Without it, `gx` never sees a private key.

---

## Getting started (dev)

### What you need

- **A Linux host with Docker and Docker Compose**, and a clone of this repository on it.
- **A public DNS name for that host.** Gaia-X fetches `did.json` and `cert.pem` from it over HTTPS. With Caddy, ports 80 and 443 must be open for Let's Encrypt. The DID and every credential URL derive from this name, so pick one you intend to keep.
- **The organisation's legal data:**
  - legal name
  - one registration number: VAT ID, LEI, EORI, tax ID or national company number
  - the country of the legal address and of the headquarters
- **Setup A only:** the certificate as a `.p12` (or `.pfx`) file and its password. The certificate must be issued for the DNS name above, with an RSA (2048/3072/4096) or EC (P-256/384/521) key.

### 1. Domain and setup

```bash
cp .env.example .env
```

Set `GX_DOMAIN`, and keep the setup block you chose (see above).

### 2. Legal data

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

The registration number is checked against the real register (e.g. VIES), even in dev. No other fields are allowed in an address. `site.toml` and `.env` are git-ignored.

### 3. Start the services

```bash
docker compose up -d
docker compose logs caddy | grep -i "certificate obtained"    # with Caddy: wait for this line
```

### 4. Setup A only: put the identity key into OpenBao

**Once, on a new host: initialise OpenBao.**

```bash
automation/openbao/admin.sh init
```

It shows two values **once**: the *unseal key* and the *admin token*.
- Store both in your password manager, not on the host, then press Enter.
- `admin.sh init` then unlocks OpenBao and enables signing.
- It also writes `gx`'s sign-only token to `secrets/openbao-token` (root-only, git-ignored).

**Import the certificate and its key.** Copy the `.p12` into RAM, not onto the disk, then import it:

```bash
scp egi.p12 admin@host:/dev/shm/          # from your machine
automation/openbao/admin.sh import /dev/shm/egi.p12
```

The command asks for the admin token and the `.p12` password, and then:
1. checks that the key matches the certificate, that the certificate is for `GX_DOMAIN`, and that it hasn't expired;
2. imports the key into OpenBao, where nobody can export it, not even the admin;
3. writes only the public chain to `certs/identity-chain.pem`;
4. deletes the `.p12` from the host.

Keep the original `.p12` only in your organisation's secure storage. It's the backup.

All of this runs in the separate `openbao-admin` container. It has no internet access and handles the key only in RAM. The `gx` container never sees the key.

### 5. Build the tool and check the setup

```bash
docker compose build gx
docker compose run --rm gx status
```

`status` changes nothing. Its first line checks the signing key, for example `key ok  OpenBao key 'gx-identity' v1 (RS256) matches the certificate`. On a fresh setup the other lines report `ACTION`. `PROBLEM` means something is missing, and the message says what to do.

### 6. First run

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

### 7. Keep it current

```bash
docker compose run --rm gx run
```

Run this daily (cron or a systemd timer). It does nothing until something is due:
- the Compliance VC has fewer than 21 days left, or
- the certificate or key changed.

```
0 4 * * *  cd /path/to/gaia-x-hosting && docker compose run --rm gx run >> /var/log/gx.log 2>&1
```

### When something fails

- The run stops at the failing step and prints the reason; for Gaia-X refusals, that's the service's own error message.
- Published files are never half-replaced: nothing reaches `static/gaia-x/` until the Compliance Service accepts the submission.
- The signed drafts stay in `static/.staging/` for inspection.
- Fix the cause and run again; finished steps are skipped automatically.
- **Setup A, "OpenBao is sealed":** the host or OpenBao restarted. Run `automation/openbao/admin.sh unseal`. The run stops before contacting Gaia-X.

**Wizard fallback:** if you obtained the credentials with the Gaia-X Wizard instead, copy its `credentials.zip` to `static/.staging/` (the container sees only `static/`) and run `docker compose run --rm gx import-zip static/.staging/credentials.zip`. It imports only credentials issued for your domain.

---

## Setup A: OpenBao administration

All commands run on the host; `admin.sh` starts OpenBao if needed.

| Command | When | Asks for |
|---|---|---|
| `admin.sh init` | Once, on a new host | nothing; shows the unseal key and admin token once |
| `admin.sh import FILE.p12` | First import, and every certificate renewal | admin token, `.p12` password |
| `admin.sh unseal` | After every restart of the host or of OpenBao | unseal key |
| `admin.sh token` | `gx`'s token expired or must be replaced; the old one is revoked | admin token |
| `admin.sh status` | Any time | nothing |

**Certificate renewal.** Import the new `.p12` the same way.
- If the key changed, it becomes a new version of the same OpenBao key, and `gx` uses the latest version.
- Then run `gx run`: it notices the new certificate (and key) and re-issues the credentials.

**gx's token** is valid for 90 days and extended on every `gx` run, so it only expires if `gx` doesn't run for 90 days. `admin.sh status` shows how many days are left.

**Backup.** OpenBao keeps its data, encrypted, in the `openbao_data` volume; the unseal key opens it. If the volume is lost, start again with `admin.sh init` and re-import the original `.p12`.

---

## Commands

```
gx [--env dev|prod] [--config-dir DIR] COMMAND
```

| Command | Purpose |
|---|---|
| `status` | Is the key usable, what is current, what would a run do. Read-only. |
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
| `cert` | Reads the identity chain (setup A: `certs/`, setup B: Caddy's storage), puts it in order, adds the self-signed root, and checks the chain, domain and expiry. Writes `static/cert.pem`. | the certificate changed |
| `did` | Writes `static/.well-known/did.json` from `cert.pem` | `cert.pem` changed |
| `preflight` | Checks that the signing key is usable and belongs to the certificate, that the live site serves the current files, that the Registry accepts the chain, and that the T&C hash is still accepted | always (read-only) |
| `issue` | Gets the registration-number credential (LRN) from the Notary and signs the Legal Person, the T&C and the presentation (VP) into `static/.staging/` | renewal is due or the key changed |
| `submit` | Sends the VP to the Compliance Service and checks the Compliance VC that comes back | something was issued |
| `publish` | Moves all four credentials into `static/gaia-x/` at once | a new Compliance VC was accepted |
| `ces` | Announces the Compliance VC on the Credential Event Service | never in dev |

Each step decides from the files on disk whether it has work to do; there is no state database.

If the Gaia-X terms change, `preflight` stops with a message. Accepting new terms is a human decision: update `credentials.tandc_hash` in the config.

---

## Configuration

Normally you edit only `.env` (domain and setup) and `config/site.toml` (legal data). The rest is committed defaults.

| File | Holds |
|---|---|
| `config/base.toml` | Shared defaults: credential URLs, renewal windows (14 / 21 / 90 days), T&C hash, and the `[vault]` and `[letsencrypt]` settings |
| `config/dev.toml`, `config/prod.toml` | Per environment: Gaia-X endpoints, whether EV is required, CES |
| `config/site.toml` | This deployment: legal data, plus any override of the files above |
| environment variables | Last word: `GX_DOMAIN`, `GX_ENV`, `GX_IDENTITY` (set by `compose.letsencrypt.yml`), `GX_STATIC_DIR` |

**Safeguards.** The config is refused when:
- dev points at anything other than the lab `/development` or `/main` endpoints, or enables CES;
- prod uses lab endpoints, doesn't require an EV certificate, or uses setup B.

### Setup B details

`caddy/Caddyfile` sets three options. They matter only when Caddy's certificate is the identity:

| Option | Reason |
|---|---|
| `issuer acme` | Let's Encrypt only. Otherwise Caddy may fall back to ZeroSSL, which gives a different chain. |
| `key_type rsa2048` | Gives RS256 signatures |
| `reuse_private_keys` | Keeps the key across renewals. Without it, every renewal would invalidate `did.json` and all credentials. |

Caddy's docs say `reuse_private_keys` may be removed. If that happens, `gx` detects the key change and re-issues automatically.

`gx` reads Caddy's files at `caddy/certificates/acme-v02.api.letsencrypt.org-directory/<domain>/<domain>.{crt,key}` in its volume. They are root-only (`0600`), which is why the `gx` container runs as root.

**Running without Docker** (setup B with certbot): `pip install ./automation`, then set `source = "letsencrypt"` in `[identity]` and point `[letsencrypt]` at `/etc/letsencrypt/live/{domain}/` in `site.toml` (see `site.toml.example`). Renew with `certbot --reuse-key`.

---

## Production

Production is setup A with `GX_ENV=prod`; the code and the OpenBao workflow are the same as in dev. What changes:
- an **EV SSL** certificate;
- the endpoints of a production GXDCH operator, set in `site.toml`;
- CES announcements, which are on.

---

## For developers

```
docker-compose.yml             nginx, Caddy, OpenBao, gx, openbao-admin
compose.letsencrypt.yml        setup B: gx reads Caddy's storage
automation/
  Dockerfile, pyproject.toml   python:3.12-slim; dependencies: cryptography, requests
  config/                      see Configuration
  openbao/
    config.hcl                 OpenBao server configuration
    Dockerfile, admin-task.sh  the openbao-admin image and what it runs
    admin.sh                   host-side entry point for the admin
  gx/
    __main__.py      CLI
    constants.py     fixed paths, URLs, API paths, media types, env var names
    errors.py        exceptions
    config.py        config loading, identity sources, safeguards
    pipeline.py      Step and Gate protocols, Context, run_steps
    steps.py         the seven steps, key check, Wizard zip import
    signers.py       Signer protocol: TransitSigner (OpenBao), PemFileSigner (setup B)
    jws.py           compact JWS over any signer
    chain.py         chain ordering, completion and checks, did.json (also used by scripts/generate_did_json.py)
    credentials.py   credential payloads and headers
    gxdch.py         HTTP calls to the Notary, Registry, Compliance and CES
```

- **Interactive and automatic runs** differ only in the `Gate`.
- **The two setups** differ only in the config and the `Signer` backend.
- **The Gaia-X formats used** are documented with their sources in the docstrings of `credentials.py` and `gxdch.py`, and the OpenBao formats in `signers.py`.

Gaia-X behaviours the code depends on (gx-compliance source and live lab, 2026-11-02):

- **The Compliance VC** is a `gx:ParticipantComplianceCredential`. It lists each submitted credential as `{id, gx:credentialType, digestSRI}`, where `digestSRI` is `sha256-` plus the SHA-256 of the decoded payload in JCS (RFC 8785) form. `submit` refuses a Compliance VC that doesn't list our three credentials with matching digests.
- **Signatures before shapes.** The Compliance Service checks signatures and resolves DIDs before it checks credential shapes. Its shape check uses only the `credentialSubject`s, merged into one graph, with RDFS inference and then SHACL using the Registry's `/development` shapes.
- **Notary retries.** The Notary returns 502 when the external register it queries (e.g. VIES) is rate-limiting it. `gx` retries after 10, 30 and 60 seconds.
- **Trust anchors.** Let's Encrypt's current hierarchy and HARICA's TLS roots (2021) are trusted by the Registry on `/development` and `/v2` (checked 2026-11-05).

### Tests

Run them from WSL or Linux, which is where Docker is available:

```bash
cd automation
python3 -m venv ~/.venvs/gx-tests && ~/.venvs/gx-tests/bin/pip install -e ".[test]"
~/.venvs/gx-tests/bin/pytest              # offline: unit tests + full pipeline runs, both setups (~10 s)
~/.venvs/gx-tests/bin/pytest --openbao    # also against a real OpenBao 2.7.1 in Docker (~1 min)
~/.venvs/gx-tests/bin/pytest --live       # also against the Gaia-X lab and public services (~1 min)
```

`pip install -e ".[shacl]"` adds what the live shape test needs.

| File | Covers |
|---|---|
| `conftest.py` | Fixtures: a throwaway CA, a deployment in a temp directory for either setup, `FakeOpenBao` (the Transit API in memory) and `FakeGxdch`. Both fakes mirror the real formats, and `FakeGxdch` verifies what it receives the way the Compliance Service does. |
| `test_jws.py`, `test_chain.py`, `test_config.py`, `test_signers.py`, `test_credentials.py`, `test_gxdch.py`, `test_pipeline.py`, `test_steps.py` | One file per module |
| `test_end_to_end.py` | Both setups, RSA and EC, over time: first run, idle run, `--force`, renewal with the same key, key change, Compliance refusal, digest mismatch, dry run, expiring certificate. Setup A: no key file anywhere, sealed OpenBao, mismatching key. The CLI and its exit codes. |
| `test_openbao.py` (`--openbao`) | A real OpenBao with this repository's `config.hcl` and admin image. Covers `init`, `import`, the key can't be exported, signing, the full pipeline, refused imports, key renewal as a new version, token replacement, `status`, sealed after restart then `unseal`, and EC keys. |
| `test_live_lab.py` (`--live`) | Lab Notary with EGI's VAT ID; Registry reads; real Let's Encrypt chains checked by the Registry; a full Compliance run signed by the vc-jwt.io test identity (the Wizard's test mode) |
| `test_live_shapes.py` (`--live`, needs `pyshacl`) | EGI's credentials against the lab SHACL shapes, built the way the Compliance Service builds its graph; broken variants are rejected |

One check isn't automated: verifying `gx`'s JWTs with the Compliance Service's own library (jose 4.15.9, Node). It was run once by hand on 2026-11-02, and all JWTs verified.

### Open points

| Item | State |
|---|---|
| First full run on a real host | Needs the host and EGI's `.p12` |
| Legal name | Use `EGI Foundation` (as provided) or `STICHTING EGI` (registered name in VIES)? |
| `--report FILE` | Writes inside the container; only a path under `static/` reaches the host. Needs a mounted log directory. |
| Notifications | Not built. Hook points: the exit code of `gx status` / `gx run` and the JSON from `--report`. |
| Production | EV certificate; where OpenBao runs (see Production) |
