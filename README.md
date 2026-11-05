# GAIA-X Identity Hosting

Everything an organisation must publish to become a GAIA-X participant, served from its own
domain: a `did:web` identity, the certificate chain behind it, and the credentials signed with
that certificate's key. A GAIA-X Digital Clearing House (GXDCH) reads these files and, if they
pass, issues a Compliance VC.

| Served at | Contents |
|---|---|
| `/.well-known/did.json` | `did:web` identity document |
| `/cert.pem` | X.509 **identity** certificate chain (trust anchor, referenced by `x5u`) |
| `/gaia-x/lrn.jwt` | Legal Registration Number VC (issued by the GXDCH Notary) |
| `/gaia-x/legal-person.jwt` | Legal Person VC (self-signed) |
| `/gaia-x/tandc.jwt` | Terms & Conditions VC (self-signed) |
| `/gaia-x/compliance-vc.jwt` | Compliance VC returned by the GXDCH |

The first two exist before you request any credential; the other four are added as you go.
nginx serves whatever is in `static/`, so the hosting part is the same however the files are
produced.

---

## Two ways to produce the files

You choose; both end with the same files at the same URLs.

**By hand**, following the runbooks. Each step is a command or a GAIA-X Wizard screen, and you
copy the results into `static/`. Good for understanding the process and for one-off runs.
- [`gaia-x-dev-test.md`](gaia-x-dev-test.md): free dry run against the GAIA-X lab. **Start here.**
- [`gaia-x-onboarding.md`](gaia-x-onboarding.md): production onboarding, certificate choice, renewals.
- The [Manual workflow](#manual-workflow) below is the condensed version.

**With the `gx` tool** in [`automation/`](automation/README.md). It runs on the host as a
compose service and does the whole chain: builds `cert.pem` and `did.json`, gets the LRN from
the Notary, signs the Legal Person and T&C, submits them to the Compliance Service, checks the
answer and publishes all four credentials at once. Run daily, it renews them before they expire.
- The identity key stays in **OpenBao**, an open-source secrets vault that runs as one more
  container: it signs on the tool's behalf and never hands the key out. Organisations with no
  certificate at all can use Caddy's Let's Encrypt certificate instead (lab only).
- It is built and tested against the GAIA-X lab; production uses the same tool with an EV
  certificate.
- Setup, the choice between the two key setups, and operation: [`automation/README.md`](automation/README.md).

The rest of this page covers what both ways share, and the manual steps.

---

## Before the first run

> ### This deployment *is* the production deployment
> The project (compose file, nginx config, scripts, URL layout) is identical in dev and
> production. **Only the contents change:** a different certificate, a regenerated `did.json`,
> re-signed credentials and different GXDCH endpoints. So use a permanent domain from the
> first run; the DID and every credential URL derive from it.

> ### ⚠️ Get the certificate type right
> Production GXDCH require the identity certificate to be **EV SSL** (CA/Browser Forum policy
> OID `2.23.140.1.1`). A Qualified Certificate for Electronic Seal is a document-signing
> certificate and does not carry it, but an eIDAS QTSP can issue the EV SSL one. For the lab,
> any publicly trusted certificate works, Let's Encrypt included. See
> [`gaia-x-onboarding.md`](gaia-x-onboarding.md) Step 1.

**Two certificates, two jobs.** The *web server* certificate (Caddy's or your proxy's) only
secures HTTPS. The *identity* certificate is served as `cert.pem`, named in `did.json`, and its
key signs every credential.

**Prerequisites**
- A **permanent** public domain with HTTPS on port 443 (`did:web` allows plain HTTP only on localhost)
- Docker and Docker Compose
- For the manual workflow: Python 3.10+ with `pip install cryptography`, for
  `scripts/generate_did_json.py`

> ⚠️ **Never commit the private key.** It is the root of trust for every credential you issue.
> `.gitignore` excludes key material and all per-deployment files; still check `git status`
> before your first push.

---

## Serving the files

```bash
cp .env.example .env      # set GX_DOMAIN; COMPOSE_PROFILES decides what runs
docker compose up -d
```

nginx always runs, on `127.0.0.1:8080`. The profiles in `.env` add the rest:

| `COMPOSE_PROFILES` | Adds | Use when |
|---|---|---|
| `caddy` | Caddy: HTTPS with an automatic Let's Encrypt certificate (ports 80 and 443 must be open) | the host has no HTTPS of its own |
| `vault` | OpenBao, for the `gx` tool's default setup | you use `gx` with your own certificate |
| *(empty)* | nothing | your own proxy already terminates HTTPS; point it at `127.0.0.1:8080` |

`.env.example` is set up for `gx` (`caddy,vault`). For the manual workflow, `caddy` or nothing
is enough. Files dropped into `static/` are served immediately, without a restart.

---

## Manual workflow

### 1. Build `cert.pem` (full chain, self-signed root last)

```bash
# from the CA's PKCS#12:
openssl pkcs12 -in your-cert.p12 -nokeys -chain -out static/cert.pem
cat root-ca.pem >> static/cert.pem                                   # the self-signed root

# lab only, from certbot:
cp /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem static/cert.pem
curl -s https://letsencrypt.org/certs/isrgrootx1.pem >> static/cert.pem
```

Neither `openssl -chain` nor certbot's `fullchain.pem` includes the self-signed root. Append it,
or the Registry replies `409 Root certificate is not self-signed`.

### 2. Generate `did.json` (and check the chain)

```bash
python scripts/generate_did_json.py \
    --domain YOUR_DOMAIN \
    --cert static/cert.pem \
    > static/.well-known/did.json
```

The script flags the three things that can break onboarding: a root that is not self-signed, a
gap in the chain, and a leaf without the EV SSL OID. Add `--strict` to make it exit non-zero
(useful in CI).

### 3. Verify before requesting anything

```bash
curl -I https://YOUR_DOMAIN/.well-known/did.json   # 200, application/json, ACAO: *
curl -I https://YOUR_DOMAIN/cert.pem               # 200, application/x-pem-file

# does the DID resolve?
curl "https://dev.uniresolver.io/1.0/identifiers/did:web:YOUR_DOMAIN"

# does the GXDCH accept the chain?  Expect exactly {"result":true}
curl -X POST "https://<operator-registry>/v2/api/trustAnchor/chain/file" \
     -H 'Content-Type: application/json' \
     -d '{"uri":"https://YOUR_DOMAIN/cert.pem"}'
```

Registry for the lab: `https://registry.lab.gaia-x.eu/development`. For production, pick an
operator from `curl -s https://wizard.lab.gaia-x.eu/api/clearing-houses` and use its three hosts
consistently. A `409` here means the Compliance call will fail the same way, so fix it first.

### 4. Obtain and drop in the credentials

Follow [`gaia-x-dev-test.md`](gaia-x-dev-test.md) (lab) or [`gaia-x-onboarding.md`](gaia-x-onboarding.md)
(production). Each `.example` file under `static/gaia-x/` documents the exact shape of the
credential that replaces it.

- **Scripted** (`curl`, see the runbooks): the Notary and Compliance responses are written
  straight into `static/gaia-x/` with `-o`.
- **GAIA-X Wizard**: at the end, *Download all credentials* gives `credentials.zip`. The files
  inside are **named by display name** (`Terms and conditions.jwt`, …). **Rename them** to the
  filenames in the URLs you typed into the Wizard and copy them into `static/gaia-x/`.

```bash
curl -I https://YOUR_DOMAIN/gaia-x/lrn.jwt             # 200
curl -I https://YOUR_DOMAIN/gaia-x/legal-person.jwt    # 200
curl -I https://YOUR_DOMAIN/gaia-x/tandc.jwt           # 200
curl -I https://YOUR_DOMAIN/gaia-x/compliance-vc.jwt   # 200
```

> **Every credential URL is permanent.** The `vcId` is part of the signed credential, so
> renaming or moving a file invalidates it.

### 5. Schedule renewals

| What | Interval |
|---|---|
| Compliance VC re-submission | ~90 days |
| Identity certificate → new `did.json` if the key changes → **re-sign everything** | at most 200 days for public TLS/EV certificates from 15 March 2026, 100 days from 15 March 2027 (Let's Encrypt: 90) |
| CES re-publish, if you push there at all | every new Compliance VC |

By hand this is a recurring task; `gx run`, scheduled daily, does it and only acts when
something is due.

---

## File layout

```
gaia-x-hosting/
├── README.md                            # this page
├── gaia-x-dev-test.md                   # lab dry-run runbook  ← start here
├── gaia-x-onboarding.md                 # production onboarding + certificate choice
├── docker-compose.yml                   # nginx; Caddy and OpenBao by profile; gx tool on demand
├── compose.letsencrypt.yml              # gx's Let's Encrypt setup (no OpenBao)
├── .env.example                         # -> .env: domain, environment, which services run
├── .gitignore                           # keeps keys & per-deployment files out of git
├── nginx/nginx.conf                     # serves the six files with correct types + CORS
├── caddy/Caddyfile                      # automatic HTTPS (Let's Encrypt)
├── automation/                          # the gx tool and its OpenBao admin scripts; see its README
├── scripts/
│   └── generate_did_json.py             # cert -> did.json, plus chain/EV-OID checks (manual workflow)
├── certs/, secrets/                     # git-ignored, gx only: public identity chain, OpenBao token
└── static/                              # what nginx serves; the real files are git-ignored
    ├── cert.pem.example
    ├── .well-known/
    │   └── did.json.example
    └── gaia-x/
        ├── lrn.jwt.example
        ├── legal-person.jwt.example
        ├── tandc.jwt.example
        └── compliance-vc.jwt.example
```

The working files in `static/` are git-ignored because they belong to one organisation and
domain. The committed `.example` files show the expected shape and the command that produces
each one.
