# GAIA-X Identity Hosting

Minimal static-file server for everything a GAIA-X participant must publish.

| Served at | Contents |
|---|---|
| `/.well-known/did.json` | `did:web` identity document |
| `/cert.pem` | X.509 **identity** certificate chain (trust anchor, referenced by `x5u`) |
| `/gaia-x/lrn.jwt` | Legal Registration Number VC (issued by the GXDCH Notary) |
| `/gaia-x/legal-person.jwt` | Legal Person VC (self-signed) |
| `/gaia-x/tandc.jwt` | Terms & Conditions VC (self-signed) |
| `/gaia-x/compliance-vc.jwt` | Compliance VC returned by the GXDCH |

The first two exist before you request any credential. The other four are added as you go.

**Documentation**
- [`gaia-x-dev-test.md`](gaia-x-dev-test.md) — free dry-run against the GAIA-X lab. **Start here.**
- [`gaia-x-onboarding.md`](gaia-x-onboarding.md) — production onboarding, certificate choice, renewals.

> ### This deployment *is* the production deployment
> The project — compose file, nginx config, scripts, URL layout — is identical in dev and
> production. **Only the contents change:** a different certificate, a new key pair, a
> regenerated `did.json`, re-signed credentials, and different GXDCH endpoints. So use a
> permanent domain from the first run.

> ### ⚠️ Get the certificate type right
> Production GXDCH require the identity certificate to be **EV SSL** (CA/Browser Forum policy
> OID `2.23.140.1.1`). A Qualified Certificate for Electronic Seal is a document-signing
> certificate and does not carry it — but an eIDAS QTSP can issue the EV SSL one. See
> [`gaia-x-onboarding.md`](gaia-x-onboarding.md) Step 1.

---

## Prerequisites

- A **permanent** public domain with HTTPS on port 443 (`did:web` allows plain HTTP only on localhost)
- Docker + Docker Compose
- Python 3.9+ and `pip install cryptography`
- A certificate:
  - **dev/test** — Let's Encrypt is accepted
  - **production** — **EV SSL** as a PKCS#12 `.p12`/`.pfx`, with an **exportable** private key

> ⚠️ **Never commit the private key.** It is the root of trust for every credential you issue.
> `.gitignore` already excludes key material and all generated per-deployment files — still
> check `git status` before your first push.

---

## Workflow

### 1 — Build `cert.pem` (full chain, self-signed root last)

```bash
# production, from the CA's PKCS#12:
openssl pkcs12 -in your-cert.p12 -nokeys -chain -out static/cert.pem
cat root-ca.pem >> static/cert.pem                                   # the self-signed root

# dev/test, from certbot:
cp /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem static/cert.pem
curl -s https://letsencrypt.org/certs/isrgrootx1.pem >> static/cert.pem
```

Neither `openssl -chain` nor certbot's `fullchain.pem` includes the self-signed root — append it,
or the Registry replies `409 Root certificate is not self-signed`.

### 2 — Generate `did.json` (and check the chain)

```bash
python scripts/generate_did_json.py \
    --domain YOUR_DOMAIN \
    --cert static/cert.pem \
    > static/.well-known/did.json
```

The script flags the three things that
can break onboarding: a root that is not self-signed, a gap in the chain, and a leaf without
the EV SSL OID. Add `--strict` to make it exit non-zero (useful in CI).

### 3 — Serve the files

**Option A — nginx only** (you already terminate TLS in front):

```bash
docker compose up -d      # listens on 127.0.0.1:8080; point your proxy at it
```

**Option B — nginx + Caddy** (auto-HTTPS via Let's Encrypt): uncomment the `caddy` service in
`docker-compose.yml`, replace `YOUR_DOMAIN`, open ports 80 and 443, then `docker compose up -d`.

Caddy's certificate is the **web server's TLS** certificate and is unrelated to `static/cert.pem`.

### 4 — Verify before requesting anything

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

Registry host for a dev run: `https://registry.lab.gaia-x.eu/development`. For production, pick an
operator from `curl -s https://wizard.lab.gaia-x.eu/api/clearing-houses` and use its three hosts
consistently. A `409` here means the Compliance call will fail the same way — fix it first.

### 5 — Obtain and drop in the credentials

Follow [`gaia-x-dev-test.md`](gaia-x-dev-test.md) (lab) or [`gaia-x-onboarding.md`](gaia-x-onboarding.md)
(production). Each `.example` file under `static/gaia-x/` documents the exact shape of the
credential that replaces it. Files are served immediately — no restart.

Two ways the four credential files get here:

- **Scripted** (`curl`, see the docs) — the Notary and Compliance responses are written straight
  into `static/gaia-x/` with `-o`.
- **GAIA-X Wizard** — at the end, *Download all credentials* gives `credentials.zip`. The files
  inside are `.jwt` but are **named by display name**
  (`Terms and conditions.jwt`, `Compliance Verifiable Credential.jwt`, …). **Rename them** to the
  exact filenames in the URLs you typed into the Wizard and copy them into `static/gaia-x/`.

```bash
curl -I https://YOUR_DOMAIN/gaia-x/lrn.jwt             # 200
curl -I https://YOUR_DOMAIN/gaia-x/legal-person.jwt    # 200
curl -I https://YOUR_DOMAIN/gaia-x/tandc.jwt           # 200
curl -I https://YOUR_DOMAIN/gaia-x/compliance-vc.jwt  # 200
```

> **Every credential URL is permanent.** The `vcId` is baked into the signature, so renaming or
> moving a file invalidates it.

### 6 — Schedule renewals

Not a one-off task:

| What | Interval |
|---|---|
| Compliance VC re-submission | ~90 days |
| Identity certificate → new key → new `did.json` → **re-sign everything** | annually |
| CES re-publish, if you push there at all | every new Compliance VC requires re-publishing |

---

## File layout

```
gaia-x-hosting/
├── docker-compose.yml                   # nginx (+ optional Caddy for auto-HTTPS)
├── gaia-x-dev-test.md                   # lab dry-run runbook  ← start here
├── gaia-x-onboarding.md                 # production onboarding + certificate choice
├── .gitignore                           # keeps keys & per-deployment files out of git
├── nginx/nginx.conf                     # serves the six files with correct types + CORS
├── scripts/
│   └── generate_did_json.py             # cert -> did.json, plus chain/EV-OID checks
└── static/                              # the real files below are git-ignored
    ├── cert.pem.example
    ├── .well-known/
    │   └── did.json.example
    └── gaia-x/
        ├── lrn.jwt.example
        ├── legal-person.jwt.example
        ├── tandc.jwt.example
        └── compliance-vc.jwt.example
```

The working files (`static/cert.pem`, `static/.well-known/did.json`, `static/gaia-x/*.jwt`,
`static/gaia-x/*.json`) are deliberately git-ignored — they are specific to one organisation and
domain. The committed `.example` files document the expected shape and the command that produces
each one.
