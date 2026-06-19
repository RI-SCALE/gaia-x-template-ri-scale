# GAIA-X Identity Hosting

Minimal static-file server for the three files required to be a GAIA-X participant:

| File served at | Purpose |
|---|---|
| `https://your.domain/.well-known/did.json` | Your `did:web` identity document |
| `https://your.domain/cert.pem` | Your X.509 certificate chain (trust anchor) |
| `https://your.domain/gaia-x/compliance-vc.json` | GAIA-X Compliance VC issued by GXDCH |

The first two files exist before you touch the GAIA-X Wizard. The third is added after.

---

## Prerequisites

- Python 3.9+ and `pip install cryptography`
- Docker + Docker Compose
- An eIDAS Qualified Seal certificate **or** an EV SSL certificate (as a PKCS#12 `.p12`/`.pfx` file — see [`gaia-x-onboarding.md`](gaia-x-onboarding.md) Step 1). The issuing CA's chain must anchor to a trust anchor listed in the [Gaia-X Registry](https://registry.gaia-x.eu/) — verify this *before* purchasing.
- A public domain pointing to this server

> ⚠️ **Never commit your private key.** The signing key that matches your certificate is the root of trust for every credential you issue. Keep the `.p12`/`.pfx`/`.key` outside this repo. The included `.gitignore` already excludes common key extensions and your generated `cert.pem` / `did.json` / `compliance-vc.json`, but double-check `git status` before your first push.

---

## Step-by-step workflow

### 1 — Extract PEM from your certificate file

```bash
openssl pkcs12 -in your-cert.p12 -nokeys -chain -out static/cert.pem
# enter the password from your CA when prompted
```

This writes the full certificate chain (leaf + intermediates) into `static/cert.pem`.

---

### 2 — Generate `did.json`

```bash
python scripts/generate_did_json.py \
    --domain your.domain.eu \
    --cert static/cert.pem \
    > static/.well-known/did.json
```

Open the output file and verify the `id` and `x5u` fields contain your actual domain.

---

### 3 — Start the server

**Option A — nginx only** (you already have a TLS-terminating proxy in front):

```bash
docker compose up -d
```

The container listens on `127.0.0.1:8080`. Configure your existing reverse proxy to forward
HTTPS requests for your domain to `localhost:8080`.

**Option B — nginx + Caddy** (auto-HTTPS via Let's Encrypt, no external proxy needed):

1. Open `docker-compose.yml` and uncomment the `caddy` service block.
2. Replace `YOUR_DOMAIN` with your actual domain name.
3. Make sure ports 80 and 443 are open to the internet.

```bash
docker compose up -d
```

Caddy will automatically obtain and renew a Let's Encrypt certificate. The first startup
takes ~10 seconds while the certificate is issued.

---

### 4 — Verify the endpoints

```bash
curl https://your.domain/.well-known/did.json
curl https://your.domain/cert.pem
```

Both must return HTTP 200. The `did.json` response must include `Access-Control-Allow-Origin: *`.

---

### 5 — Validate your `did:web` and trust anchor

Catch malformed identity documents *before* you try a Wizard run. Two independent checks:

**a) Does your `did:web` resolve and parse?** Use the Universal Resolver and DID Lint
(both recommended by the GAIA-X Compliance Document):

```bash
# Universal Resolver — should return your DID document, not an error
curl "https://dev.uniresolver.io/1.0/identifiers/did:web:your.domain.eu"
```

Or paste `did:web:your.domain.eu` into the web UIs:
- Universal Resolver: https://dev.uniresolver.io/
- DID Lint: https://did-lint.org/

Confirm the resolved document shows your `verificationMethod`, the `JsonWebKey2020` type,
and an `x5u` that points at your live `cert.pem`.

**b) Is your certificate chain a valid GAIA-X trust anchor?** Run it past the GXDCH
trust-anchor checker (use the production notary host once you hold a production cert;
the `.lab.` host is for dev/test certificates):

```bash
# dev / test certificates:
curl "https://registrationnumber.notary.lab.gaia-x.eu/v1/api/trustAnchor/chain?vcUrl=https://your.domain/cert.pem"
# production certificates: use registrationnumber.notary.gaia-x.eu (your chosen GXDCH operator)
```

A successful response confirms the chain anchors to a CA in the GAIA-X Registry. If it
fails here, the Wizard submission will also fail — fix the certificate first.

---

### 6 — Go through the GAIA-X Wizard

Open [wizard.lab.gaia-x.eu](https://wizard.lab.gaia-x.eu/) → **Onboarding** tab → **Start**.

The Wizard handles everything from here: filling credentials, signing, Notary call, VP packaging,
and GXDCH submission. You will need:

- Your **private key** in PEM format (the key that matches `cert.pem`; used client-side only, never leaves the browser)
- Your **DID** (`did:web:your.domain.eu`)
- Your **verification method ID** (`did:web:your.domain.eu#key-1`)
- Your organisation's **legal registration number** (EORI / LEI / EUID / VAT)

Wizard flow:
1. Fill in organisation details (legal name, registration number, country codes).
2. Tick the Terms & Conditions checkbox.
3. Paste your private key → click **Next**.
4. Enter your DID and verification method ID → click **Next**.
5. Click **Sign** — three credentials are created and signed. Download them if you want a local copy.
6. Select a **GXDCH operator** from the dropdown, then click **Submit to compliance** — the Wizard sends a Verifiable Presentation to that Clearing House.
7. On success, download the **Compliance VC** JSON file.

---

### 7 — Drop in the Compliance VC

```bash
cp ~/Downloads/compliance-vc.json static/gaia-x/compliance-vc.json
```

The file is served immediately (no restart needed). Verify:

```bash
curl https://your.domain/gaia-x/compliance-vc.json
```

---

### 8 — (Optional) Publish to the GAIA-X Credential Event Service

Back in the Wizard, click **Share** on the Compliance VC. This pushes the URL
`https://your.domain/gaia-x/compliance-vc.json` to the GAIA-X CES, making your participant
status discoverable in GAIA-X-connected catalogues.

---

## File layout

```
gaia-x-hosting/
├── docker-compose.yml                   # nginx (+ optional Caddy for auto-HTTPS)
├── gaia-x-onboarding.md                 # full onboarding guide (background + Wizard walkthrough)
├── .gitignore                           # keeps keys & per-deployment files out of git
├── nginx/nginx.conf                     # serves static/ with correct headers
├── scripts/
│   └── generate_did_json.py             # extracts public key from cert → did.json
└── static/                              # the real files below are git-ignored
    ├── cert.pem.example                 # template; generate the real static/cert.pem
    ├── .well-known/
    │   └── did.json.example             # template; script writes the real did.json here
    └── gaia-x/
        └── compliance-vc.json.example   # template; drop the real Wizard output here
```

> The working files (`static/cert.pem`, `static/.well-known/did.json`,
> `static/gaia-x/compliance-vc.json`) are deliberately git-ignored — they are
> specific to your organisation and domain. The committed `.example` files document
> the expected shape. nginx serves the real files once you create them.
