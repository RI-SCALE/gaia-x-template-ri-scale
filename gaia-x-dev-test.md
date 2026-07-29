# GAIA-X Dev/Test Integration — Developer Runbook

> A short guide for running a **dev/test** GAIA-X onboarding.
> Goal: prove the plumbing end-to-end and get a **lab-issued Compliance VC**.

---

**Environment = development** Every GAIA-X host below is the `*.lab.gaia-x.eu` one, and in the Wizard need to select the **development** environment.

| Service | Dev/test host |
|---|---|
| Wizard | `wizard.lab.gaia-x.eu` |
| Compliance | `compliance.lab.gaia-x.eu` |
| Registry | `registry.lab.gaia-x.eu` |
| Notary | `registrationnumber.notary.lab.gaia-x.eu` |

---

## Step 0 — Collect the legal info

The registration number is validated for real by the Notary **even in dev**, so it must be genuine.

| # | Required | Example | Used in |
|---|---|---|---|
| 1 | **Registered legal name** (exactly as in the official registry) | `GRNET S.A.` | Legal Person VC |
| 2 | **Legal registration number + its type** — one of LEI / EUID / VAT / EORI | LEI `213800...` or VAT `EL099028220` | Legal Registration Number VC (Notary checks it) |
| 3 | **Headquarters address** as an ISO 3166-2 subdivision code | `GR-I` (Attica) | Legal Person VC |
| 4 | **Legal address** as an ISO 3166-2 subdivision code (often same as #3) | `GR-I` | Legal Person VC |

Notes:
- Prefer **LEI** or **EUID** if the entity has one — cleanest for the Notary. VAT works too.
- ISO 3166-2 = `COUNTRY-REGION` (e.g. `AT-9` = Vienna, `GR-I` = Attica). Look up at <https://en.wikipedia.org/wiki/ISO_3166-2>.

---

## Step 1 — Domain + dev certificate

For dev a public domain and **any CA-signed certificate** are required — **Let's Encrypt is accepted**. No eIDAS, no EV SSL. (Those are production-only.)

Use a domain topology you'd keep in production, e.g. `gaia-x.<test-domain>` — the `did:web` and VC URL are meant to be stable.

Obtain a Let's Encrypt certificate for your domain with any ACME client, then place the chain and keep the key:

```bash
certbot certonly --standalone -d gaia-x.your-test-domain.eu
cp /etc/letsencrypt/live/gaia-x.your-test-domain.eu/fullchain.pem static/cert.pem
# keep the matching privkey.pem aside for the Wizard (Step 4) — never commit it
```

The **same key pair** is used to sign in the Wizard, so `cert.pem` and the key you give the Wizard always match. The private key **never** goes into any file in this repo — it's pasted into the Wizard client-side only (Step 4).

---

## Step 2 — Generate `did.json` and serve the files

```bash
# extract public key from cert -> DID document
python scripts/generate_did_json.py \
    --domain gaia-x.your-test-domain.eu \
    --cert static/cert.pem \
    > static/.well-known/did.json

# start the static server (nginx already sets Content-Type + CORS)
docker compose up -d
```

Verify the two files are live with the right headers (CORS `*` is mandatory):

```bash
curl -I https://gaia-x.your-test-domain.eu/.well-known/did.json   # 200 + Access-Control-Allow-Origin: *
curl -I https://gaia-x.your-test-domain.eu/cert.pem               # 200
```

---

## Step 3 — Validate before the Wizard

Catches ~all onboarding failures early.

```bash
# a) DID resolves & parses (or paste into the web UIs below)
curl "https://dev.uniresolver.io/1.0/identifiers/did:web:gaia-x.your-test-domain.eu"

# b) cert chain is a valid trust anchor for the LAB env
curl "https://registrationnumber.notary.lab.gaia-x.eu/v1/api/trustAnchor/chain?vcUrl=https://gaia-x.your-test-domain.eu/cert.pem"
```

- Universal Resolver: <https://dev.uniresolver.io/> · DID Lint: <https://did-lint.org/>
- The resolved DID must show your `verificationMethod`, `JsonWebKey2020`, and an `x5u` pointing at your live `cert.pem`.
- If (b) fails, the Wizard will fail too — fix the cert/hosting first.

---

## Step 4 — Run the GAIA-X Wizard (development environment)

Open <https://wizard.lab.gaia-x.eu/> → **Onboarding**.

1. **Select the *development* environment** (not "Clearing Houses" / production). This is the one change that makes the whole test work with a Let's Encrypt cert.
2. Fill in org details from **Step 0**: legal name, registration number, HQ country code, legal address country code.
3. Tick **Terms & Conditions** (the Wizard pulls the current hash automatically).
4. Paste your **private key** (the one matching `cert.pem`; stays in-browser).
5. Enter your **DID** `did:web:gaia-x.your-test-domain.eu` and **verification method ID** `did:web:gaia-x.your-test-domain.eu#key-1`.
6. Click **Sign** — creates + signs the 3 VCs (Legal Registration Number, Legal Person, T&C) and calls the lab Notary to counter-sign the registration number. Download them if you want copies.
7. Select the **dev GXDCH** and click **Submit to compliance** → on success you get the **Compliance VC**. Download it.

> Do **not** click **Share** / push to CES for a test run — that would advertise a non-production credential.

---

## Step 5 — Host the Compliance VC & final end-to-end test

```bash
cp ~/Downloads/compliance-vc.json static/gaia-x/compliance-vc.json   # served immediately
```

Confirm all three files resolve publicly:

```bash
curl -I https://gaia-x.your-test-domain.eu/.well-known/did.json      # 200, application/json, CORS *
curl -I https://gaia-x.your-test-domain.eu/cert.pem                  # 200
curl -I https://gaia-x.your-test-domain.eu/gaia-x/compliance-vc.json # 200, application/json, CORS *
```

Optional sanity check — the Compliance VC's `credentialSubject` should reference your `did:web` and the registration number you submitted.

---

## Quick checklist

```
[ ] Step 0  Got legal name, registration number (+type), HQ + legal ISO 3166-2 codes from the entity
[ ] Step 1  Public domain + Let's Encrypt cert (fullchain -> static/cert.pem, key kept aside)
[ ] Step 2  did.json generated; did.json + cert.pem serve 200 with CORS *
[ ] Step 3  DID resolves (Universal Resolver) AND lab trust-anchor check passes
[ ] Step 4  Wizard in DEVELOPMENT env -> 3 VCs signed -> Compliance VC issued
[ ] Step 5  compliance-vc.json hosted; all 3 URLs return 200; NOT pushed to CES
```
