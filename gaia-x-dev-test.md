# GAIA-X Dev/Test Integration — Developer Runbook

> Goal: prove our plumbing end-to-end and get a **lab-issued Compliance VC**, using a free
> Let's Encrypt certificate.
>
> **Verified against the live GAIA-X lab services on 2026-09-15** (Wizard v2.3.0, Loire/v2
> ontology). The official GAIA-X user guide may be outdated and deviate from the deployed version of Wizard.

---

## Read before starting: this deployment *is* the production deployment

Everything built here is reused for production unchanged. **The project stays the same — only
the contents change.** 

| | Stays identical dev → prod | Must be replaced for prod |
|---|---|---|
| `docker-compose.yml`, `nginx/`, `scripts/` | ✅ | |
| Domain and URL layout (`did.json`, `cert.pem`, `/gaia-x/*`) | ✅ | |
| Identity certificate (`static/cert.pem`) | | Let's Encrypt → **EV SSL** |
| Signing key pair | | comes with the new certificate |
| `static/.well-known/did.json` | | regenerate from the new key |
| All four credentials | | re-sign; LRN re-issued by the **production** Notary |
| GXDCH endpoints | | `lab…/development` → `<operator>…/v2` |

Two consequences worth deciding **before any deployment**:

1. **Use a permanent domain.** `did:web` and every VC URL are meant to be stable forever.
   Don't test on a throwaway hostname.
2. **In production the TLS certificate and the identity certificate are two different certs.**
   Here, one Let's Encrypt cert does both jobs. In production nginx keeps a Let's Encrypt TLS
   cert, while `static/cert.pem` becomes the EV SSL identity cert. Plan two renewal cycles.

> ⚠️ **Before buying a certificate**, read the certificate section of
> [`gaia-x-onboarding.md`](gaia-x-onboarding.md).

---

## Two different "dev tests"

The Wizard was reworked in **v2.0.0 (2026-05-25)**. It no longer has a "use my own certificate
against the development environment" mode. Therefore, two types of a test suggested:

| | Path A — Wizard smoke test | Path B — real dev test |
|---|---|---|
| **Effort** | ~10 min, nothing to prepare | Steps 1–5 of this doc |
| **Uses our cert / DID?** | **No** — signs with a shared dummy key, issuer is `did:web:vc-jwt.io:api` | **Yes** |
| **How** | Wizard defaults, don't touch anything | Our own tooling → POST straight to the lab Compliance API |
| **Proves** | GAIA-X is up; our legal name + registration number pass the Notary | Our certificate, `did:web`, hosting and signing all work |

**Do Path A first** (it is free and instant and de-risks Step 0), then **do Path B** — B is the
one that actually validates the deployment. Path B does **not** use the Wizard.

---

## Environment: use the `development` deployment path

Every lab service exposes several deployment paths.

| Service | Dev/test endpoint |
|---|---|
| Compliance | `https://compliance.lab.gaia-x.eu/development` |
| Registry (trust anchors) | `https://registry.lab.gaia-x.eu/development` |
| Notary (registration number) | `https://registrationnumber.notary.lab.gaia-x.eu/development` |
| CES (do **not** push test credentials) | `https://ces-development.lab.gaia-x.eu` |
| Wizard (Path A only) | `https://wizard.lab.gaia-x.eu` |

> ⚠️ **Do not use the `/v2` path for a dev test.** `registry.lab.gaia-x.eu/v2` rejects any
> non-EV certificate outright (`409 — The leaf certificate provided is not EV-SSL,
> 2.23.140.1.1 OID is missing`). `/development` accept Let's Encrypt.
> All paths are listed at <https://catalogue.lab.gaia-x.eu/>.

---

## Step 0 — Collect the legal info

The registration number is validated against **real external registries even in dev**, so it
must be genuine.

| # | Required | Example |
|---|---|---|
| 1 | **Registered legal name**, exactly as in the official registry | `Stichting EGI` |
| 2 | **Registration number + type** (see below) | LEI `9695007587FA72F7E115` or VAT `NL123456789B01` |
| 3 | **Headquarters address** as ISO 3166-2 subdivision code | `NL-NH` |
| 4 | **Legal address** as ISO 3166-2 subdivision code (often the same) | `NL-NH` |

**Accepted number types.** The Notary supports five; the Wizard UI only offers three:

| Type | Notary (`/development`) | Wizard UI |
|---|---|---|
| `lei-code` / `leiCode` | yes | yes |
| `vat-id` / `vatID` | yes | yes |
| `eori` / `EORI` | yes | yes |
| `tax-id` (OpenCorporates) | yes | no |
| `country-company-number` | yes | no |

- **Prefer LEI**, then VAT. **EUID is not supported** by the Notary.
- ISO 3166-2 = `COUNTRY-REGION`. Look up at <https://en.wikipedia.org/wiki/ISO_3166-2>.

---

## Step 1 — Domain + Let's Encrypt certificate

For dev, **Let's Encrypt is accepted**. No eIDAS, no EV SSL (those are production-only).
Use a domain topology we would keep in production, e.g. `gaia-x.<our-domain>` — the `did:web`
and the VC URLs are meant to be permanent.

```bash
certbot certonly --standalone -d gaia-x.our-domain.eu
```

### ⚠️ Build `cert.pem` correctly — this is the #1 cause of failure

`fullchain.pem` alone **will be rejected**. The Registry requires a chain that ends in a
**self-signed root**, and it also needs every cross-signed intermediate in between. Both
failure modes were reproduced:

| `cert.pem` contents | Registry `/development` says |
|---|---|
| `fullchain.pem` only | `409` — *Root certificate is not self-signed* |
| leaf + intermediate + self-signed root, skipping the cross-signed root | `409` — *… invalid signature* |
| **`fullchain.pem` + self-signed root appended** | **`200 {"result":true}`** ✅ |

```bash
# fullchain.pem = leaf -> LE intermediate -> LE cross-signed root
cp /etc/letsencrypt/live/gaia-x.our-domain.eu/fullchain.pem static/cert.pem
# append Let's Encrypt's self-signed root to terminate the chain
curl -s https://letsencrypt.org/certs/isrgrootx1.pem >> static/cert.pem

# sanity check: the LAST certificate must be self-signed (subject == issuer)
openssl crl2pkcs7 -nocrl -certfile static/cert.pem | openssl pkcs7 -print_certs -noout
```

Keep `privkey.pem` outside the repo. The **same key pair** signs the credentials, so `cert.pem`
and the signing key must always match.

> Verify the last certificate is self-signed.

---

## Step 2 — Generate `did.json` and serve the files

```bash
python scripts/generate_did_json.py \
    --domain gaia-x.our-domain.eu \
    --cert static/cert.pem \
    > static/.well-known/did.json

docker compose up -d       # nginx already sets Content-Type + CORS
```

```bash
curl -I https://gaia-x.our-domain.eu/.well-known/did.json   # 200 + Access-Control-Allow-Origin: *
curl -I https://gaia-x.our-domain.eu/cert.pem               # 200
```

### Plan the VC URLs now

Every credential carries its own URL as its `id`, decided **before** signing — the Notary refuses
to issue without one (`400 — The verifiable credential ID is missing`), and the Compliance VC
will contain these URLs as `{id, integrity}` pointers. Reserve these paths:

| Credential | Suggested URL |
|---|---|
| Legal Registration Number VC | `https://gaia-x.our-domain.eu/gaia-x/lrn.jwt` |
| Legal Person VC | `https://gaia-x.our-domain.eu/gaia-x/legal-person.jwt` |
| Terms & Conditions VC | `https://gaia-x.our-domain.eu/gaia-x/tandc.jwt` |
| Compliance VC | `https://gaia-x.our-domain.eu/gaia-x/compliance-vc.jwt` |

---

## Step 3 — Validate before submitting

These two checks catch nearly every failure.

```bash
# a) does our DID resolve and parse?
curl "https://dev.uniresolver.io/1.0/identifiers/did:web:gaia-x.our-domain.eu"

# b) is our chain rooted in a GAIA-X trust anchor?  (POST, not GET — and on the REGISTRY host)
curl -X POST "https://registry.lab.gaia-x.eu/development/api/trustAnchor/chain/file" \
     -H 'Content-Type: application/json' \
     -d '{"uri":"https://gaia-x.our-domain.eu/cert.pem"}'
```

- Success for (b) is exactly `{"result":true}`. A `409` means the chain is wrong — fix Step 1
  before going further; the Compliance call will fail for the same reason.
- The resolved DID must show our `verificationMethod`, type `JsonWebKey2020`, and an `x5u`
  pointing at our live `cert.pem`.
- Also useful: DID Lint <https://did-lint.org/>.

> The old `registrationnumber.notary.…/v1/api/trustAnchor/chain?vcUrl=` URL no longer exists.
> The v2 Notary has no trust-anchor endpoint at all — this check moved to the **Registry**.

---

## Step 4 — Get the credentials

### Path A — Wizard smoke test (no cert, no key)

Open <https://wizard.lab.gaia-x.eu/> → toggle off *I'll use my own private key for signing (production use)*. Flow: `Start → Legal Person → Terms & Conditions → Sign → Compliance Check`.

What happens, step by step (verified against Wizard v2.3.0):

| Step | What the Wizard does | Real or dummy? |
|---|---|---|
| Legal Person | You enter the Step 0 data. The Wizard calls the **lab Notary** with the number; the Notary validates it against the real external registry and returns a Notary-signed LRN VC. | **Real** — a wrong number fails here |
| Terms & Conditions | Tick the box; the current hash is filled in. | real hash |
| Sign | Legal Person + T&C VCs are signed by the external `vc-jwt.io` service with a **shared dummy key**; issuer is `did:web:vc-jwt.io:api`. Each VC is stored on the Wizard's own server at `…/api/credentials/<uuid>`. | **Dummy identity** |
| Compliance Check | VP built, signed by `vc-jwt.io`, POSTed to `compliance.lab.gaia-x.eu/development`. Full validation runs (signatures, shapes, Notary signature, T&C hash). Returns a Compliance VC signed by the **lab** GXDCH. | real check, wrong subject |
| Credential | Everything is shown; **Download all credentials** gives `credentials.zip`. | — |

The Compliance VC attests `vc-jwt.io`'s identity, not ours — **do not host
it and do not push it to CES.**

**What `credentials.zip` contains and why it is still useful.** The three input VCs, the
Compliance VC and the VP, each as `.jwt`, named by display name (`Terms and conditions.jwt`, `Compliance Verifiable
Credential.jwt`, …). They are worthless as *our* credentials, but they are **correct,
machine-produced Loire/v2 examples built from our own legal data** — the best template for
authoring the Legal Person and T&C VCs in Path B: copy the payloads, replace `issuer`, `id` and
`kid` with ours, re-sign with our key.

So Path A proves exactly three things: the registration number passes a GAIA-X Notary, the legal
data passes the shape validation, and the lab is up. Nothing about the certificate, key, DID or
hosting.


### Path B — real dev test with our own identity (no Wizard)

1. **Get the Legal Registration Number VC** from the lab Notary (it counter-signs it):

   ```bash
   VCID=$(python -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" \
          "https://gaia-x.our-domain.eu/gaia-x/lrn.jwt")
   curl "https://registrationnumber.notary.lab.gaia-x.eu/development/registration-numbers/lei-code/<OUR-LEI>?vcId=$VCID&subjectId=did:web:gaia-x.our-domain.eu"
   ```
   Save the response to `static/gaia-x/lrn.jwt` so the URL above resolves.

2. **Author and sign the Legal Person VC and the Terms & Conditions VC** with our key, as
   enveloped VC-JWTs (`RS256` or `ES256`, matching the key type in `did.json`). The JWT `kid`
   must be our verification method, e.g. `did:web:gaia-x.our-domain.eu#key-1`. Publish each at
   the URL reserved in Step 2.

3. **Bundle all three into a Verifiable Presentation** and sign it with the same key
   (VP-JWT, per [W3C vc-jose-cose](https://www.w3.org/TR/vc-jose-cose/#with-jose)).

4. **Submit to the lab Compliance Service — the response body *is* the Compliance VC:**

   ```bash
   VCID=$(python -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" \
          "https://gaia-x.our-domain.eu/gaia-x/compliance-vc.jwt")
   curl -X POST \
     "https://compliance.lab.gaia-x.eu/development/api/credential-offers/standard-compliance?vcid=$VCID" \
     -H 'Content-Type: application/vp+jwt' \
     --data-binary @our-vp.jwt \
     -o static/gaia-x/compliance-vc.jwt \
     -w '\nHTTP %{http_code}  %{content_type}\n'
   ```



   | Outcome | HTTP | Body |
   |---|---|---|
   | success | **`201`**, `Content-Type: application/vc+jwt` | the Compliance VC, as **one JWT string** (`eyJ…`.`…`.`…`) |
   | failure | `4xx` / `409` | JSON with a `message` / `errors` list naming the failed check |

   Because `-o` writes the body to `static/gaia-x/compliance-vc.jwt`, the file appears at the
   exact URL we declared as `vcid` — nginx serves it immediately. **On failure the same `-o`
   writes the JSON error into that file**, so always check the printed status and delete the
   file if it isn't `201`.

   Quick look at what came back (payload only, no verification):

   ```bash
   cut -d. -f2 static/gaia-x/compliance-vc.jwt | tr '_-' '/+' | base64 -d 2>/dev/null | python -m json.tool
   ```

Before responding, the service resolves the `did:web`, verifies each signature against the `x5u`
chain, checks the chain root against the Registry, checks the T&C hash, and re-checks the
registration number with the Notary.


> **Do not push anything to CES during a test run** — the lab CES is world-readable (anyone can
> `GET https://ces-development.lab.gaia-x.eu/v2/credentials-events`), so a test credential would
> be publicly advertised.

---

## Step 5 — Final check

Step B4 already wrote the Compliance VC into `static/`, so nothing needs copying. Confirm all six files resolve publicly:

> During submission the
> Compliance Service fetches only `did.json`, `cert.pem` and the Registry — the VCs travel
> *inside* the VP, so the POST would succeed even if `lrn.jwt` etc. were not yet online.
> But the Compliance VC it returns is just a list of `{id, integrity}` pointers to those files.
> **Anyone who later verifies our compliance resolves those pointers**.

```bash
curl -I https://gaia-x.our-domain.eu/.well-known/did.json       # 200, application/json, CORS *
curl -I https://gaia-x.our-domain.eu/cert.pem                   # 200, application/x-pem-file
curl -I https://gaia-x.our-domain.eu/gaia-x/lrn.jwt             # 200, application/jwt
curl -I https://gaia-x.our-domain.eu/gaia-x/legal-person.jwt    # 200, application/jwt
curl -I https://gaia-x.our-domain.eu/gaia-x/tandc.jwt           # 200, application/jwt
curl -I https://gaia-x.our-domain.eu/gaia-x/compliance-vc.jwt   # 200, application/jwt, CORS *
```

Sanity check the Compliance VC: its `credentialSubject` is a list of `{id, integrity}` pointers
to the three VCs we submitted. It contains **no endpoints and no dataset information** — it only
attests that we are a conformant participant.

---

## Quick checklist

```
[ ] Step 0  Legal name, registration number (LEI preferred; NOT EUID), HQ + legal ISO 3166-2 codes
[ ] Path A  Wizard smoke test passes -> legal data + number are acceptable
[ ] Step 1  LE cert obtained; cert.pem = fullchain + self-signed root; last cert is self-signed
[ ] Step 2  did.json generated; did.json + cert.pem serve 200 with CORS *; VC URLs reserved
[ ] Step 3  DID resolves AND trustAnchor/chain/file returns {"result":true} on /development
[ ] Step B1 LRN VC obtained from lab Notary and published at its vcId URL
[ ] Step B2 Legal Person + T&C VCs signed with our key and published
[ ] Step B3 VP signed; POSTed to compliance .../development/... -> Compliance VC issued
[ ] Step 5  All six URLs return 200; nothing pushed to CES
```
---
