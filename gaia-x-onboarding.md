# GAIA-X Onboarding Guide
> For RI-SCALE participants intending to use GAIA-X as a data space
>
> **Production path.** For the free lab dry-run first, see [`gaia-x-dev-test.md`](gaia-x-dev-test.md)
> — the infrastructure is identical, only the certificate and credentials differ.
>
> **Endpoints and certificate rules verified against the live GXDCH services on 2026-09-15**
> (Loire / v2, registry v2.10.3–2.11.0). Parts of the official GAIA-X documentation and the
> Wizard user guide are out of date; this document follows the deployed services and says so.

---

## What GAIA-X Actually Is

GAIA-X is **not a data center or storage provider**. It is a European federation framework that defines
rules for trusted, interoperable data spaces. Its core deliverable for RI-SCALE is that it **issues a
compliance Verifiable Credential (VC)** to any participant that meets its technical requirements.

**Important clarification on EDC/DCP:** The EDC (Eclipse Dataspace Connector) stack and DCP
protocol are used in industrial data spaces (Catena-X, Manufacturing-X, etc.) where connectors
actively negotiate data contracts between counterparties. **None of the data centers and data
spaces that RI-SCALE currently integrates with use EDC or DCP:**

| Data space | Auth stack actually used |
|---|---|
| Copernicus CDSE | Proprietary Keycloak + OAuth2 `client_credentials` + CloudFerro keys-manager |
| Destination Earth DEDL | EUMETSAT RODEO Keycloak + OAuth2 `client_credentials` |
| EOSC | EGI Check-in OIDC (hub-and-spoke federation model) |
| EUCAIM | EGI Check-in OIDC |

All of these are standard OIDC/OAuth2 flows. No DCP negotiation takes place; no EDC connector
is present on the other side. Consequently, **hosting an EDC connector or IdentityHub is not
required for an RI to interoperate with any of these systems**, including in the context of
GAIA-X compliance.

---

## Part 1: Organisational Membership

Joining the GAIA-X Association (AISBL) as an organisation member is separate from technical
compliance. It is not required to obtain a Compliance VC, but gives voting rights and working
group access.

**Process:**
1. Contact `aisbl-membership@gaia-x.eu` or use the application form at [forms.membersplatform.gaia-x.eu](https://forms.membersplatform.gaia-x.eu/).
2. Receive application documents from the secretariat.
3. Complete and return the documents; Board of Directors decides on admission.

This step is optional for RI-SCALE purposes.

---

## Part 2: Technical Compliance — Getting a GAIA-X Participant VC

This is the **mandatory** path. The output is a signed GAIA-X Compliance VC issued by a GAIA-X
Digital Clearing House (GXDCH), which proves the organisation is a valid GAIA-X participant.

Since no EDC stack is involved in RI-SCALE's actual data spaces, the goal here is simply to
**hold a valid GAIA-X Compliance VC** and make it publicly resolvable. No IdentityHub, no
running connector service.

### Process overview

```
[Prepare PKI + DID] → [Author self-description VCs] → [Submit to GXDCH] → [Receive Compliance VC]
        ↑                         ↑                           ↑                       ↓
   Step 1–2                  Step 3–4                    Step 3–4         [Host VC as static file]
  (manual / cert)         (GAIA-X Wizard)            (GAIA-X Wizard)              ↓
                                                                       [(Optional) Push URL to CES]
```

**Where does the GAIA-X Wizard fit?** Steps 3 and 4 are handled entirely by the GAIA-X Wizard:
filling in org details, signing the three credentials (including the Notary call for the
Legal Registration Number), packaging the VP, and submitting to GXDCH — all in one guided
browser session. The outputs (signed VCs + Compliance VC) are downloaded as `credentials.zip`
and must be **renamed and copied** into `static/gaia-x/` by you — see Step 4, Option 1.

**What remains outside the Wizard:** obtaining the certificate (Step 1), setting up the
`did:web` endpoint, and hosting all six static files (Step 2 and Step 5). The Wizard is optional
— Step 4 Option 2 does the same thing over HTTP and can be used for renewal automation.

---

### Step 1 — Obtain a qualifying X.509 certificate

> ### ⚠️ Buy an **EV SSL** certificate, not an eIDAS qualified seal
>
> The GAIA-X policy documents say eIDAS is preferred and EV SSL is a conditional fallback.
> **The deployed code says the opposite.** Every production GXDCH registry rejects a leaf
> certificate that does not carry the CA/Browser Forum **EV SSL** policy OID `2.23.140.1.1`:
>
> ```
> 409  "The leaf certificate provided is not EV-SSL - 2.23.140.1.1 OID is missing"
> ```
>
> An eIDAS **Qualified Certificate for Electronic Seal does not contain that OID** — it carries
> ETSI QCStatements instead. So as deployed today, an eIDAS seal fails this check and an EV SSL
> certificate passes. Source: `verifyLeafOIDEVSSL()` in
> [`gx-registry`](https://gitlab.com/gaia-x/lab/compliance/gx-registry/-/blob/development/src/trust-anchor/services/trust-anchor.service.ts).
>
> **Confirm this yourself before buying any certificate.** Every registry publishes the flag that
> controls the check:
>
> ```bash
> curl -s https://<operator-registry>/v2/configurations/credentials | grep -o 'evsslonly[^}]*'
> ```
>
> Measured 2026-09-15 — all eight production operators enforce it:
>
> | Registry | `evsslonly` |
> |---|---|
> | all 8 production GXDCH operators (`…/v2`) | `true` → EV required |
> | `registry.lab.gaia-x.eu/development` and `/main` | `false` → any CA, incl. Let's Encrypt |

Two separate requirements, both mandatory:

1. **The chain root must be a trust anchor in the GAIA-X Registry** — true for any public CA.
2. **The leaf must be EV SSL** (see above).

| Environment | Accepted certificate |
|---|---|
| **Production** (`<operator>/v2`) | **EV SSL** — verified working. eIDAS qualified seal: **rejected** (verified in source) |
| **Development / test** (`lab…/development`, `/main`) | Any CA, including Let's Encrypt |

#### Obtaining an EV SSL certificate

Purchase from any CA/Browser Forum member (DigiCert, Sectigo, GlobalSign, …). Vetting covers
verified legal existence, physical address (no P.O. boxes), domain control, and a callback to the
organisation's published phone number. Delivered as PKCS#12. **1–5 days, €100–300/yr.**

Ask the CA to confirm in writing that the issued certificate includes certificate policy OID
`2.23.140.1.1`.

#### eIDAS Qualified Certificate for Electronic Seal — for reference

Issued under eIDAS (EU 910/2014) by a state-supervised QTSP; find one via the
[EU Trusted List Browser](https://eidas.ec.europa.eu/efda/tl-browser/) (service type
"QCert for eSeal"). Requires proof of legal existence, the registration number, and identity
verification of an authorised representative. **1–4 weeks, €100–400/yr.** Carries full EU legal
presumption and may be required by future GAIA-X Label Levels — but see the warning above before
choosing it.

> **Key custody.** A QTSP may deliver an eIDAS key on a QSCD hardware token from which the
> private key cannot be exported. Local/CI signing then becomes impossible. Confirm you will
> receive an exportable PKCS#12 before ordering.

#### Chain construction — the most common hard failure

`cert.pem` must contain the **full chain ending in a self-signed root**, including every
cross-signed intermediate. Both failure modes were reproduced against the live registry:

| `cert.pem` contents | Registry response |
|---|---|
| leaf + intermediates only (e.g. certbot `fullchain.pem`) | `409` — *Root certificate is not self-signed* |
| self-signed root present but a cross-signed intermediate omitted | `409` — *… invalid signature* |
| **full chain + self-signed root** | **`200 {"result":true}`** ✅ |

```bash
# verify: the LAST certificate must have subject == issuer
openssl crl2pkcs7 -nocrl -certfile static/cert.pem | openssl pkcs7 -print_certs -noout
```

> **The TLS certificate and the identity certificate are different certificates.** Let's Encrypt
> is fine for the web server's TLS. The EV SSL certificate is the *identity* certificate served
> at `cert.pem` and referenced by `x5u`. Two certificates, two renewal cycles.

---

### Step 2 — Set up `did:web` identity

GAIA-X uses the `did:web` DID method. You need a public domain you control.

**Minimum infrastructure:**
- A domain with HTTPS (port 443, required by the `did:web` spec — HTTP only valid for localhost)
- A JSON file served at: `https://<your-domain>/.well-known/did.json`
- The `did.json` file must be served with `Content-Type: application/json` and
  `Access-Control-Allow-Origin: *` headers so DID resolvers can fetch it cross-origin

**Generating `did.json` from your certificate:**

The `publicKeyJwk` object inside `did.json` must contain the public key extracted from
your X.509 certificate.

Example output:
```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
  "id": "did:web:your.domain.eu",
  "verificationMethod": [{
    "id": "did:web:your.domain.eu#key-1",
    "type": "JsonWebKey2020",
    "controller": "did:web:your.domain.eu",
    "publicKeyJwk": {
      "kty": "RSA",
      "n": "<base64url modulus>",
      "e": "AQAB",
      "x5u": "https://your.domain.eu/cert.pem"
    }
  }],
  "assertionMethod": ["did:web:your.domain.eu#key-1"]
}
```

The private key is **never placed in `did.json`** — it stays secret and is used only to sign the
credentials (client-side in the Wizard, or in your own tooling).

**Validate before you proceed.** Once `did.json` and `cert.pem` are served over public HTTPS,
confirm the DID resolves and the chain is accepted — this catches the most common onboarding
failures early:

```bash
# a) DID resolves and parses
curl "https://dev.uniresolver.io/1.0/identifiers/did:web:your.domain.eu"

# b) chain is accepted by your chosen GXDCH's registry  (POST, on the REGISTRY host)
curl -X POST "https://<operator-registry>/v2/api/trustAnchor/chain/file" \
     -H 'Content-Type: application/json' \
     -d '{"uri":"https://your.domain.eu/cert.pem"}'
```

- Success for (b) is exactly `{"result":true}`. A `409` naming the EV OID means the certificate
  type is wrong (Step 1); a `409` about the root means the chain is wrong (Step 1).
- The resolved DID must show your `verificationMethod`, type `JsonWebKey2020`, and an `x5u`
  pointing at the live `cert.pem`. Also useful: **DID Lint** (`https://did-lint.org/`).

---

### Step 3 — Author and sign the required Verifiable Credentials

Three credentials must be produced. All must be signed with the private key that corresponds to
the certificate in your DID document.

**Recommended path: GAIA-X Wizard** — a hosted UI at `wizard.lab.gaia-x.eu` that generates,
signs, and submits everything in a single guided flow. No code required. See the walkthrough
in Step 4 below, which covers Steps 3 and 4 together as the Wizard does not separate them.

**Manual / programmatic path:** Described below. Use this if you need to automate signing or run
renewals from CI (Step 5).

---

#### Required credentials

##### 3a. Legal Registration Number VC
A claim about your official registration identifier. **Issued and signed by the GXDCH Notary**
(not self-signed), which validates the number against real external registries:

```
GET https://<operator-notary>/v2/registration-numbers/{type}/{value}
      ?vcId=<url-encoded URL where you will publish this VC>
      &subjectId=did:web:your.domain.eu
```

| `{type}` | Notary | Wizard UI |
|---|---|---|
| `lei-code` (preferred) | yes | yes |
| `vat-id` | yes | yes |
| `eori` | yes | yes |
| `tax-id` (OpenCorporates) | yes | no |
| `country-company-number` | yes | no |

- **EUID is not supported.** Use LEI, or VAT.
- `vcId` and `subjectId` are both **mandatory** — decide your VC URLs before calling (Step 5).

##### 3b. Legal Person VC
Describes your organisation. References the Legal Registration Number VC.

| Field | Description |
|---|---|
| `gx:legalName` | Registered legal name |
| `gx:legalRegistrationNumber` | Reference to the credential above |
| `gx:headquarterAddress` | `{ "gx:countrySubdivisionCode": "XX-YY" }` (ISO 3166-2) |
| `gx:legalAddress` | Same structure as above |

##### 3c. Terms & Conditions VC
A self-signed declaration of acceptance. In Loire/v2 this is a single hash field:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/gaia-x/development#"],
  "type": ["VerifiableCredential", "gx:Issuer"],
  "id": "https://your.domain.eu/gaia-x/tandc.jwt",
  "credentialSubject": {
    "id": "https://your.domain.eu/gaia-x/tandc.jwt#cs",
    "gaiaxTermsAndConditions": "4bd7554097444c960292b4726c2efa1373485e8a5565d94d41195214c5e0ceb3"
  }
}
```

The hash is a fixed constant per Trust Framework release. The value above is the one the
registry itself uses as of 2026-09-15; there is **no public registry endpoint that returns it**. Re-check it against
[`terms-and-conditions-credential.service.ts`](https://gitlab.com/gaia-x/lab/compliance/gx-registry/-/blob/development/src/registry-identity/services/terms-and-conditions-credential.service.ts)
before onboarding, or let the Wizard fill it in.

---

#### Signing format

Credentials are signed as **enveloped VC-JWTs** — the VC payload carried inside a JOSE/JWS
envelope, per [W3C vc-jose-cose](https://www.w3.org/TR/vc-jose-cose/#with-jose). The JWT `kid`
must be the verification method ID from your `did.json`, e.g. `did:web:your.domain.eu#key-1`,
and `iss` your DID.

Signing algorithm: RS256 (RSA) or ES256 (EC) — must match the key type in your DID document.

---

### Step 4 — Package into a Verifiable Presentation and submit to GXDCH

A **Verifiable Presentation (VP)** bundles the three signed VC-JWTs from Step 3 into one envelope,
itself signed with your key: a **VP-JWT** (`Content-Type: application/vp+jwt`, per
[W3C vc-jose-cose](https://www.w3.org/TR/vc-jose-cose/#with-jose)).

#### Option 1 — GAIA-X Wizard (covers Steps 3 and 4 in one browser session)

Open [wizard.lab.gaia-x.eu](https://wizard.lab.gaia-x.eu/) → keep *I'll use my own private key for signing (production use)* toggled on. It then targets a real GXDCH. The flow becomes eight steps:
`Start → Legal Person → Terms & Conditions → Identity → Private key → Sign → Compliance Check → Credential`.

1. **Legal Person:** legal name, registration number + type (EORI / vatID / leiCode only in the
   UI), HQ and legal address country codes, and the **URL where the LRN VC will live** —
   type **your own** URL here, e.g. `https://your.domain.eu/gaia-x/lrn.jwt`.
2. **Terms & Conditions:** tick the checkbox — the current hash is filled in for you.
3. **Identity:** your `did:web`, the verification method (auto-resolved from your DID), and a
   URL for each of the Legal Person VC, T&C VC and Compliance VC — again **your own** URLs
   (`…/gaia-x/legal-person.jwt`, `…/gaia-x/tandc.jwt`, `…/gaia-x/compliance-vc.jwt`).
4. **Private key:** paste a PEM private key, or use a WebAuthn/FIDO2 token, or a national eID
   card. Signing with a pasted or generated key happens entirely in the browser.
5. **Sign** → three VCs. **Compliance Check** → VP built, submitted, Compliance VC returned.
6. **Credential** → click **Download all credentials**. You get **`credentials.zip`**.

#### What is in `credentials.zip`, and what to do with it

The zip holds every signed artifact of the run: the three input VCs, the Compliance VC, and
the VP.

- **Files are named by their display name, not by your URLs** — e.g.
  `Terms and conditions.jwt`, `Compliance Verifiable Credential.jwt`. **You must rename them**
  to the exact filenames in the URLs you typed in steps 1 and 3.

```bash
unzip credentials.zip -d /tmp/gx
cp "/tmp/gx/Legal registration number.jwt"          static/gaia-x/lrn.jwt
cp "/tmp/gx/<Legal Person document name>.jwt"       static/gaia-x/legal-person.jwt
cp "/tmp/gx/Terms and conditions.jwt"               static/gaia-x/tandc.jwt
cp "/tmp/gx/Compliance Verifiable Credential.jwt"   static/gaia-x/compliance-vc.jwt
```

(Check the actual names with `ls` — the Legal Person entry may appear as `Document-N.jwt`.
Identify each file by decoding its payload if in doubt: `cut -d. -f2 <file> | base64 -d`.)

nginx serves them the moment they land. Nothing is published before this step.

> **Choosing the operator.** In production mode the Wizard picks a GXDCH **at random**. To choose
> deliberately, enable **Advanced Mode** (sidebar footer) — an *Environment* selector appears in
> the header. Note it deliberately hides lab endpoints, so the Wizard cannot be pointed at the
> lab with your own key; for lab runs use [`gaia-x-dev-test.md`](gaia-x-dev-test.md).

#### Option 2 — submit the VP yourself (scriptable, recommended for renewals)

Bundle the three signed VC-JWTs into a **VP-JWT** and POST it:

```bash
VCID=$(python -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" \
       "https://your.domain.eu/gaia-x/compliance-vc.jwt")

curl -X POST \
  "https://<operator-compliance>/v2/api/credential-offers/standard-compliance?vcid=$VCID" \
  -H 'Content-Type: application/vp+jwt' \
  --data-binary @your-vp.jwt \
  -o static/gaia-x/compliance-vc.jwt \
  -w '\nHTTP %{http_code}  %{content_type}\n'
```

**The HTTP response body is the Compliance VC.**

| Outcome | HTTP | Body |
|---|---|---|
| success | **`201`**, `Content-Type: application/vc+jwt` | the Compliance VC as **one JWT string** — save it as-is |
| failure | `4xx` / `409` | JSON naming the failed check |

Before answering, the Compliance Service: resolves your `did:web` → validates each JWT signature
against your `x5u` chain → checks the chain root (and EV OID) against the Registry → checks the
T&C hash → re-checks the registration number with the Notary.

#### Production GXDCH operators

There is no single shared endpoint — each operator runs its own Compliance, Registry and Notary.
The authoritative live list is the meta-registry:

```bash
curl -s https://wizard.lab.gaia-x.eu/api/clearing-houses
```

As of 2026-09-15 it lists eight, all on `/v2`: **Aire Networks, deltaDAO, OVH, Aerospace Digital
Exchange, Pfalzkom, CISPE, circularsolution**, plus the GAIA-X lab. (Older documentation naming
T-Systems, Aruba or Arsys is out of date.) The compliance result is equivalent across operators —
pick by region and legal preference, then use **that operator's** three hosts consistently.

> The GAIA-X Association's own `registry.gaia-x.eu` / `compliance.gaia-x.eu` gateway was
> returning `421`/`503` on 2026-09-15. Use a named operator from the list above.

---

### Step 5 — Store and publish the Compliance VC

The Compliance VC is a VC-JWT — one line of text. Option 2 above writes it straight into
`static/`; Wizard users get it inside `credentials.zip` as `Compliance Verifiable Credential.jwt`
and rename it into place (Option 1, step 6). Either way it must sit at the stable, publicly
resolvable URL declared as `vcid`, because that is where every verifier will fetch it from.

#### What to host and where

**Six** static files under the same domain as your `did:web`. Every credential needs its own
resolvable URL because the `vcId` values you declared in Step 3/4 are baked into the signatures:

| File | URL path | Purpose |
|---|---|---|
| DID document | `/.well-known/did.json` | Identity anchor — resolved first by any verifier |
| Certificate chain | `/cert.pem` (must match `x5u` in `did.json`) | Trust anchor — validates VC signatures |
| Legal Registration Number VC | `/gaia-x/lrn.jwt` | Notary-signed registration number |
| Legal Person VC | `/gaia-x/legal-person.jwt` | Organisation self-description |
| Terms & Conditions VC | `/gaia-x/tandc.jwt` | Signed T&C acceptance |
| Compliance VC | `/gaia-x/compliance-vc.jwt` | Proof of participant status |

The paths under `/gaia-x/` are your choice, but they must match what you signed and must never
change afterwards. `nginx/nginx.conf` in this repo already serves all six correctly.

#### Hosting requirements

- **HTTPS is mandatory** (port 443; `did:web` permits plain HTTP only on localhost). Use any CA
  for the web server's TLS — the EV requirement applies only to the *identity* certificate.
- **`Content-Type`**: `application/json` for `did.json`,
  `application/jwt` for the `.jwt` credentials.
- **`Access-Control-Allow-Origin: *`** on all six — resolvers and the Wizard fetch them
  cross-origin from a browser.
- **Stable URLs, permanently.** A changed URL invalidates every signature that references it and
  any CES listing.

#### Renewal — this is not a one-off

| What | Interval | Consequence |
|---|---|---|
| Compliance VC | ~90 days (observed) | re-submit the VP — Option 2 above is scriptable for exactly this |
| Identity certificate | annually | new key pair → regenerate `did.json` → **re-sign every credential** |
| CES entry, if you push at all | same as Compliance VC | ~1 year retention, otherwise you drop off |

#### Optional: publish to the Credential Event Service (CES)

CES is a **notice board, not a catalogue**.

```
POST https://<ces-host>/v2/credentials-events     # CloudEvent wrapping the VC-JWT
     type: eu.gaia-x.credential                   # for gx:ComplianceCredential
GET  https://<ces-host>/v2/credentials-events     # what consumers read (public)
```

---

## Part 3: Compliance Levels

Standard Compliance is **sufficient to participate** in GAIA-X-compliant data spaces.
Optional Label Levels are not required for basic interoperability:

| Level | Requirement | Needed for RI-SCALE? |
|---|---|---|
| **Standard Compliance** | Valid Compliance VC from GXDCH | Yes — minimum |
| **Label Level 1** | GDPR compliance + eIDAS/EV cert | No (unless data space mandates it) |
| **Label Level 2** | ISO 27001 or equivalent certification | No |
| **Label Level 3** | EU-based provider + SOC2/BSI C5 | No |

---

## Minimal Working Conditions — Summary Checklist

```
[ ] Lab dry-run completed first (see gaia-x-dev-test.md) — same infrastructure, free
[ ] GXDCH operator chosen from the live meta-registry; its evsslonly flag checked
[ ] EV SSL certificate ordered, CA confirmed policy OID 2.23.140.1.1 is present
      (eIDAS is rejected by the deployed code — only with written confirmation from the operator)
[ ] Private key exportable and kept secret (not locked in a non-exportable QSCD)
[ ] Permanent public domain with HTTPS on port 443
[ ] cert.pem = full chain ENDING IN A SELF-SIGNED ROOT; last cert has subject == issuer
[ ] did.json at /.well-known/did.json, x5u pointing at the live cert.pem
[ ] DID resolves (Universal Resolver) AND trustAnchor/chain/file returns {"result":true}
[ ] Four VCs signed and each published at the exact vcId URL used when signing:
    [ ] Legal Registration Number VC (issued by the operator's Notary)
    [ ] Legal Person VC (self-signed)
    [ ] Terms & Conditions VC (self-signed, current hash)
    [ ] Compliance VC (returned by the operator's Compliance Service)
[ ] All six URLs return 200 with correct Content-Type and CORS *
[ ] (Optional) Compliance VC pushed to CES — understood that this advertises status only
```


---

## Relevant Links

**Live services**

| Resource | URL |
|---|---|
| Index of all GXDCH deployments and paths | https://catalogue.lab.gaia-x.eu/ |
| Live list of production GXDCH operators | https://wizard.lab.gaia-x.eu/api/clearing-houses |
| A registry's own config (incl. `evsslonly`) | `https://<operator-registry>/v2/configurations/credentials` |
| GAIA-X Wizard + its machine-readable reference | https://wizard.lab.gaia-x.eu/ · [`/aiDocumentation`](https://wizard.lab.gaia-x.eu/aiDocumentation) |
| Loire ontology (classes and properties) | https://docs.gaia-x.eu/ontology/development/ |

**Source code**

| Component | URL |
|---|---|
| Registry (trust-anchor / EV check) | https://gitlab.com/gaia-x/lab/compliance/gx-registry |
| Compliance Service | https://gitlab.com/gaia-x/lab/compliance/gx-compliance |
| Notary (registration numbers) | https://gitlab.com/gaia-x/lab/compliance/gaia-x-notary-registrationnumber |
| Wizard | https://gitlab.com/gaia-x/lab/gaia-x-onboarding-prototypes/gx-signing-tool |
| Credential Event Service | https://gitlab.com/gaia-x/lab/credentials-events-service |

**Policy and background:**

| Resource | URL |
|---|---|
| Join GAIA-X / AISBL membership | https://gaia-x.eu/join-gaia-x/ · https://forms.membersplatform.gaia-x.eu/ |
| Compliance Document (latest) | https://docs.gaia-x.eu/policy-rules-committee/compliance-document/latest/ |
| Trust Anchors (24.11) | https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/Gaia-X_Trust_Anchors/ |
| Trust Framework (live) | https://gaia-x.gitlab.io/policy-rules-committee/trust-framework/ |
| EU Trusted List Browser (eIDAS QTSPs) | https://eidas.ec.europa.eu/efda/tl-browser/ |
| W3C VC-JOSE-COSE (signing format) | https://www.w3.org/TR/vc-jose-cose/#with-jose |
| Demystifying GAIA-X Credentials (SCS) | https://scs.community/2024/10/15/demystifying-gaia-x-credentials/ |
