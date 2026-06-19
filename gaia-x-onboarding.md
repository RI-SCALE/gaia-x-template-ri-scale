# GAIA-X Onboarding Guide
> For RI-SCALE participants intending to use GAIA-X as a data space

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
   Step 1–2                  Step 3–4                    Step 3–4         [Host VC as static JSON]
  (manual / cert)         (GAIA-X Wizard)            (GAIA-X Wizard)              ↓
                                                                       [(Optional) Push URL to CES]
```

**Where does the GAIA-X Wizard fit?** Steps 3 and 4 are handled entirely by the GAIA-X Wizard:
filling in org details, signing the three credentials (including the Notary call for the
Legal Registration Number), packaging the VP, and submitting to GXDCH — all in one guided
browser session. The outputs (signed VCs + Compliance VC) can be downloaded as JSON files.

**What remains outside the Wizard:** obtaining the certificate (Step 1), setting up the
`did:web` endpoint and hosting the Compliance VC (Step 2 and Step 5).

---

### Step 1 — Obtain a qualifying X.509 certificate

GXDCH validates the trust anchor of your certificate chain. **The decisive requirement is 
whether its issuing CA resolves to a trust anchor listed
in the [GAIA-X Registry](https://registry.gaia-x.eu/).** Always confirm your chosen CA is a
registered trust anchor *before* purchasing — the GXDCH trust-anchor checker (see Step 4 /
README) verifies this against a live `cert.pem`.

| Environment | Accepted CAs |
|---|---|
| **Production** | A cert whose chain anchors to a CA in the GAIA-X Registry — in practice an **eIDAS qualified certificate** (preferred), or an **EV SSL certificate** *only where no eIDAS alternative is registered for your country* |
| **Development / test** | Any CA, including Let's Encrypt |

> **Important nuance on EV SSL.** Per the [GAIA-X Trust Anchors document](https://docs.gaia-x.eu/policy-rules-committee/compliance-document/24.11/Gaia-X_Trust_Anchors/),
> an EV SSL certificate is accepted *only if there is no alternative specified in the GAIA-X
> Registry for the country of business registration*. For an EU/EEA organisation an eIDAS QTSP
> almost always exists in the Registry, so EV SSL may be **rejected** for exactly that audience.
> EU research infrastructures should plan on an **eIDAS Qualified Certificate for Electronic Seal**.


#### Option A — eIDAS Qualified Certificate (EU-preferred)

**What it is:** A certificate issued under the eIDAS Regulation (EU 910/2014) by a state-supervised
Qualified Trust Service Provider (QTSP). For legal persons (organisations, not individuals), the
relevant type is a **Qualified Certificate for Electronic Seal**, which binds the certificate to the
legal entity rather than a natural person.

**Legal weight:** Carries the strongest legal presumption in all EU/EEA member states — equivalent
to a wet signature in terms of evidentiary value.

**How to obtain:**
1. Find a QTSP on the [EU Trusted List Browser](https://eidas.ec.europa.eu/efda/tl-browser/) —
   filter by country and service type "QCert for eSeal". Major cross-border providers include
   GlobalSign, DigiCert, and Sectigo; each EU member state also has national QTSPs.
2. Submit a certificate application to the chosen QTSP. They will require:
   - Proof of legal existence (company registration extract, not older than 3–6 months)
   - Official registration number (e.g., company/VAT/EUID number)
   - Authorised representative identity verification (passport or national ID)
3. The QTSP verifies the legal entity's identity (in-person or remotely via video call depending
   on provider and country).
4. Certificate is issued — typically delivered as a PKCS#12 file or on a hardware token (QSCD).


#### Option B — EV SSL Certificate (Extended Validation)

**What it is:** An SSL/TLS certificate issued to a domain owner following the CA/Browser Forum
Extended Validation (EV) guidelines. Unlike DV (Domain Validation) or OV (Organisation Validation)
certificates, EV certificates require verified proof of the organisation's legal existence and its
operational control of the domain.

**Legal weight:** Not a formal EU legal instrument (no eIDAS backing), but the vetting depth is
accepted by GXDCH as a sufficient trust anchor for GAIA-X Standard Compliance.

**How to obtain:**
1. Purchase from any CA/Browser Forum-member CA (DigiCert, Sectigo, GlobalSign, etc.).
2. The CA conducts a vetting process that includes:
   - Verified legal existence and good standing (checked against official government registries)
   - Physical address verification (no P.O. Boxes accepted)
   - Domain control verification (DNS, CNAME, or HTTP challenge)
   - Phone call to the organisation's verified main number to confirm the signing authority
3. Certificate is issued as a PKCS#12 file with the domain and organisation name embedded.


#### Which to choose

| Criteria | eIDAS Qualified | EV SSL |
|---|---|---|
| Accepted by GXDCH for Standard Compliance | Yes | Conditional — only if no eIDAS alternative is registered for your country |
| EU legal presumption | Yes | No |
| Acquisition time | 1–4 weeks | 1–5 days |
| Typical cost | €100–400/yr | €100–300/yr |
| Preferred for EU research organisations | Yes | Fallback (may be rejected — see nuance above) |

For an RI operating within the European Research Infrastructure ecosystem, **eIDAS is the
recommended choice** — it aligns with EU data sovereignty principles and may be required by
stricter GAIA-X Label Levels in the future. EV SSL is a faster fallback if eIDAS procurement
is a bottleneck.

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

The private key is **never placed in `did.json`** — it stays secret and is only used inside
the GAIA-X Wizard (client-side, in-browser) to sign the credentials.

**Validate before you proceed.** Once `did.json` and `cert.pem` are served over public HTTPS,
confirm the DID resolves and the chain is a valid trust anchor — this catches the most common
onboarding failures *before* a Wizard run:

- **Universal Resolver** (`https://dev.uniresolver.io/`) and **DID Lint** (`https://did-lint.org/`) —
  resolve `did:web:your.domain.eu` and confirm the `verificationMethod`, `JsonWebKey2020` type,
  and `x5u` are present and correct. Both tools are recommended by the GAIA-X Compliance Document.
- **GXDCH trust-anchor checker** — `https://registrationnumber.notary.lab.gaia-x.eu/v1/api/trustAnchor/chain?vcUrl=https://your.domain/cert.pem`
  (use the production notary host of your chosen GXDCH operator for production certificates).

---

### Step 3 — Author and sign the required Verifiable Credentials

Three credentials must be produced. All must be signed with the private key that corresponds to
the certificate in your DID document.

**Recommended path: GAIA-X Wizard** — a hosted UI at `wizard.lab.gaia-x.eu` that generates,
signs, and submits everything in a single guided flow. No code required. See the walkthrough
in Step 4 below, which covers Steps 3 and 4 together as the Wizard does not separate them.

**Manual / programmatic path:** Described below for reference. Use if you need to automate or
integrate signing into a pipeline. Alternative tooling: [gaiax-credentials-tool](https://github.com/fundacionctic/gaiax-credentials-tool)
(CLI), [gx-agent](https://github.com/Sphereon-Opensource/gx-agent) (Node.js agent).

---

#### Required credentials

##### 3a. Legal Registration Number VC
A claim about your official registration identifier. Mandatory field:

| Field | Value |
|---|---|
| `gx:legalRegistrationNumber` | One of: EORI, LEI, EUID, VAT ID |

This VC is typically **counter-signed by a GXDCH Notary Service** (i.e., not self-signed) to
confirm the registration number is valid. The GXDCH Notary endpoint accepts the number and
returns a signed credential. The Wizard handles this automatically.

##### 3b. Legal Person VC
Describes your organisation. References the Legal Registration Number VC.

| Field | Description |
|---|---|
| `gx:legalName` | Registered legal name |
| `gx:legalRegistrationNumber` | Reference to the credential above |
| `gx:headquarterAddress` | `{ "gx:countrySubdivisionCode": "XX-YY" }` (ISO 3166-2) |
| `gx:legalAddress` | Same structure as above |

##### 3c. Terms & Conditions VC
A signed declaration of acceptance of the GAIA-X Terms & Conditions.

| Field | Value |
|---|---|
| `gx:URL` | Published T&C URL (from GAIA-X Registry) |
| `gx:hash` | SHA-256 hash of the current T&C document |

The current hash must match the value published in the GAIA-X Registry — it changes with each
Trust Framework release. The Wizard always uses the current value automatically.

---

#### Signing format

In the current GAIA-X release (Loire, 24.11 / 25.10) credentials are signed as **Enveloped
Verifiable Credentials (EVC)** — a VC Data Model credential wrapped in a JOSE/JWS envelope
(i.e. a signed JWT carrying the VC payload), using the key declared in your DID document. The
`kid` header must reference the verification method ID from your `did.json`, e.g.
`did:web:your-domain.eu#key-1`.

Signing algorithm: RS256 (RSA) or ES256 (EC) — must match the key type in your DID document.

---

### Step 4 — Package into a Verifiable Presentation and submit to GXDCH

A **Verifiable Presentation (VP)** is simply a JSON-LD wrapper that bundles multiple VCs together.
The GXDCH Compliance Service accepts a VP containing all three credentials from Step 3.

#### Recommended: use the GAIA-X Wizard (covers Steps 3 and 4 in one flow)

1. Go to [wizard.lab.gaia-x.eu](https://wizard.lab.gaia-x.eu/) and open the **Onboarding** tab.
2. **Fill in organisation details:** legal name, registration number, headquarters country, legal address country.
3. **Accept Terms & Conditions** by ticking the checkbox — the Wizard fetches the current T&C hash from the registry automatically.
4. **Provide your private key** (PKCS#1 RSA PEM format). The Wizard never stores this; it is used client-side only to sign the credentials in the browser.
5. **Configure your DID:** enter your `did:web` identifier and the verification method ID from your `did.json`. The Wizard will use these as the `issuer` and `kid` fields in the signed JWTs.
6. Click **Sign** — the Wizard creates and signs all three VCs (Legal Registration Number, Legal Person, T&C). It calls the GXDCH Notary to counter-sign the Legal Registration Number VC automatically.
7. The signed VCs appear on-screen and are saved to the **Local Wallet** (browser IndexedDB). You can download them as JSON at this point.
8. With all three VCs in the Holder section, **select a GXDCH operator** from the dropdown, then click **Submit to compliance** — the Wizard packages them into a VP and POSTs it to that operator's Compliance Service.
9. If validation passes, the GXDCH returns a **Compliance VC** signed by the Clearing House. Save it to the Local Wallet and download the JSON.

#### Manual: packaging a VP by hand

If you are not using the Wizard, package the three signed VCs into a VP manually:

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    "<LegalRegistrationNumberVC as JWT string>",
    "<LegalPersonVC as JWT string>",
    "<TermsAndConditionsVC as JWT string>"
  ]
}
```

POST to the Compliance Service of one GXDCH instance. Example against the dev/test instance:

```
POST https://compliance.lab.gaia-x.eu/v2/api/participant/verify
Content-Type: application/json

<VP JSON body>
```

> The exact path and API version drift between releases. **Confirm the current path from your
> chosen GXDCH operator's Swagger UI** (each operator exposes one at its own `…/docs` endpoint).
> The Wizard always targets the correct current
> endpoint — which is why it is the recommended route for submission.

The Compliance Service:
1. Resolves your `did:web` → fetches `did.json`.
2. Validates all three JWT signatures against your X.509 trust chain.
3. Checks the T&C hash against the current registry value.
4. Checks the Legal Registration Number against the GXDCH Notary.
5. If all pass → returns a **Compliance VC** signed by the Clearing House.

**GXDCH instances (production):** there is *no single shared endpoint*. Production GXDCH are
operated independently by several providers (e.g. T-Systems, Aruba, Aire Networks, Arsys,
Proximus), and **each runs its own Compliance, Registry, and Notary hosts**. You choose one
operator — in the Wizard this is a dropdown at the submission step. Pick by region/legal
preference; the compliance result is equivalent across operators.

**GXDCH instances (development / testing):** `https://compliance.lab.gaia-x.eu` (with the
matching `registry.lab.gaia-x.eu` and `registrationnumber.notary.lab.gaia-x.eu`).

---

### Step 5 — Store and publish the Compliance VC

The Compliance VC is a plain JSON document. Once
downloaded from the Wizard it must be hosted at a stable, publicly resolvable HTTPS URL.
Any party wanting to verify your GAIA-X status will fetch it from that URL.

#### What to host and where

Three files must be publicly accessible under the same domain you used for your `did:web`:

| File | Required URL path | Purpose |
|---|---|---|
| DID document | `https://<domain>/.well-known/did.json` | Identity anchor — resolved first by any verifier |
| Certificate chain | `https://<domain>/cert.pem` (or any stable path matching `x5u` in `did.json`) | Trust anchor — validates VC signatures |
| Compliance VC | `https://<domain>/gaia-x/compliance-vc.json` (path is your choice) | Proof of GAIA-X participant status |

All three are static files.

#### Hosting requirements

- **HTTPS is mandatory** — use any CA for TLS (Let's Encrypt is fine for this purpose; the eIDAS/EV requirement applies only to the *identity* certificate, not to the web server TLS certificate).
- **`Content-Type: application/json`** on `did.json` and `compliance-vc.json`.
- **`Access-Control-Allow-Origin: *`** on all three endpoints — DID resolvers and GXDCH fetch these cross-origin from the browser.
- **Stable URL** — once you publish the Compliance VC URL (e.g. to the CES), changing it invalidates your listing. Treat the URL as permanent.

#### Hosting options

Any web server or object storage that supports HTTPS and custom response headers works:

| Option | Notes |
|---|---|
| **nginx / Apache** | Serve a local directory; configure CORS headers explicitly |
| **Caddy** | Auto-provisions Let's Encrypt TLS; CORS headers via one-liner config |
| **AWS S3 / Azure Blob / GCS** | Enable static website hosting + CORS policy on the bucket |
| **GitHub Pages** | Free, HTTPS automatic; CORS `*` is already set by default |
| **Any existing HTTPS web server** | If the RI already runs one, a subdirectory or subdomain is sufficient |

The file content itself does not change after issuance — no dynamic server logic is required.

#### Optional: publish to the Credential Event Service (CES)

The GAIA-X **Credential Event Service (CES)** is a federated directory that stores
*resolvable URLs* of Compliance VCs (not the credential content itself). Pushing to CES makes
your participant status discoverable through GAIA-X-connected catalogues.

- Push is voluntary — it is not required for compliance status.
- When pushed, CES consumers resolve your URL and fetch the credential from your HTTPS endpoint.
- The GAIA-X Wizard performs the CES push automatically via the **Share** button after submission.

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
[ ] Public domain with HTTPS (port 443) — one domain is sufficient for all files
[ ] eIDAS Qualified Certificate for Electronic Seal (preferred) OR EV SSL certificate
[ ] Corresponding private key (kept secret; used only for VC signing in the Wizard)
[ ] X.509 cert chain hosted as PEM at a stable public URL
[ ] did.json hosted at https://<domain>/.well-known/did.json (references cert via x5u/x5c)
[ ] Three VCs authored, signed, and validated via GAIA-X Wizard:
    [ ] Legal Registration Number VC (counter-signed by GXDCH Notary)
    [ ] Legal Person VC (self-signed)
    [ ] Terms & Conditions VC (self-signed)
[ ] Compliance VC received from GXDCH Compliance Service (via Wizard submission)
[ ] Compliance VC hosted as static JSON at a stable public HTTPS URL
[ ] (Optional) Compliance VC URL pushed to Credential Event Service via Wizard "Share" button
```


---

## Relevant Links

| Resource | URL |
|---|---|
| GAIA-X Join Gaia-X | https://gaia-x.eu/join-gaia-x/ |
| GAIA-X Membership Application Form | https://forms.membersplatform.gaia-x.eu/ |
| Compliance Document 24.06 | https://gaia-x.eu/wp-content/uploads/2024/09/Compliance-Document_24.06.pdf |
| How to become conformant (PDF) | https://gaia-x.eu/wp-content/uploads/2024/10/How-to-become-a-Gaia-X-conformant-Service.pdf |
| Trust Framework (live) | https://gaia-x.gitlab.io/policy-rules-committee/trust-framework/gaia-x_trust_framework/ |
| Compliance Process (live) | https://gaia-x.gitlab.io/policy-rules-committee/compliance-document/Process/ |
| Participant ontology | https://gaia-x.gitlab.io/policy-rules-committee/trust-framework/participant/ |
| GAIA-X Wizard | https://wizard.lab.gaia-x.eu/ |
| GXDCH dev Compliance Service | https://compliance.lab.gaia-x.eu |
| Credential Event Service (GitLab) | https://gitlab.com/gaia-x/lab/credentials-events-service |
| Demystifying GAIA-X Credentials (SCS) | https://scs.community/2024/10/15/demystifying-gaia-x-credentials/ |
| ICAM credential format (24.07) | https://docs.gaia-x.eu/technical-committee/identity-credential-access-management/24.07/credential_format/ |
