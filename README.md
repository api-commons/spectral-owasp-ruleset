# Spectral OWASP API Security Ruleset

**A curated, owned, grounded [Stoplight Spectral](https://github.com/stoplightio/spectral) ruleset for the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).**

`@api-common/spectral-owasp-ruleset` lets any team add a real **security
governance layer** to their OpenAPI linting **in one line**. It maps 22 OWASP
checks to all ten OWASP API Security categories, using only Spectral's
**built-in functions** — no custom JavaScript — so it runs anywhere Spectral
runs.

**Swagger 2.0 and OpenAPI 3.x, at parity.** Spectral auto-detects a document's
format and each check runs on the shape it applies to. Format-agnostic checks
(schema bounds, inventory metadata, global security, TRACE, external docs) carry
no `formats` tag and fire on both. Where the two specs differ structurally —
security schemes (`components.securitySchemes` vs `securityDefinitions`),
transport (`servers` vs `host`/`schemes`), and request/response bodies
(`content` media-type maps vs body parameters + response `schema`) — the 3.x
rule is tagged `formats: [oas3]` and a `-oas2` twin carries the same OWASP
grounding for Swagger 2.0. Nothing false-positives or no-ops across formats.

Why this exists: a study of 1,005 public API pipelines found only **14%** run any
security rules at all, and just **3.4%** emit SARIF for their security tooling.
This ruleset closes that gap with an adoptable, **provenanced** set of rules —
every rule names the OWASP item it defends, explains the risk, and links to the
source.

One of the [API Commons tools](https://apicommons.org/tools/), alongside
[Spectral Reporter](https://reporter.apicommons.org),
[API Validator](https://validator.apicommons.org),
[API Discovery](https://discover.apicommons.org),
[API Documentation](https://documentation.apicommons.org),
[API Reusability](https://reusability.apicommons.org), and
[MCP Install](https://install.apicommons.org).

## Grounded, owned rules

Every rule carries its provenance, modelling what a governance rule *should*
look like:

- a stable, OWASP-mapped **id** (e.g. `owasp-api1-bola-operation-security-defined`)
- a **description** of the risk it addresses
- a **message** shown on each finding
- a **severity** (`error` / `warn` / `info`)
- a **documentationUrl** deep-linking the specific OWASP API Security Top 10 item

## One-line adoption

**Remote extends** — reference the ruleset by URL, no install (point at the
raw file on your pinned tag/commit):

```yaml
# .spectral.yaml
extends:
  - "https://raw.githubusercontent.com/api-commons/spectral-owasp-ruleset/main/owasp-api-top10.yaml"
```

**Or install from npm** and extend by package name:

```bash
npm i -D @api-common/spectral-owasp-ruleset
```

```yaml
# .spectral.yaml
extends:
  - "@api-common/spectral-owasp-ruleset"
```

You can layer it on top of the Spectral OpenAPI core rules:

```yaml
extends:
  - "spectral:oas"
  - "@api-common/spectral-owasp-ruleset"
```

Then lint:

```bash
npx @stoplight/spectral-cli lint openapi.yaml
```

## What it checks — rule → OWASP item → severity

The OWASP API Security Top 10 is partly about **runtime** authorization and
abuse decisions that a static OpenAPI document cannot fully express. Where an
item is directly lintable we ship a real check; where it is not, we ship the
strongest **static proxy** we honestly can (e.g. "is auth even *declared* on
this operation?") and mark the residual **advisory**. We do not fake coverage.

The **Formats** column shows where each check applies: **both** = one
format-agnostic rule; **3.x + 2.0 twin** = a `formats: [oas3]` rule paired with a
`-oas2` twin (named below) that checks the equivalent Swagger 2.0 structure.

| Rule id | OWASP item | What it checks | Severity | Coverage | Formats |
| --- | --- | --- | --- | --- | --- |
| `owasp-api1-bola-operation-security-defined` | API1 BOLA | Every operation declares a `security` requirement (object authz needs an authenticated request) | warn | proxy | both |
| `owasp-api2-auth-security-schemes-defined` | API2 Broken Auth | `components.securitySchemes` defines ≥1 scheme | error | lintable | 3.x + `…-oas2` twin (`securityDefinitions`) |
| `owasp-api2-auth-apikey-not-in-url` | API2 Broken Auth | API-key schemes use `in: header`/`cookie`, never `query`/`path` | error | lintable | 3.x + `…-oas2` twin (2.0: `in: header` only) |
| `owasp-api2-auth-no-http-basic` | API2 Broken Auth | No HTTP Basic auth scheme | warn | lintable | 3.x + `…-oas2` twin (2.0: `type: basic`) |
| `owasp-api2-auth-oauth2-https-urls` | API2 Broken Auth | OAuth2 authorization/token/refresh URLs are `https://` | error | lintable | 3.x + `…-oas2` twin (2.0: url on the scheme, no `flows`) |
| `owasp-api3-bopla-response-schema-defined` | API3 BOPLA | Every response `content` declares a `schema` (exposed properties reviewable) | warn | proxy | 3.x + `…-oas2` twin (2.0: `responses[2xx].schema`) |
| `owasp-api3-bopla-request-schema-defined` | API3 BOPLA | Every request `content` declares a `schema` (bounds mass assignment) | warn | proxy | 3.x + `…-oas2` twin (2.0: `in: body` param `schema`) |
| `owasp-api4-resource-array-maxitems` | API4 Resource Consumption | Array schemas declare `maxItems` | warn | lintable | both |
| `owasp-api4-resource-string-maxlength` | API4 Resource Consumption | String schemas declare `maxLength` | info | lintable | both |
| `owasp-api4-resource-integer-bounds` | API4 Resource Consumption | Integer/number schemas declare `maximum` | info | lintable | both |
| `owasp-api5-bfla-global-security-defined` | API5 BFLA | A top-level `security` baseline is declared (default-deny) | warn | proxy | both |
| `owasp-api6-sensitive-flows-rate-limit-response` | API6 Sensitive Business Flows | State-changing ops document a `429` response (throttling) | info | proxy | both |
| `owasp-api7-ssrf-url-property-format` | API7 SSRF | URL-bearing properties declare `format: uri` for review | info | proxy | both |
| `owasp-api8-misconfig-https-servers` | API8 Security Misconfiguration | All `servers` URLs are `https://` | error | lintable | 3.x + `…-oas2` twin (2.0: `schemes` https/not http) |
| `owasp-api8-misconfig-no-trace-method` | API8 Security Misconfiguration | No `trace` HTTP method (blocks XST) | error | lintable | both (TRACE is 3.x-only, so vacuous on 2.0) |
| `owasp-api8-misconfig-servers-defined` | API8 Security Misconfiguration | `servers` is declared | warn | lintable | 3.x + `owasp-api8-misconfig-host-defined-oas2` (2.0: `host`) |
| `owasp-api9-inventory-info-version` | API9 Inventory | `info.version` is present | error | lintable | both |
| `owasp-api9-inventory-contact-defined` | API9 Inventory | `info.contact` is present (known owner) | warn | lintable | both |
| `owasp-api9-inventory-operation-description` | API9 Inventory | Every operation has a `description` (no shadow endpoints) | warn | lintable | both |
| `owasp-api9-inventory-operationid-defined` | API9 Inventory | Every operation has an `operationId` | warn | lintable | both |
| `owasp-api9-inventory-servers-not-example` | API9 Inventory | Server URLs are not placeholders (`example.com`/`localhost`) | warn | lintable | 3.x + `owasp-api9-inventory-host-not-example-oas2` (2.0: `host`) |
| `owasp-api10-consumption-externaldocs-https` | API10 Unsafe Consumption | `externalDocs.url` is `https://` | info | proxy | both |

**22 OWASP checks, all 10 OWASP API Security Top 10 (2023) categories covered —
on both Swagger 2.0 and OpenAPI 3.x.** 13 checks are single format-agnostic
rules; 9 are a `formats: [oas3]` rule plus a `-oas2` twin (31 rule entries in
`owasp-api-top10.yaml`).

### Lintable vs advisory, by OWASP item

| OWASP item | Static coverage |
| --- | --- |
| **API1 BOLA** | **Proxy** — object-level authz is runtime; we require every operation to *declare* auth. |
| **API2 Broken Authentication** | **Lintable** — scheme presence, API-key location, no Basic, HTTPS OAuth URLs. |
| **API3 BOPLA** | **Proxy** — property-level authz is runtime; we require request/response schemas so exposed/writable properties are reviewable. |
| **API4 Unrestricted Resource Consumption** | **Lintable** — `maxItems`/`maxLength`/`maximum` bounds on payloads. |
| **API5 BFLA** | **Proxy** — function-level authz is runtime; we require a default-deny `security` baseline. |
| **API6 Sensitive Business Flows** | **Proxy / advisory** — "sensitive" is business context; we nudge a `429` on state-changing ops. Confirm real throttling at the gateway. |
| **API7 SSRF** | **Proxy / advisory** — whether the server fetches user URLs is invisible in the spec; we flag URL-bearing inputs for `format` + allow-list review. Real defense is runtime host allow-listing. |
| **API8 Security Misconfiguration** | **Lintable** — HTTPS servers, no TRACE, servers declared. |
| **API9 Improper Inventory Management** | **Lintable** — version, contact, per-operation description/operationId, no placeholder hosts. |
| **API10 Unsafe Consumption of APIs** | **Proxy / advisory** — upstream consumption is invisible in the spec; we require HTTPS on the URLs the doc points others to. Validate third-party responses at runtime. |

The **advisory** residuals — object/property/function-level authorization
decisions (API1/API3/API5), sensitive-flow abuse (API6), SSRF allow-listing
(API7), and third-party response validation (API10) — are runtime concerns.
Enforce them in code, tests, and your gateway; this ruleset makes sure the
document at least *exposes* them for review.

## In GitHub Actions (dedicated security job + optional SARIF)

Run the OWASP ruleset as its own gate, separate from your general style lint, so
a security regression is unambiguous — and (optionally) upload SARIF so findings
show up in the repo's **Security → Code scanning** tab.

```yaml
name: API Security Governance
on: [push, pull_request]

jobs:
  owasp-api-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Fail the build on any OWASP error-severity finding.
      - name: OWASP API Security lint
        run: |
          npx @stoplight/spectral-cli lint openapi.yaml \
            -r https://raw.githubusercontent.com/api-commons/spectral-owasp-ruleset/main/owasp-api-top10.yaml

      # Optional: emit SARIF for GitHub code scanning (does not fail the job).
      - name: OWASP API Security lint (SARIF)
        if: always()
        run: |
          npx @stoplight/spectral-cli lint openapi.yaml \
            -r https://raw.githubusercontent.com/api-commons/spectral-owasp-ruleset/main/owasp-api-top10.yaml \
            -f sarif -o results.sarif || true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: owasp-api-security
```

Pin the raw URL to a tag or commit SHA (not `main`) for reproducible CI, or
install the npm package and `extends: ["@api-common/spectral-owasp-ruleset"]`
from a committed `.spectral.yaml`.

## Try it locally

The repo ships four fixtures (a 3.x pair and a Swagger 2.0 pair) and a test that
proves the ruleset actually fires on both formats:

```bash
npm install                 # installs the Spectral CLI (devDependency)
npm test                    # lints both format pairs: insecure fires all 10
                            # families, clean is silent, and no rule throws

# Or lint the fixtures by hand:
npm run lint:insecure       # 3.x: 30 findings across 20 rules, all 10 families
npm run lint:clean          # 3.x: 0 findings
npm run lint:insecure:oas2  # 2.0: 30 findings across 19 rules, all 10 families
npm run lint:clean:oas2     # 2.0: 0 findings
```

`fixtures/insecure.yaml` (OpenAPI 3.x) and `fixtures/insecure-oas2.yaml`
(Swagger 2.0) are intentionally-broken specs (API key in the query string, no
operation `security`, plaintext transport, HTTP Basic, missing body/response
schemas, missing inventory metadata). `fixtures/clean.yaml` and
`fixtures/clean-oas2.yaml` are well-governed specs that pass.

## How the rules are written

Every rule uses only Spectral's default functions —
`defined`, `truthy`, `falsy`, `pattern`, `schema`, `enumeration`, `casing`,
`length`, `alphabetical` — so there is nothing to install, audit, or trust
beyond Spectral itself. Read `owasp-api-top10.yaml`; it is heavily commented,
grouped by OWASP item, with the reasoning for each check and each advisory gap.

## TODOs (for the human picking this up)

- [ ] **Create + push the GitHub repo** `api-commons/spectral-owasp-ruleset`
      (this tree is committed locally but has **no remote** yet — no push has
      happened). Once pushed, the raw `extends` URLs above go live.
- [ ] **npm publish** `@api-common/spectral-owasp-ruleset` (scope `@api-common`
      is singular). `publishConfig.access` is already `public`; run
      `npm publish` once the repo is up.
- [ ] Consider tagging a release so the CI `extends` URL can pin a SHA/tag
      instead of `main`.
- [ ] Optionally publish a landing page under `apicommons.org/tools/` and add it
      to the tools index.

## License

[Apache-2.0](./LICENSE) — free and open. Copyright 2026 API Commons (Kin Lane).
A project of [API Evangelist](https://apievangelist.com), maintained under
[API Commons](https://apicommons.org). API Evangelist offers expert
[governance services](https://apievangelist.com/services/) when you want help
standing up API security governance.
