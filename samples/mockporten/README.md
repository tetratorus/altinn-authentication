# Test-IDP ("MockPorten")

A **synthetic-only OpenID Connect provider used as an upstream identity provider
for automated test runs** against Altinn Authentication — including in
production-like environments.

> ⚠️ **Test purpose only.** This service must never authenticate a real person.
> It only issues tokens for **synthetic (Tenor) fødselsnummer** and is gated by a
> shared access password, a feature flag, and (downstream) the chained opt-in in
> Altinn Authentication. See Altinn issues **#1409** (design) and **#1983**
> (hardening).

> 🔒 **Why is this safe to enable in production — and why can't anyone log in as a
> real person?** See **[SECURITY.md](SECURITY.md)** for the detailed rationale (the
> disjoint synthetic/real number ranges and the authoritative `RequireSyntheticPid`
> gate in Altinn Authentication).

---

## Why this exists

Automated end-to-end tests need to log in as users without a real electronic ID
(ID-porten / Feide). This service stands in as an OIDC upstream that Altinn
Authentication can route to **only when explicitly asked**, and that can **only**
mint identities for synthetic test persons. A real personal identity number can
never be authenticated here — that is the load-bearing invariant.

## Security model

Defence in depth — no single control is trusted alone:

| Layer | Control |
|---|---|
| Kill switch | `GeneralSettings:TestIdpEnabled` (default **false**). When off, every endpoint returns `404`. |
| Access | A single **shared access password** (not a per-user credential). Constant-time comparison, global lockout after N failures. |
| Identity | **Fail-closed Tenor gate**: only a well-formed synthetic fødselsnummer (month 81–92, valid mod11) is accepted. Any ordinary number or real D-number is rejected *before* a code is issued. |
| No oracle | The shared password is checked **first**. Until it is proven, the endpoint reveals nothing (bad/locked password → bare `401`/`429`, no redirect), so it cannot be probed. `pid` is accepted **only** in the POST body, never the query string. |
| Authoritative gate | Altinn Authentication independently enforces `RequireSyntheticPid` (see #1409). The check here is *defence in depth*; the authoritative synthetic-only gate lives in the auth component, so a compromised Test-IDP that asserts a real `pid` is still rejected downstream. |

### Synthetic (Tenor) fødselsnummer format

A Norwegian fnr is 11 digits: `DD MM YY III KK`. Tenor / Skatteetaten
**synthetic** test persons are marked by **adding 80 to the month**:

| Variant | Modification | Field | Test? |
|---|---|---|---|
| Ordinary fnr | — | `MM` 01–12 | **No** |
| D-number (real, foreigners) | day + 40 | `DD` 41–71 | **No** |
| H-number (internal help no.) | month + 40 | `MM` 41–52 | No |
| **Synthetic / Tenor** | **month + 80** | **`MM` 81–92** | **Yes** |

A synthetic person may additionally be a D-number (`DD` 41–71). The marker is
always month + 80. Validation is a positive, fail-closed check
(`NorwegianIdentityNumber.IsSyntheticTenorPid`): only a synthetic, mod11-valid
number passes; everything else (including any parse/format failure) is rejected.

## How it works

Standard OIDC **Authorization Code** flow, stateless (the authorization code is
itself a signed JWT; no session store):

1. A client (normally Altinn Authentication acting as upstream) sends the user to
   `GET /Authorize` with the usual OIDC parameters.
2. The user (or test automation) submits **one form**: the shared access
   password + a synthetic Tenor fødselsnummer.
3. The password is validated (constant-time, with lockout). Then the
   fnr is validated by the fail-closed Tenor gate.
4. On success an authorization `code` is issued and the browser is redirected
   back to `redirect_uri` with `code` and `state`.
5. The client exchanges the code at `POST /token` for an `id_token` /
   `access_token`.

### Endpoints

| Method & path | Purpose |
|---|---|
| `GET /Authorize` | Renders the test login form, or resolves a PAR `request_uri` (404 if disabled). |
| `POST /Authorize` | Validates shared password → Tenor gate → issues code & redirects. |
| `POST /par` | Pushes an authorization request, returns an opaque `request_uri` (404 if disabled). |
| `POST /token` | Exchanges the authorization code for tokens (404 if disabled). Also accepts `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` when `MaskinportenSettings:Enabled` is true. |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata for machine (Maskinporten-style) clients. |
| `GET /api/v1/openid/.well-known/openid-configuration` | OIDC discovery document. |
| `GET /api/v1/openid/.well-known/openid-configuration/jwks` | Signing keys (JWKS, with x5c chain). |
| `GET /` | Information page (clearly marked test-only). |

## Configuration

Bound from the `GeneralSettings` configuration section
(`GeneralSettings__Key` as environment variables; Key Vault secrets named
`GeneralSettings--Key`):

| Key | Default | Meaning |
|---|---|---|
| `TestIdpEnabled` | `false` (code) / `true` (`appsettings.json`) | Master kill switch. When false all endpoints 404. |
| `TestIdpSharedPassword` | `""` (empty ⇒ fail-closed, all logins refused) | The single shared access password. **Never committed** — provided via Key Vault. |
| `SharedPasswordMaxFailures` | `5` | Consecutive failures before lockout. |
| `SharedPasswordLockoutMinutes` | `15` | Lockout duration. |
| `JwtValidityMinutes` / `JwtSigningCertificateRolloverDelayHours` | — | Token signing/validity. |
| `IdProviderEndpoint` / `IssCode` / `IssToken` | — | Issuer / discovery URLs. |

Key Vault is added as a configuration source from `kvSetting:KeyVaultURI`
(authenticated with `DefaultAzureCredential`). A secret named
**`GeneralSettings--TestIdpSharedPassword`** binds to
`GeneralSettings:TestIdpSharedPassword` (the Key Vault config provider maps
`--` → `:`). The signing certificate is read from the same vault
(`kvSetting:MaskinPortenCertSecretId`, default `idprovider-signing-cert-1`).
When `kvSetting:KeyVaultURI` is empty (local/container runs without Azure), the
signing certificate is instead loaded from the PKCS#12 file at
`CertificateSettings:CertificatePath` / `CertificateSettings:CertificatePwd`.

### Maskinporten-style machine tokens (local runtimes)

Altinn apps obtain service-owner tokens by exchanging a Maskinporten token at
Authentication's `/exchange/maskinporten`. To exercise that path without the
real Maskinporten, Mockporten can act as an RFC 7523 JWT-bearer authorization
server. It is off by default; register synthetic clients under
`MaskinportenSettings`:

```jsonc
"MaskinportenSettings": {
  "Enabled": true,
  "Clients": [{
    "ClientId": "<client_id, used as the grant iss>",
    "OrgNo": "<synthetic org number, becomes consumer 0192:<OrgNo>>",
    "PublicJwk": "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\"}",
    "AllowedScopes": ["altinn:serviceowner/instances.read"]
  }]
}
```

The grant must be signed by the client's registered key, have `iss=ClientId`,
`aud=IssToken`, a lifetime, and only scopes in `AllowedScopes` (empty list ⇒
any). The issued token carries `iss`, `client_id`, `scope`, `consumer` and
`jti`, signed with the same certificate as the OIDC tokens.

## Using it as a client

### Via Altinn Authentication (recommended, e.g. AT22)

Altinn Authentication selects the upstream provider from the `iss` query
parameter. The provider is configured there under key `mockporten`, so append
`&iss=mockporten` to the normal authentication URL:

```
https://platform.at22.altinn.cloud/authentication/api/v1/authentication
    ?goto=<url-encoded return url>
    &iss=mockporten
```

Without `iss` the default (real) provider is used. This routes the browser to
this service's `/Authorize`, where the shared password + synthetic fnr are
entered; the rest of the OIDC handshake is automatic.

### Automated tests

1. Hold the shared access password in the CI secret store (ideally via OIDC
   workload-identity federation — no long-lived secret stored). **Never** put it
   in the repo, source, or logs.
2. Drive the flow to `/Authorize`, then **POST** the form with fields:
   - `Password` — the shared access password
   - `Pid` — a synthetic Tenor fødselsnummer (month 81–92, valid mod11)
   - the OIDC parameters round-tripped as hidden fields
3. Follow the redirect and exchange the `code` at `/token`.

The `pid` must be sent in the **POST body only** — never as a query parameter.

## Local development

`appsettings.Development.json` enables the provider and sets a throwaway dev
password:

```jsonc
"GeneralSettings": {
  "TestIdpEnabled": true,
  "TestIdpSharedPassword": "local-dev-only-change-me"
}
```

```bash
cd samples/mockporten
dotnet run --project Mockporten/Mockporten.csproj
```

## Build & test

```bash
cd samples/mockporten
dotnet build Mockporten.sln
dotnet test  Mockporten.sln
```

Unit tests (`Mockporten.Tests`) cover the load-bearing invariant: the synthetic
Tenor gate (ordinary fnr, real D-number, broken mod11, malformed input all
rejected; valid synthetic — including synthetic D-number — accepted) and the
shared-password validator (constant-time match, fail-closed when unconfigured,
lockout after N failures, counter reset on success), the single-valued `acr`
claim, and the JWT-bearer grant (disabled by default, unknown client, wrong key,
wrong audience and out-of-allow-list scope all rejected).

`Dockerfile` builds a container image (`docker build -t mockporten samples/mockporten`).

## Deployment requirements

- The app's managed identity needs **get + list secrets** on the configured
  Key Vault (separate from certificate permissions in access-policy mode).
- Create the secret `GeneralSettings--TestIdpSharedPassword` in that vault.
- Set `GeneralSettings:TestIdpEnabled = true` for the environment (already set
  in `appsettings.json`; the code default stays `false` as a fail-safe).
- The Key Vault config source loads at **startup only** — rotating the secret
  requires an app restart.

## Status & roadmap

Implemented (phases 1–2, see #1983): synthetic-only fail-closed gate, feature
flag, shared-password authentication (constant-time, lockout,
no-oracle), Key Vault wiring, test-only UI.

Not yet implemented (tracked in #1983):

- Chained opt-in: client allowlist, PAR, required `acr`/`scope`, `prompt=login`.
- PKCE (S256) enforcement and `private_key_jwt` client authentication at
  `/token`; single-use authorization codes.
- Separate `id_token` vs `access_token`; OIDC discovery/issuer/JWKS corrections.
- Observability (metrics, structured PII-free logging, alarms) and secret
  hygiene (App Insights connection string).

**Do not rely on this service for anything other than synthetic test data.**
