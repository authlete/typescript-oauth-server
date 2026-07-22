# typescript-oauth-server

The **headless OAuth/OIDC Authorization Server** in the *Externalized Login & Consent* pattern: a thin client of [Authlete 3.0](https://www.authlete.com/) on the inside, a standard OAuth/OIDC surface on the outside, with login and consent handed off to a separate UI ([`auth-ui`](https://github.com/authlete/auth-ui)).

Built on **TypeScript · Hono · `@authlete/typescript-sdk`**.

> The AS is the **headless** half of the pair — every screen a user sees during sign-in or consent is rendered by `auth-ui`. The AS owns only protocol endpoints and the redirect back to the RP.

## Quickstart

Requires an Authlete 3.0 service (see **Provisioning** below) and `auth-ui` running for the full login flow.

```bash
npm install
cp .env.example .env    # fill in the values from Configuration below
npm run dev             # → http://localhost:3000
```

Sanity checks:

```bash
curl http://localhost:3000/health
curl http://localhost:3000/.well-known/openid-configuration | jq .
```

End-to-end is exercised by `auth-ui`'s smoke harness (`auth-ui/scripts/smoke-e2e.mjs`).

## Provisioning (one-time, per Authlete service)

1. Sign up at https://us.authlete.com and create a new Authlete 3.0 service.
2. Register a test RP client in the service (Authorization Code + PKCE) for end-to-end testing.
3. Generate an ES256 key pair for the AS's interaction-protocol signing. Register the public JWK with the Authlete service's JWKS (so it shows up in `/oauth/jwks`); keep the private JWK in this AS's env as `AS_SIGNING_JWKS`.
4. Populate the AS's `.env` from the Authlete console (service id + API token + URLs).
5. `auth-ui` needs its own ES256 key pair and JWKS publication — see its setup docs.

## Configuration

Copy `.env.example` to `.env` and fill in:

| Variable | Purpose |
|---|---|
| `AUTHLETE_BASE_URL` | Authlete cluster URL (default `https://us.authlete.com`). |
| `AUTHLETE_SERVICE_ID` | Numeric service id from the Authlete console. |
| `AUTHLETE_API_TOKEN` | Service access token from the Authlete console. |
| `AS_BASE_URL` | This server's public URL and issuer identity (RPs and `auth-ui` use it). On Vercel previews, falls back to `VERCEL_URL`. |
| `AUTH_UI_URL` | Where `auth-ui` is reachable. |
| `AS_SIGNING_JWKS` | The AS's private ES256 JWKS for signing interaction-protocol JWTs; its public counterpart is registered with Authlete (surfaces in `/oauth/jwks`). |
| `AUTH_UI_JWKS_URI` | auth-ui's public JWKS, used to verify its JWTs (defaults to `${AUTH_UI_URL}/.well-known/jwks.json`). |
| `PORT` | Listen port (default `3000`). |
| `AS_CORS_ORIGINS` | Comma-separated allowlist of browser origins (e.g. the Authlete OAuth Playground). Empty disables CORS. |

Optional overrides (`AS_ISSUER_ID`, `AUTH_UI_ISSUER_ID`, `AS_SIGNING_KID`) are documented in `.env.example`.

## Deploy to Vercel

The server is a Hono app with a `default` export, which Vercel runs with zero configuration — each route becomes a Vercel Function. The AS holds no per-transaction state, so it maps cleanly onto serverless.

1. Import the GitHub repo into a Vercel project once. Every push then builds and deploys automatically, with a preview URL per pull request.
2. Set the environment variables from **Configuration** in the Vercel project (there is no `.env` file in a deployment). `AS_SIGNING_JWKS` must be the same private JWKS whose public counterpart is registered with Authlete.
3. Set `AS_BASE_URL` to your stable production domain — it is the issuer identity and must match what is registered with the Authlete service. Preview deployments fall back to their per-deploy `VERCEL_URL`, so leave `AS_BASE_URL` unset in the Preview environment if you want previews to self-configure.

`vercel.json` pins functions to a US region (`iad1`) to keep latency to the Authlete US cluster low; adjust it for your cluster.

## Endpoints

| Path | Spec | Purpose |
|---|---|---|
| `GET/POST /oauth/authorize` | OAuth 2.0, OIDC Core | Authorization endpoint — redirects to the interaction app for login + consent. |
| `POST /oauth/token` | RFC 6749 §3.2 | Token endpoint — `authorization_code`, `refresh_token`, `client_credentials`. |
| `GET/POST /oauth/userinfo` | OIDC Core §5.3 | UserInfo endpoint. |
| `POST /oauth/par` | RFC 9126 | Pushed Authorization Requests. |
| `POST /oauth/introspect` | RFC 7662 | Token introspection. |
| `POST /oauth/revoke` | RFC 7009 | Token revocation. |
| `POST /api/register` | RFC 7591 | Dynamic Client Registration. |
| `GET/PUT/DELETE /api/register/{id}` | RFC 7592 | Client registration management (read / update / delete). |
| `GET /oauth/jwks` | RFC 7517 | Service JWK Set (merges Authlete-managed keys + the AS's own interaction-protocol signing key). |
| `GET /.well-known/openid-configuration` | OIDC Discovery | OIDC discovery metadata. |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | OAuth AS metadata. |
| `GET  /api/authorizations/{id}` | [Interaction Protocol](./INTERACTION_PROTOCOL.md) | Interaction app fetches in-flight authorization state (JWT-bearer auth). |
| `POST /api/authorizations/{id}/decision` | [Interaction Protocol](./INTERACTION_PROTOCOL.md) | Interaction app submits the user's decision (JWT-bearer auth). |
| `GET  /authorizations/{id}/resume` | [Interaction Protocol](./INTERACTION_PROTOCOL.md) | Browser returns here from the interaction app; the AS calls Authlete `issue`/`fail` and redirects the RP. |

## Interaction protocol

The AS hands off all user-facing interactions (sign-in, consent, MFA, …) to `auth-ui` over the **Interaction Protocol** — a bilateral signed-JWT contract.

- Full spec: **[`INTERACTION_PROTOCOL.md`](./INTERACTION_PROTOCOL.md)** — JWT envelope, verification rules, URL surface, per-operation claim shapes.
- Authentication is a per-request signed JWT in `Authorization: Bearer`. Each peer publishes a JWKS; each verifies the other's signatures against the published keyset. No OAuth-client registration is used by this protocol.
- **Channel modes:** **back-channel** (server-to-server) is shipped and is what runs today. A **front-channel** (browser-mediated, for dev/test setups where the AS can't reach `auth-ui` directly) is specified in the protocol but **not yet implemented** — see Roadmap.

## How it works — Externalized Login & Consent

Decouple authentication and consent from the AS. The AS stays a thin, spec-compliant surface holding **no per-transaction state**; `auth-ui` owns everything the user touches.

### Roles

| Component | Role |
|---|---|
| **RP** | the app requesting access: starts `/authorize`, receives tokens. Integrates with the AS using standard OAuth/OIDC. |
| **AS** (this repo) | OAuth/OIDC endpoints; delegates login/consent to `auth-ui`; owns the redirect back to the RP. |
| **auth-ui** | the UI the user actually sees: authenticates the user, collects consent, records the decision against an opaque **authorization id**. |
| **Authlete** | protocol engine; owns per-transaction state; only the AS calls it. |

### State model

- **Authlete owns per-transaction state.** Each in-flight authorization is an Authlete ticket; auth result, consent decision, and request context all hang off it.
- **The AS holds none.** The browser carries only an opaque **authorization id**; the AS exchanges it with Authlete for context as needed. (One transitional exception is documented inline in `src/userstore.ts`.)
- `auth-ui` holds the user session, not the OAuth transaction.

### Trust boundaries

```
 ┌──────────┐    OAuth / OIDC    ┌──────────┐  interaction protocol   ┌──────────┐
 │   RP     │ ─────────────────→ │    AS    │ ───(mutual JWT)───────→ │ auth-ui  │
 └──────────┘                    │  (this)  │                          │          │
                                 │          │   @authlete/sdk          │          │
                                 │          │ ─────────────────→  Authlete         │
                                 └──────────┘                          └─────┬────┘
                                                                             │
                                                  (future) federated IdPs · MFA · passkeys
```

- **AS ↔ RPs:** standard OAuth/OIDC. One spec, no surprises.
- **AS ↔ auth-ui:** the [Interaction Protocol](./INTERACTION_PROTOCOL.md) — bilateral signed JWT (see above).
- **AS ↔ Authlete:** the Authlete SDK over HTTPS.
- **The AS never federates outward** — no social login, no upstream OIDC, no SAML. All of that lives in `auth-ui`.

### Why this pattern

- **Implementation-portable.** A thin Authlete client with no user state can be this Node service, a sidecar, a reverse-proxy plugin, or live inside an API gateway / edge worker.
- **Authentication and consent evolve in `auth-ui`** — MFA, passkeys, federation, step-up, per-claim consent, RAR, grant management — none of which the AS ever sees.
- **Independent deploy and scale.** Two services, one narrow protocol between them.

This separation matches the architecture Authlete is designed around: the engine owns the spec and per-transaction state; you own the user experience.

## Federation mode (advanced)

The AS also supports [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html), letting it act as a federation-participating OpenID Provider under a trust anchor. **This is opt-in** — operators who don't enable it on the Authlete service never see federation behavior; the routes return `404` and the discovery doc doesn't advertise them.

### What it adds

Two new endpoints, paths matching [java-oauth-server](https://github.com/authlete/java-oauth-server):

| Path | Method | Purpose |
|---|---|---|
| `GET /.well-known/openid-federation` | GET | Signed **entity configuration** (entity statement JWT) declaring the OP's metadata, JWKS, and `authority_hints`. |
| `POST /api/federation/register` | POST | **Explicit client registration.** Accepts either `application/entity-statement+jwt` (the RP's entity configuration) or `application/trust-chain+json` (a JSON array of entity statement JWTs). |

**Automatic registration** is fully transparent — when an RP arrives at `/oauth/authorize` with a federation entity ID as `client_id`, Authlete validates the trust chain inline and registers the client. No additional AS-side code.

The `.well-known/openid-configuration` document automatically gains the federation fields (`federation_registration_endpoint`, `client_registration_types_supported`, `signed_jwks_uri`, etc.) when federation is enabled on the Authlete service.

### Enabling it

All configuration lives on the **Authlete service** — the AS picks it up automatically with no env changes. In the Authlete console:

1. **Client Registration** tab — enable Federation Support; check `Automatic`, `Explicit`, or both; set Registration Endpoint to `<AS_BASE_URL>/api/federation/register`.
2. **Entity Configuration** tab — set Organization Name; add Authority Hints (the trust anchor's entity ID); optionally set Configuration Duration.
3. **Trust Anchors** tab — add each trust anchor as `{ Entity Identifier, JWKS }`.
4. **Federation JWKS** — supply an ES256 keypair for signing entity statements.

## Roadmap

The AS surface grows with the OAuth/OIDC spec; authentication features grow in `auth-ui`.

### OAuth/OIDC surface

- **FAPI 2.0** — DPoP, JAR, JARM (PAR already shipped).
- **mTLS client auth** (`tls_client_auth`).
- **CIBA** (`urn:openid:params:grant-type:ciba`).
- **RP-Initiated Logout / Front- and Back-channel Logout**.
- **Grants Management API**.

### Interaction protocol

- **Per-claim consent forwarding** — plumb `consentedClaims` end-to-end at `/auth/authorization/issue` so `/userinfo` honors precisely what the user agreed to release (see the `TODO(claims-leakage)` block in `src/routes/userinfo.ts`).
- **Front-channel transport implementation** — a JWT-via-browser-redirect carrier for dev/test deployments where the interaction app isn't directly reachable from the AS. The contract is already specified in [`INTERACTION_PROTOCOL.md`](./INTERACTION_PROTOCOL.md); only back-channel is shipped today.
