# typescript-oauth-server

The **headless OAuth/OIDC Authorization Server** in the _Externalized Login & Consent_ pattern: a thin client of [Authlete 3.0](https://www.authlete.com/) on the inside, a standard OAuth/OIDC surface on the outside, with login and consent handed off to a separate UI ([`auth-ui`](https://github.com/authlete/auth-ui)).

Built on **TypeScript · Hono · `@authlete/typescript-sdk`**.

> The AS is the **headless** half of the pair — every screen a user sees during sign-in or consent is rendered by `auth-ui`. The AS owns only protocol endpoints and the redirect back to the RP.

## Quickstart

Requires an Authlete 3.0 service (see **Provisioning** below) and `auth-ui` running for the full login flow.

```bash
npm install
cp .env.example .env    # fill in the values from Configuration below
npm run keygen >> .env  # generate the AS_SIGNING_JWKS interaction signing key
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
3. Generate the AS's interaction-protocol signing key with `npm run keygen`; keep the printed private JWKS in this AS's env as `AS_SIGNING_JWKS`. Its public counterpart is published at `/.well-known/jwks.json` for `auth-ui` to verify the AS's signed messages — no Authlete registration needed.
4. Populate the AS's `.env` from the Authlete console (service id + API token + URLs).
5. `auth-ui` needs its own ES256 key pair and JWKS publication — see its setup docs.

## Configuration

Copy `.env.example` to `.env` and fill in:

| Variable              | Purpose                                                                                                                                                                          |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AUTHLETE_BASE_URL`   | Authlete cluster URL (default `https://us.authlete.com`).                                                                                                                        |
| `AUTHLETE_SERVICE_ID` | Numeric service id from the Authlete console.                                                                                                                                    |
| `AUTHLETE_API_TOKEN`  | Service access token from the Authlete console. Needs `use_service`; the connected-apps revoke also needs `modify_client`.                                                       |
| `AS_BASE_URL`         | This server's public URL — its issuer identity (RPs and `auth-ui` use it). On Vercel previews, falls back to `VERCEL_URL`.                                                       |
| `AUTH_UI_URL`         | Where `auth-ui` is reachable — its identity and JWKS (`/.well-known/jwks.json`) are derived from this.                                                                           |
| `AS_SIGNING_JWKS`     | The AS's private ES256 JWKS for signing interaction-protocol JWTs to `auth-ui`; its public counterpart is published at `/.well-known/jwks.json`. Generate with `npm run keygen`. |
| `PORT`                | Listen port (default `3000`).                                                                                                                                                    |
| `CORS_ORIGINS`        | Comma-separated allowlist of browser origins (e.g. the Authlete OAuth Playground). Empty disables CORS.                                                                          |

## Deploy to Vercel

The server is a Hono app with a `default` export, which Vercel runs with zero configuration — each route becomes a Vercel Function. The AS holds no per-transaction state, so it maps cleanly onto serverless.

1. Import the GitHub repo into a Vercel project once. Every push then builds and deploys automatically, with a preview URL per pull request.
2. Set the environment variables from **Configuration** in the Vercel project (there is no `.env` file in a deployment). `AS_SIGNING_JWKS` is the AS's interaction signing key; its public counterpart is served at `/.well-known/jwks.json`.
3. Set `AS_BASE_URL` to your stable production domain — it is the issuer identity and must match what is registered with the Authlete service. Preview deployments fall back to their per-deploy `VERCEL_URL`, so leave `AS_BASE_URL` unset in the Preview environment if you want previews to self-configure.

`vercel.json` pins functions to a US region (`iad1`) to keep latency to the Authlete US cluster low; adjust it for your cluster.

## Endpoints

| Path                                          | Spec                                                                         | Purpose                                                                                                                                  |
| --------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `GET/POST /oauth/authorize`                   | OAuth 2.0, OIDC Core                                                         | Authorization endpoint — redirects to the interaction app (with a signed interaction token) for login + consent.                         |
| `POST /oauth/token`                           | RFC 6749 §3.2                                                                | Token endpoint — `authorization_code`, `refresh_token`, `client_credentials`.                                                            |
| `GET/POST /oauth/userinfo`                    | OIDC Core §5.3                                                               | UserInfo endpoint.                                                                                                                       |
| `POST /oauth/par`                             | RFC 9126                                                                     | Pushed Authorization Requests.                                                                                                           |
| `POST /oauth/introspect`                      | RFC 7662                                                                     | Token introspection.                                                                                                                     |
| `POST /oauth/revoke`                          | RFC 7009                                                                     | Token revocation.                                                                                                                        |
| `POST /api/register`                          | RFC 7591                                                                     | Dynamic Client Registration.                                                                                                             |
| `GET/PUT/DELETE /api/register/{id}`           | RFC 7592                                                                     | Client registration management (read / update / delete).                                                                                 |
| `GET/DELETE /api/gm/{grantId}`                | [Grant Management for OAuth 2.0](https://openid.net/specs/fapi-grant-management.html) | Grant Management — query (`GET`) or revoke (`DELETE`) a grant. Bearer-authenticated with the grant's access token.                        |
| `GET /oauth/jwks`                             | RFC 7517                                                                     | OAuth JWK Set — the service's token-signing keys (Authlete-managed).                                                                     |
| `GET /.well-known/jwks.json`                  | [Interaction Protocol](./INTERACTION_PROTOCOL.md)                            | The AS's interaction-protocol public key, for `auth-ui` to verify the AS's signed messages.                                              |
| `GET /.well-known/openid-configuration`       | OIDC Discovery                                                               | OIDC discovery metadata.                                                                                                                 |
| `GET /.well-known/oauth-authorization-server` | RFC 8414                                                                     | OAuth AS metadata.                                                                                                                       |
| `GET /.well-known/openid-federation`          | [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) | Signed entity configuration. `404` unless federation is enabled on the Authlete service.                                                 |
| `POST /api/federation/register`               | [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) | Explicit client registration (`entity-statement+jwt` or `trust-chain+json`). `404` unless federation is enabled on the Authlete service. |
| `GET  /api/authorizations/{id}`               | [Interaction Protocol](./INTERACTION_PROTOCOL.md)                            | Interaction app fetches in-flight authorization state (JWT-bearer auth).                                                                 |
| `POST /api/authorizations/{id}/outcome`       | [Interaction Protocol](./INTERACTION_PROTOCOL.md)                            | Interaction app reports an interaction's outcome (JWT-bearer auth).                                                                      |
| `GET  /authorizations/{id}/resume`            | [Interaction Protocol](./INTERACTION_PROTOCOL.md)                            | Browser returns here from the interaction app; the AS calls Authlete `issue`/`fail` and redirects the RP.                                |
| `GET/DELETE /api/authorized-apps`             | [Interaction Protocol](./INTERACTION_PROTOCOL.md)                            | Connected-apps management — the interaction app lists (`GET`) or revokes (`DELETE`) the apps a subject has granted (JWT-bearer auth). Revoke needs a token with `modify_client`. |

## Interaction protocol

The AS hands off all user-facing interactions (sign-in, consent, MFA, …) to `auth-ui` over the **Interaction Protocol** — a bilateral signed-JWT contract.

- Full spec: **[`INTERACTION_PROTOCOL.md`](./INTERACTION_PROTOCOL.md)** — JWT envelope, verification rules, URL surface, per-operation claim shapes.
- Authentication is a per-request signed JWT in `Authorization: Bearer`. Each peer publishes a JWKS; each verifies the other's signatures against the published keyset. No OAuth-client registration is used by this protocol.
- All server-to-server: both peers must be network-reachable to each other.

## How it works — Externalized Login & Consent

Decouple authentication and consent from the AS. The AS stays a thin, spec-compliant surface holding **no per-transaction state**; `auth-ui` owns everything the user touches.

### Roles

| Component          | Role                                                                                                                                  |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| **RP**             | the app requesting access: starts `/authorize`, receives tokens. Integrates with the AS using standard OAuth/OIDC.                    |
| **AS** (this repo) | OAuth/OIDC endpoints; delegates login/consent to `auth-ui`; owns the redirect back to the RP.                                         |
| **auth-ui**        | the UI the user actually sees: authenticates the user, collects consent, records the decision against an opaque **authorization id**. |
| **Authlete**       | protocol engine; owns per-transaction state; only the AS calls it.                                                                    |

### State model

- **Authlete owns per-transaction state.** Each in-flight authorization is an Authlete ticket; auth result, consent decision, and request context all hang off it.
- **The AS holds none.** The browser carries only an opaque **authorization id**; the AS exchanges it with Authlete for context as needed.
- `auth-ui` holds the user session, not the OAuth transaction.

### Trust boundaries

```
┌────┐   OAuth / OIDC   ┌───────────┐   interaction protocol   ┌─────────┐
│ RP │ ───────────────→ │ AS (this) │ ←──── (mutual JWT) ─────→ │ auth-ui │
└────┘                  └─────┬─────┘                           └────┬────┘
                              │ @authlete/typescript-sdk             │
                              ↓                                      ↓
                        ┌──────────┐                  (future) federated IdPs ·
                        │ Authlete │                        MFA · passkeys
                        └──────────┘
```

- **AS ↔ RPs:** standard OAuth/OIDC. One spec, no surprises.
- **AS ↔ auth-ui:** the [Interaction Protocol](./INTERACTION_PROTOCOL.md) — bilateral signed JWT (see above).
- **AS ↔ Authlete:** the Authlete SDK over HTTPS.
- **The AS never federates outward** — no social login, no upstream OIDC, no SAML. All of that lives in `auth-ui`.

### Why this pattern

- **Implementation-portable.** A thin Authlete client with no user state can be this Node service, a sidecar, a reverse-proxy plugin, or live inside an API gateway / edge worker.
- **Authentication and consent evolve in `auth-ui`** — MFA, passkeys, federation, step-up, per-claim consent, RAR — none of which the AS ever sees.
- **Independent deploy and scale.** Two services, one narrow protocol between them.

This separation matches the architecture Authlete is designed around: the engine owns the spec and per-transaction state; you own the user experience.
