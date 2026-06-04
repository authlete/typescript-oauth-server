# typescript-oauth-server

The **headless OAuth/OIDC Authorization Server** in the *Externalized Login & Consent* pattern. A thin client of [Authlete 3.0](https://www.authlete.com/) on the inside, a standard OAuth/OIDC surface on the outside, with login and consent handed off to a separate UI (`auth-ui`).

Built on **TypeScript · Hono · `@authlete/typescript-sdk`**.

> This is the AS half of the pair. **The AS is headless** — every screen a user sees during sign-in or consent is rendered by `auth-ui`. The AS only owns protocol endpoints and the redirect back to the RP.

## Externalized Login & Consent Pattern

**Intent.** Decouple user authentication and consent from the OAuth/OIDC Authorization Server. The AS stays a thin, spec-compliant surface; a separate UI application (`auth-ui`) owns everything the user touches. The AS holds no per-transaction state.

### Roles

| Component | Responsibility | What it sees |
|---|---|---|
| **Relying Party (RP)** | Initiates `/authorize`; receives code/tokens. | Only the AS. |
| **Authorization Server (AS) — this repo** | OAuth/OIDC endpoints (`/authorize`, `/token`, `/userinfo`, `/par`, `/introspect`, `/revoke`, `/jwks`, `.well-known/*`). Delegates user-facing flow to `auth-ui`; owns the final redirect back to the RP. | RP, Authlete, `auth-ui` — never external IdPs. |
| **auth-ui** | Authenticates the user with any combination of factors (password, MFA, passkeys, federation); collects consent; records the decision against the opaque interaction ticket. | Only the opaque ticket id — no codes, no tokens, no RP `redirect_uri`s. |
| **Authlete** | OAuth/OIDC protocol engine. Owns per-transaction state via tickets. | Never reachable from the browser; only the AS calls it. |

### State model

- The **Authlete ticket** is the only handle for an in-flight authorization. Auth result, consent decision, and request context all hang off it.
- The **AS holds no per-transaction state**. The browser carries only the ticket id; the AS exchanges it back for context as needed. (One transitional exception is documented inline in `src/userstore.ts`.)
- `auth-ui` holds the user session but not the OAuth transaction.

### Trust boundaries

```
 ┌──────────┐    OAuth / OIDC    ┌──────────┐   component protocol    ┌──────────┐
 │   RP     │ ─────────────────→ │    AS    │ ───(bearer-auth)──────→ │ auth-ui  │
 └──────────┘                    │  (this)  │                          │          │
                                 │          │   @authlete/sdk          │          │
                                 │          │ ─────────────────→  Authlete         │
                                 └──────────┘                          └─────┬────┘
                                                                             │
                                                  (future) federated IdPs · MFA · passkeys
```

- **AS outward to RPs**: standard OAuth/OIDC. One spec, no surprises.
- **AS ↔ auth-ui**: a bespoke 2-endpoint component protocol (`GET/POST /api/interactions/{ticket}`), bearer-authenticated. `auth-ui` obtains the bearer via `client_credentials` + `private_key_jwt`.
- **AS ↔ Authlete**: standard Authlete SDK over HTTPS.
- **AS never federates outward.** No social login, no upstream OIDC, no SAML. All of that lives in `auth-ui`.

### Why this pattern

- **Implementation-portable.** A thin Authlete client with no user state can be this Node service, a sidecar, a reverse-proxy plugin, or live inside an API gateway / edge worker.
- **Authentication grows in `auth-ui`.** MFA, passkeys, federation, step-up, risk-based prompts — none of which the AS ever sees.
- **Consent grows in `auth-ui`.** Granular per-claim choices, Rich Authorization Requests (RAR), persistent grant management — all UI work behind the same ticket interface.
- **Independent deploy and scale.** Two services, one narrow protocol between them.

This separation matches the architecture Authlete is designed around: the engine owns the spec and per-transaction state; you own the user experience.

## Endpoints

| Path | Spec | Purpose |
|---|---|---|
| `GET/POST /oauth/authorize` | OAuth 2.0, OIDC Core | Authorization endpoint — redirects to `auth-ui` for login + consent. |
| `GET /oauth/authorize/finalize` | (component) | `auth-ui` returns here after the user decides; the AS calls Authlete `issue`/`fail` and redirects the RP. |
| `POST /oauth/token` | RFC 6749 §3.2 | Token endpoint — `authorization_code`, `refresh_token`, `client_credentials`. |
| `GET/POST /oauth/userinfo` | OIDC Core §5.3 | UserInfo endpoint. |
| `POST /oauth/par` | RFC 9126 | Pushed Authorization Requests. |
| `POST /oauth/introspect` | RFC 7662 | Token introspection. |
| `POST /oauth/revoke` | RFC 7009 | Token revocation. |
| `GET /oauth/jwks` | RFC 7517 | Service JWK Set. |
| `GET /.well-known/openid-configuration` | OIDC Discovery | OIDC discovery metadata. |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | OAuth AS metadata. |
| `GET/POST /api/interactions/:ticket` | (component) | Bearer-protected interface used by `auth-ui`. |

## Component protocol

The `/api/interactions/{ticket}` pair is the only non-standard surface in this AS. It's a small, bespoke 2-endpoint contract that `auth-ui` uses to drive the user-facing flow.

**Authentication.** Both endpoints require a Bearer token with the `urn:authlete-as:interactions` scope. `auth-ui` obtains one via `POST /oauth/token` with `grant_type=client_credentials` + `private_key_jwt`.

### `GET /api/interactions/{ticket}` — fetch render context

Returned JSON tells `auth-ui` what to render and what the RP asked for:

```jsonc
{
  "client": {
    "client_id": "2234376661",
    "name": "Demo App",
    "logo_uri": "https://…",
    "policy_uri": "https://…",
    "tos_uri": "https://…"
  },
  "needs": ["authentication", "consent"],
  "skip": false,                       // true when prompt=none and the AS could short-circuit
  "login_hint": "alice@example.com",   // optional
  "prompt": "login consent",           // optional, space-separated
  "acr_values": ["urn:mace:incommon:iap:silver"],
  "max_age": 3600,                     // optional, seconds
  "ui_locales": ["en-US"],
  "subject": null,                     // optional, when AS has a hint
  "requested_scopes": [
    { "name": "openid",  "description": "Sign you in" },
    { "name": "email",   "description": "See your email address" }
  ],
  "requested_claims": {                // OIDC claims parameter, parsed
    "id_token": { "email": null },
    "userinfo": { "name": null },
    "all": ["email", "name"]
  },
  "previously_granted_scopes": []
}
```

`404 Not Found` if the ticket is unknown or expired.

### `POST /api/interactions/{ticket}` — submit the user's decision

Body is either an **approved** or **denied** decision:

```jsonc
// Approved
{
  "subject": "user-abc123",            // required
  "acr": "urn:mace:incommon:iap:silver",
  "amr": ["pwd"],
  "authenticated_at": 1717545600,      // seconds since epoch
  "granted_scopes": ["openid", "email"],
  "user_claims": {                     // values returned at /userinfo for this auth
    "sub": "user-abc123",
    "name": "Alice",
    "email": "alice@example.com",
    "email_verified": true
  }
}

// Denied
{
  "error": "access_denied",
  "error_description": "User denied the authorization request"
}
```

Response:

```json
{ "redirect_to": "https://as.example.com/oauth/authorize/finalize?ticket=…" }
```

`auth-ui` issues a browser redirect to `redirect_to`; the AS then calls Authlete `issue` / `fail` and forwards the browser to the RP's `redirect_uri`.

## Configuration

Copy `.env.example` to `.env` and fill in:

| Variable | Purpose |
|---|---|
| `AUTHLETE_BASE_URL` | Authlete cluster URL (default `https://us.authlete.com`). |
| `AUTHLETE_SERVICE_ID` | Numeric service id from the Authlete console. |
| `AUTHLETE_API_TOKEN` | Service access token from the Authlete console. |
| `AS_BASE_URL` | This server's public URL (RPs and `auth-ui` use it). |
| `AUTH_UI_URL` | Where `auth-ui` is reachable. |
| `PORT` | Listen port (default `3000`). |
| `AS_CORS_ORIGINS` | Comma-separated allowlist of browser origins (e.g. Authlete OAuth Playground). Empty disables CORS. |

## Provisioning (one-time, per Authlete service)

1. Sign up at https://us.authlete.com and create a new Authlete 3.0 service.
2. In the service, register two clients:
   - **A test RP** (Authorization Code + PKCE) for end-to-end testing.
   - **`auth-ui` first-party client**: `grant_types=client_credentials`, `token_endpoint_auth_method=private_key_jwt`. Generate an ES256 key pair; register the public JWKS in Authlete; keep the private key for `auth-ui`'s env.
3. Populate the AS's `.env` from the Authlete console (service id + API token + URLs).

## Run locally

```bash
pnpm install
pnpm dev
```

Server boots at `http://localhost:3000`. Health probe:

```bash
curl http://localhost:3000/health
```

Discovery sanity:

```bash
curl http://localhost:3000/.well-known/openid-configuration | jq .
```

End-to-end is exercised by `auth-ui`'s smoke harness (`auth-ui/scripts/smoke-e2e.mjs`).

## Roadmap

The AS surface grows with the OAuth/OIDC spec; authentication features grow in `auth-ui`.

- **FAPI 2.0** — DPoP, JAR, JARM (PAR already shipped).
- **mTLS client auth** (`tls_client_auth`).
- **CIBA** (`urn:openid:params:grant-type:ciba`).
- **Dynamic Client Registration** (RFC 7591/7592).
- **RP-Initiated Logout / Front- and Back-channel Logout**.
- **Grants Management API**.

