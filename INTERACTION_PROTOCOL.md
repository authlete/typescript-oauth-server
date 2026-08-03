# Interaction Protocol

A bilateral protocol for a headless OAuth/OIDC Authorization Server to offload
all user-facing interactions — sign-in, consent, MFA, step-up, federation — to
a separate **interaction app**, and to securely exchange information with that
app over the network.

The AS speaks standard OAuth/OIDC at its public surface. Everything that
involves a human moves out to the interaction app, which owns the user store
and the consent store. The two peers talk to each other only through the
contract defined here.

## Roles

| Role | Owns |
|---|---|
| **AS** | OAuth/OIDC endpoints, authorization-transaction state, no UI, no user data. |
| **Interaction app** | User store, consent store, all UI screens. No OAuth/OIDC knowledge. |

The interaction app is pluggable. Any app that implements this contract can
pair with the AS — the canonical implementation in this project is `auth-ui`,
but the protocol does not depend on it.

## Trust model

- Each peer has a key pair and publishes its public keys as a JWKS at
  `<base URL>/.well-known/jwks.json`. The other peer derives that location from
  the peer's base URL — there is no separately-configured JWKS URI.
- Each peer verifies the other's signed messages against the published JWKS.
- Every inter-peer message is a per-request signed JWT (same crypto primitive
  as RFC 7521 / 7523, applied per call — no intermediate bearer tokens).
- No OAuth-client registration is involved on either side for this protocol.

## Channels

Two interaction modes, selected at deployment time:

| Mode | Carrier | When to use |
|---|---|---|
| **backchannel** | Direct server-to-server HTTPS request; JWT in `Authorization: Bearer`. | **Production default.** Use when both peers are network-reachable to each other. |
| **frontchannel** | JWT carried on existing browser redirects as a URL query parameter. No JS, no form-post. | **Dev/test only** — for asymmetric reachability (e.g., AS on `localhost` while the interaction app is hosted). Exposes JWT contents (including PII) to browser history, referer headers, and intermediate access logs. Implementations MUST refuse in production unless explicitly overridden. |

The two modes share the **same JWT envelope, claim shapes, and verification
rules**. Only the carrier differs. A deployment runs in one mode at a time.

## JWT envelope

All inter-peer messages share this envelope:

```
Header:
  alg  ES256 (or RS256)
  kid  signer's key id
  typ  JWT

Claims (always):
  iss  caller's issuer id
  sub  caller's issuer id           // service is its own subject
  aud  receiver's issuer id
  iat  unix seconds
  exp  short-lived; depends on the message:
       · server-to-server call tokens (§1.a, §2.a, §4):        iat + 60
       · the §1 interaction token (spans the user's sign-in+consent): iat + 600
       · frontchannel tokens carried across interaction (§1, §2.b): iat + 300
  jti  uuid v4
```

Per-operation claims are layered on top (see Operations below).

## Verification rules

Every receiver, every inbound JWT:

1. Parse the compact JWT; read `kid` from the header.
2. Fetch the caller's JWKS from `<caller base URL>/.well-known/jwks.json`
   (cache with a 5-minute TTL); look up the key by `kid`.
3. Verify the signature.
4. Verify `iss` equals the configured caller identifier.
5. Verify `aud` equals the receiver's own identifier.
6. Verify `iat` is in the past (≤ 5s clock skew) and `exp` is in the future.
7. Verify per-operation bindings (e.g. `authorization`, user `id`) match the URL.
8. Proceed.

### Replay protection — stateless

The AS keeps **no `jti` store**. Replay protection comes from:

- **Short `exp`** (see the envelope above — 60 s for calls, longer only for the
  browser-carried interaction/frontchannel tokens).
- **Authorization-id binding** for non-idempotent operations. The id is backed
  by the AS's single-use transaction state, so a replayed JWT for a completed
  authorization fails inside the AS's state engine.
- **Idempotency** for read-only operations (state fetch, user fetch).
- **TLS** for backchannel.

## Key resolution

Each peer publishes one JWKS that may contain one or more keys, distinguished
by `kid`. The signer picks its own key with this resolver:

1. Use the explicitly configured `kid` if set.
2. Else if the JWKS has exactly one key, use it.
3. Else use the first key whose `alg` matches the configured signing alg.
4. Else use the first key in `keys[]`.

The verifier picks by the `kid` from the inbound JWS header; no fallback.

## URL surface

```
Browser paths (top-level — no /api/ prefix):
  AS → interaction app:   <APP_URL>/authorizations/<id>?interaction=<jwt>
  interaction app → AS:   <AS_URL>/authorizations/<id>/resume[?decision=<jwt>]

API paths (server-to-server JSON, JWT in Authorization: Bearer):
  interaction app → AS:   GET  /api/authorizations/{id}
                          POST /api/authorizations/{id}/outcome
  AS → interaction app:   GET  /api/users/{id}
```

Conventions:
- **`authorizations`** is the in-flight authorization-transaction resource.
- **`/api/`** = server-to-server JSON.
- **Top-level paths** = browser-hit, HTML or redirect response.
- The AS's `/oauth/` namespace is reserved for RFC-defined OAuth/OIDC endpoints
  and is not used by this protocol.

## Operations

### 1. AS → interaction app: hand off the authorization

The AS, after processing `/oauth/authorize`, redirects the browser:

```
<APP_URL>/authorizations/<id>?interaction=<jwt>
```

The `interaction` JWT is a **signed routing token**. It carries the AS's own
callback base URL (`as_base`), so the interaction app calls back to the correct
AS deployment **without holding that URL in static config**. The callback base
is the one value that varies per deployment — and per tenant in a multi-tenant
host. Trust identity (`iss`/`aud`, both JWKS) stays static config on both sides;
only the routing base rides as data.

The token is **routing-only — no user data** — so carrying it on the redirect is
safe in both channels (unlike the frontchannel state token below).

Interaction JWT claims:
```jsonc
{
  "authorization": "<id>",              // MUST equal the <id> in the URL path
  "as_base": "https://as.example.com",  // AS origin to call back to (§1.a, §2)

  // frontchannel only — the full authorization state inline (see §1.a),
  // letting the app skip the §1.a GET:
  "details": { /* ... */ }
}
```

The interaction app verifies the token (signature against the AS JWKS,
`iss`/`aud`, `exp`), checks `authorization` matches the URL `<id>`, and then uses
`as_base` as the origin for the calls in §1.a and §2. Because `as_base` is inside
the signed token and a single trusted AS identity is assumed, a token that
verifies is proof the base is genuine — no separate origin allow-list is needed.

#### 1.a. `GET /api/authorizations/{id}` — the next required interaction

**Direction:** interaction app → AS.
**JWT claims:** `authorization: <id from URL>`.
**Response (JSON):** the client (for display) plus the first interaction. The AS
orchestrates two interactions — **authenticate**, then **consent** — so the first
step is always `authenticate`.
```jsonc
{
  "client": { "client_id", "name", "logo_uri", "policy_uri", "tos_uri" },
  "next": "authenticate",
  "authenticate": {
    "acr_values": ["..."],
    "max_age": 3600,
    "prompt": "login",
    "login_hint": "...",
    "ui_locales": ["en-US"]
  }
}
```

### 2. Interaction app → AS: report an interaction outcome

#### 2.a. `POST /api/authorizations/{id}/outcome` (backchannel)

The app reports the outcome of one interaction; the AS reconciles and replies with
what's `next` (`authenticate` | `consent` | `done`). The app loops until `done`,
then redirects the browser to `redirect_to`.

**JWT claims** — the `outcome`:
```jsonc
// authenticate outcome
{ "authorization": "<id>", "outcome": {
    "type": "authenticate",
    "subject": "<user-id>", "acr": "<acr>", "amr": ["pwd"],
    "authenticated_at": 1717545600,
    "user_claims": { "sub": "...", "name": "...", "email": "...", "email_verified": true } } }

// consent outcome
{ "authorization": "<id>", "outcome": { "type": "consent", "granted_scopes": ["openid", "email"] } }

// either interaction, on rejection
{ "authorization": "<id>", "outcome": {
    "type": "authenticate" | "consent",
    "error": "login_required" | "access_denied", "error_description": "..." } }
```

**Response** — the next step:
```jsonc
{ "next": "consent", "consent": {
    "new":             [{ "name": "approve:expense", "description": "..." }],  // still needs consent
    "already_granted": [{ "name": "read:expense",    "description": "..." }]   // shown read-only
} }
// or, nothing left to do:
{ "next": "done", "redirect_to": "<AS_URL>/authorizations/<id>/resume" }
```

The AS computes the consent step for the authenticated subject:
`new = requested − already-granted` (Authlete's `mergedGrantedScopes`). If nothing
is new and `prompt=consent` is absent, it skips consent and replies `done`. Any
granted-scopes lookup failure falls back to full consent (every requested scope is
`new`), so an AS that never uses the API behaves exactly as before.

### 3. AS resume: `GET /authorizations/{id}/resume`

Browser-hit on the AS side, once the app has looped to `done`. The AS completes the
OAuth flow from the accumulated outcomes — `issue` with the authenticated subject
and the final scope grant (already-granted ∪ newly consented), or `fail` if either
interaction was rejected — and redirects the browser to the RP's `redirect_uri`.
The authorization code never passes through the interaction app.

### 4. AS → interaction app: fetch the user resource (backchannel)

`GET /api/users/{id}` with `Authorization: Bearer <jwt>`. Used by the AS at
`/userinfo` handling time to source fresh claim values.

**Response (JSON):**
```jsonc
{
  "id": "<user-id>",
  "name": "<current name>",
  "email": "<current email>",
  "email_verified": true,
  "picture": "<image url>"
}
```

The interaction app returns its raw user representation. The AS owns the
OIDC-claim projection (filter the user fields by the claims the user
consented to release).

`404 Not Found` if the id is unknown.

Frontchannel has no counterpart for this operation; it is backchannel-only.

## Configuration

Each peer needs:

| Concept | Notes |
|---|---|
| Own base URL | The deployment's base URL — its `iss`/`aud`, and the origin of its published JWKS (`/.well-known/jwks.json`). |
| Peer base URL | The other side's base URL. Its identity **and** JWKS both derive from this — no separate JWKS URI. |
| Own private JWKS | For signing outbound JWTs. May contain one or many keys. |
| Channel mode | `backchannel` (prod) or `frontchannel` (dev only). |

The interaction app does **not** configure the AS's callback base — it receives
that per-request in the §1 interaction token. It still configures the AS's
*identity* (issuer id + JWKS URI) statically, as the trust anchor.

Env-var names are implementation-specific; see each repo's `.env.example`.

## Production guidance

- Use **backchannel** in production. Period.
- Implementations MUST refuse frontchannel when `NODE_ENV=production` unless
  an explicit override is set.
- Both peers should publish their public JWKS over HTTPS with a sensible
  cache header (`public, max-age=300` recommended).
- Rotate keys by adding a second key with a new `kid` to the JWKS; switch
  signing to the new key on a deployment; remove the old key from the JWKS
  after the cache TTL window has elapsed.

## Open notes

- The interaction app SHOULD pass the per-claim consent set back to the AS
  (along with `granted_scopes`) so the AS can persist it and honor it
  precisely at `/userinfo` time. See the `TODO(claims-leakage)` block in
  `src/routes/userinfo.ts` for the in-flight contract gap and the plan.
- `GET /api/users/{id}` could grow a `?fields=` query parameter for data
  minimization; for now it returns the full user resource.
