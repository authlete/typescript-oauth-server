# Interaction Protocol

A bilateral protocol for a headless OAuth/OIDC Authorization Server to offload
all user-facing interactions — sign-in, consent, MFA, step-up, federation — to
a separate **interaction app**, and to securely exchange information with that
app over the network.

The AS speaks standard OAuth/OIDC at its public surface. Everything that
involves a human moves out to interaction app(s). The two peers talk to each
other only through the contract defined here.

## The model

An authorization has **required interactions** — `authenticate`, and `consent`
when there's something to consent to. Each yields an **outcome**. The AS hands an
app the browser; the app runs the interactions served at its own URL, reporting
each outcome, until the AS says it's done; then it returns the browser to the AS,
which either hands off to the next app or finalizes once every outcome is in.
Apps are dumb — the AS drives them; an app doesn't know if it runs one interaction
or several.

## Roles

| Role                | Owns                                                                                                                                 |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| **AS**              | OAuth/OIDC endpoints, the authorization-transaction state machine, and which app runs each interaction. No UI, no user data.         |
| **Interaction app** | User store + UI for the interactions it serves. Renders what the AS hands it; no OAuth/OIDC logic, not the consent system-of-record. |

Apps are pluggable and there can be more than one. The canonical app is
`auth-ui`, which serves `authenticate` (and `consent` inline, by default). A
regulated deployment may add a dedicated **consent UI** that serves `consent`;
it's just a second interaction app entered the same way. In that mode the consent
system-of-record is a separate external consent service the AS syncs to
out-of-band (not this browser loop) — see "External consent" below.

## Trust model

- Each peer has a key pair and publishes its public keys as a JWKS at
  `<base URL>/.well-known/jwks.json`. The other peer derives that location from
  the peer's base URL — there is no separately-configured JWKS URI.
- Each peer verifies the other's signed messages against the published JWKS.
- Every inter-peer message is a per-request signed JWT (same crypto primitive
  as RFC 7521 / 7523, applied per call — no intermediate bearer tokens).
- No OAuth-client registration is involved on either side for this protocol.

## Transport

All API operations are direct server-to-server HTTPS requests with the JWT in
`Authorization: Bearer`. The two peers must be network-reachable to each other.
The only browser-carried token is the §1 interaction token, which is
routing-only and carries no user data.

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
       · server-to-server call tokens (§1.a, §2, §4):          iat + 60
       · the §1 interaction token (spans the user's sign-in+consent): iat + 600
  jti  uuid v4
```

Per-operation claims are layered on top (see Operations below): `authorization` for the authorization-transaction calls, or `subject` for the account-scoped connected-apps calls.

## Verification rules

Every receiver, every inbound JWT:

1. Parse the compact JWT; read `kid` from the header.
2. Fetch the caller's JWKS from `<caller base URL>/.well-known/jwks.json`
   (cache with a 5-minute TTL); look up the key by `kid`.
3. Verify the signature.
4. Verify `iss` is a configured peer and select its JWKS by it — the AS accepts
   either interaction app it's configured with (auth-ui, or the consent UI); the
   verified `iss` is the caller's identity.
5. Verify `aud` equals the receiver's own identifier.
6. Verify `iat` is in the past (≤ 5s clock skew) and `exp` is in the future.
7. Verify per-operation bindings (e.g. `authorization`, user `id`) match the URL.
8. Proceed.

### Replay protection — stateless

The AS keeps **no `jti` store**. Replay protection comes from:

- **Short `exp`** (see the envelope above — 60 s for calls, longer only for the
  browser-carried interaction token).
- **Authorization-id binding** for non-idempotent operations. The id is backed
  by the AS's single-use transaction state, so a replayed JWT for a completed
  authorization fails inside the AS's state engine.
- **Idempotency** for read-only operations (state fetch, user fetch).
- **TLS** on every server-to-server call.

## Key resolution

Each peer publishes one JWKS that may contain one or more keys, distinguished
by `kid`. The signer picks its own key with this resolver:

1. If the JWKS has exactly one key, use it.
2. Else use the first key whose `alg` matches the configured signing alg.
3. Else use the first key in `keys[]`.

The verifier picks by the `kid` from the inbound JWS header; no fallback.

## URL surface

```
Browser paths (top-level — no /api/ prefix):
  AS → interaction app:   <APP_URL>/authorizations/<id>?interaction=<jwt>
  interaction app → AS:   <AS_URL>/authorizations/<id>/resume

API paths (server-to-server JSON, JWT in Authorization: Bearer):
  interaction app → AS:   GET    /api/authorizations/{id}
                          POST   /api/authorizations/{id}/outcome
                          GET    /api/authorized-apps
                          DELETE /api/authorized-apps/{clientId}
  AS → interaction app:   GET    /api/users/{id}
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
is the one value that varies per deployment. Trust identity (`iss`/`aud`, both
JWKS) stays static config on both sides; only the routing base rides as data.

The token is **routing-only — no user data** — so carrying it on the redirect is
safe.

Interaction JWT claims:

```jsonc
{
  "authorization": "<id>", // MUST equal the <id> in the URL path
  "as_base": "https://as.example.com", // AS origin to call back to (§1.a, §2)
}
```

The interaction app verifies the token (signature against the AS JWKS,
`iss`/`aud`, `exp`), checks `authorization` matches the URL `<id>`, and then uses
`as_base` as the origin for the calls in §1.a and §2. Because `as_base` is inside
the signed token and a single trusted AS identity is assumed, a token that
verifies is proof the base is genuine — no separate origin allow-list is needed.

#### 1.a. `GET /api/authorizations/{id}` — the next interaction for the caller

**Direction:** interaction app → AS.
**JWT claims:** `authorization: <id from URL>`.
**Response (JSON):** the client (for display) plus the next interaction **that this
caller serves** — or `done` if the next pending interaction belongs to another app
(then return the browser to `redirect_to`). auth-ui gets `authenticate` first;
a dedicated consent UI gets `consent`.

```jsonc
{
  "client": { "client_id", "name", "logo_uri", "policy_uri", "tos_uri" },
  "next": "authenticate",
  "authenticate": { "acr_values": ["..."], "max_age": 3600, "prompt": "login", "login_hint": "...", "ui_locales": ["en-US"] }
}
// or, when consent is this caller's next interaction:
{ "client": { ... }, "next": "consent", "consent": { "new": [...], "already_granted": [...], "authorization_details": [...] } }
// or, nothing here for this caller:
{ "client": { ... }, "next": "done", "redirect_to": "<AS_URL>/authorizations/<id>/resume" }
```

### 2. Interaction app → AS: report an interaction outcome

#### `POST /api/authorizations/{id}/outcome`

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
    "new":             [{ "name": "approve:expense", "description": "..." }],  // scopes still needing consent
    "already_granted": [{ "name": "read:expense",    "description": "..." }],  // shown read-only
    "authorization_details": [{ "type": "...", "actions": ["..."] }]           // RAR (RFC 9396), if requested
} }
// or, nothing left to do:
{ "next": "done", "redirect_to": "<AS_URL>/authorizations/<id>/resume" }
```

The AS computes the consent step for the authenticated subject:
`new = requested − already-granted` (Authlete's `mergedGrantedScopes`). Consent is
required only when something is new **or** there are `authorization_details` (RAR
is per-request, so its presence always requires consent) — **unless** the client
is trusted **first-party**, which suppresses consent entirely (see below).
`prompt=consent` re-confirms the whole request (nothing counts as pre-granted). Any
granted-scopes lookup failure falls back to full consent.

**First-party clients.** A client marked `first_party=true` (an attribute on its
Authlete client record) skips consent — the AS auto-grants the full request. This
is how the consent UI's own OIDC sign-in stays silent. It's client configuration
in Authlete, not protocol config.

### 3. AS resume: `GET /authorizations/{id}/resume`

Browser-hit on the AS side, once an app has looped to `done`. The AS looks at what
interaction is still pending:

- **Another app's interaction is pending** (e.g. auth-ui finished authenticate and
  a dedicated consent UI must run consent) → redirect the browser to that app's
  entry (§1), same signed-token convention.
- **Nothing pending** → complete the OAuth flow from the accumulated outcomes:
  `issue` with the authenticated subject and the final scope grant
  (already-granted ∪ newly consented; the full request for a first-party client),
  or `fail` if any interaction was rejected — then redirect to the RP's
  `redirect_uri`.

The authorization code never passes through an interaction app.

### 4. AS → interaction app: fetch the user resource

`GET /api/users/{id}` with `Authorization: Bearer <jwt>`. Used by the AS at
`/userinfo` handling time to source fresh claim values.

**Response (JSON):**

```jsonc
{
  "id": "<user-id>",
  "name": "<current name>",
  "email": "<current email>",
  "email_verified": true,
  "picture": "<image url>",
}
```

The interaction app returns its raw user representation. The AS owns the
OIDC-claim projection (filter the user fields by the claims the user
consented to release).

`404 Not Found` if the id is unknown.

### 5. Interaction app → AS: connected-apps management

Account-scoped, not part of the authorization loop above: the interaction app's
account UI lists and revokes the apps a user has granted. Same transport and keys,
but the JWT carries a `subject` claim (the acting user) instead of an
`authorization`. Revoke needs the AS's Authlete token to hold `modify_client`.

#### `GET /api/authorized-apps` — list the subject's granted apps

**JWT claims:** `{ "subject": "<user-id>" }`

**Response (JSON):**

```jsonc
{
  "apps": [
    {
      "client": {
        "client_id": "...",
        "name": "...",
        "logo_uri": "...",
        "client_uri": "...",
        "redirect_uris": ["..."],
      },
      "scopes": ["openid", "email"],
    },
  ],
}
```

#### `DELETE /api/authorized-apps/{clientId}` — revoke the subject's grant

Clears the subject's remembered scopes and tokens for the client, so a later
authorization re-prompts consent. `204 No Content` on success.

**JWT claims:** `{ "subject": "<user-id>" }`

## External consent

When a dedicated consent UI is configured, a separate consent service is the
consent system-of-record. The AS keeps it in sync out-of-band — not in the
browser loop, and only from the generic grant lifecycle:

- **After issue** (`/token`), if the grant carries a `consent_id`, the AS links
  the grant to that consent record.
- **On revoke** (`/gm` DELETE), the AS notifies the consent service.

Same mutual-JWT primitive, addressed to the consent service. These calls no-op
when no consent service is configured, and `/token` and `/gm` never reference the
consent service directly — the calls sit behind a generic grant-lifecycle seam.

## Configuration

Each peer needs:

| Concept          | Notes                                                                                                         |
| ---------------- | ------------------------------------------------------------------------------------------------------------- |
| Own base URL     | The deployment's base URL — its `iss`/`aud`, and the origin of its published JWKS (`/.well-known/jwks.json`). |
| Peer base URL    | The other side's base URL. Its identity **and** JWKS both derive from this — no separate JWKS URI.            |
| Own private JWKS | For signing outbound JWTs. May contain one or many keys.                                                      |

The interaction app does **not** configure the AS's callback base — it receives
that per-request in the §1 interaction token. It still configures the AS's
_identity_ (issuer id + JWKS URI) statically, as the trust anchor.

The AS configures its auth-ui peer (base URL) and, optionally, a second peer for
the consent UI (base URL). A consent UI's presence is the only switch: absent →
auth-ui handles consent inline; present → auth-ui authenticates and the consent UI
handles consent. Base URL is the only per-app config.

Env-var names are implementation-specific; see each repo's `.env.example`.

## Production guidance

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
