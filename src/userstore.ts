/**
 * In-memory cache of user claim values keyed by subject.
 *
 * Populated when auth-ui submits an approved decision; read at /userinfo
 * to satisfy claim-value lookup. In-process; restart-volatile.
 *
 * TODO: this is a hack. The AS is otherwise stateless; this file is the only
 * exception. It exists because Authlete's /auth/userinfo/issue requires the
 * caller to pass claim VALUES (Authlete returns claim NAMES only) and we have
 * no user database on the AS side. The Java reference solves the same problem
 * via a UserDao SPI hitting the AS's local user store.
 *
 * Proper stateless fixes to evaluate before this file grows:
 *   1. AS → auth-ui callback at /userinfo time: expose a new
 *      `GET /api/users/{subject}/claims` on auth-ui (bearer-protected), have
 *      the AS fetch fresh values from auth-ui's better-auth user table on
 *      every /userinfo. Always-fresh, no AS state, +1 RTT per /userinfo.
 *   2. Authlete-side userinfo callback (if Authlete 3.0 supports a
 *      service-level "fetch claims from this URL" config): Authlete calls back
 *      to the AS to source claim values, AS proxies to auth-ui. No state on
 *      either side of the AS↔Authlete boundary.
 *
 * Until then: this map. Single-instance only — multi-replica needs Redis or
 * the rewrite above.
 */

type Entry = {
  claims: Record<string, unknown>;
  expiresAt: number;
};

const TTL_SECONDS = 24 * 60 * 60;
const SWEEP_INTERVAL_MS = 60 * 60 * 1000;
const store = new Map<string, Entry>();

export function storeClaims(subject: string, claims: Record<string, unknown>): void {
  if (!subject) return;
  store.set(subject, { claims, expiresAt: nowSeconds() + TTL_SECONDS });
}

export function getClaims(subject: string | undefined): Record<string, unknown> | null {
  if (!subject) return null;
  const entry = store.get(subject);
  if (!entry) return null;
  if (entry.expiresAt < nowSeconds()) {
    store.delete(subject);
    return null;
  }
  return entry.claims;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// Bound memory by periodically evicting expired entries — without a sweep,
// subjects that are never re-read leak.
const sweep = setInterval(() => {
  const cutoff = nowSeconds();
  for (const [subject, entry] of store) {
    if (entry.expiresAt < cutoff) store.delete(subject);
  }
}, SWEEP_INTERVAL_MS);
sweep.unref?.();
