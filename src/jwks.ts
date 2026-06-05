/**
 * JWKS handling for the interaction protocol.
 *
 * Owns:
 *   - parsing the AS's private JWKS from env into structured keys,
 *   - producing the public JWKS for /oauth/jwks (merged with Authlete's),
 *   - selecting the signing key per the resolver rules in INTERACTION_PROTOCOL.md §5.
 */

import type { JWK } from "jose";
import { config } from "./config.js";

export type JWKS = { keys: JWK[] };

const PRIVATE_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

/** Parse a JWKS env value into a typed JWKS, validating the shape. */
export function parseJwks(raw: string): JWKS {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JWKS env: not JSON (${(err as Error).message})`);
  }
  if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as JWKS).keys)) {
    throw new Error("Invalid JWKS env: missing 'keys' array");
  }
  const { keys } = parsed as JWKS;
  if (keys.length === 0) throw new Error("Invalid JWKS env: 'keys' array is empty");
  return { keys };
}

/** Strip private fields from a JWKS, producing the public JWKS for publication. */
export function publicJwks(jwks: JWKS): JWKS {
  return {
    keys: jwks.keys.map((k) => {
      const out: Record<string, unknown> = { ...k };
      for (const f of PRIVATE_FIELDS) delete out[f];
      return out as unknown as JWK;
    }),
  };
}

/**
 * Resolve a signing key from the local JWKS using the rules:
 *   1. explicit kid match
 *   2. only one key in the set
 *   3. first key whose `alg` matches the configured signing alg
 *   4. first key in the set
 */
export function resolveSigningKey(jwks: JWKS, opts: { kid?: string; alg?: string }): JWK {
  if (opts.kid) {
    const byKid = jwks.keys.find((k) => k.kid === opts.kid);
    if (!byKid) throw new Error(`No JWK with kid=${opts.kid} in configured JWKS`);
    return byKid;
  }
  if (jwks.keys.length === 1) return jwks.keys[0]!;
  if (opts.alg) {
    const byAlg = jwks.keys.find((k) => k.alg === opts.alg);
    if (byAlg) return byAlg;
  }
  return jwks.keys[0]!;
}

let cachedAsPrivateJwks: JWKS | null = null;
let cachedAsPublicJwks: JWKS | null = null;

/** Memoized AS private JWKS (parsed from env once). */
export function getAsPrivateJwks(): JWKS {
  if (!cachedAsPrivateJwks) {
    if (!config.asSigningJwks) throw new Error("AS_SIGNING_JWKS not configured");
    cachedAsPrivateJwks = parseJwks(config.asSigningJwks);
  }
  return cachedAsPrivateJwks;
}

/** Memoized AS public JWKS — published via /oauth/jwks (merged with Authlete's). */
export function getAsPublicJwks(): JWKS {
  if (!cachedAsPublicJwks) {
    cachedAsPublicJwks = config.asSigningJwks ? publicJwks(getAsPrivateJwks()) : { keys: [] };
  }
  return cachedAsPublicJwks;
}
