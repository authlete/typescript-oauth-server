/**
 * JWKS handling for the interaction protocol.
 *
 * Owns:
 *   - parsing the AS's private JWKS from env into structured keys,
 *   - producing the public JWKS published at /.well-known/jwks.json,
 *   - selecting the signing key per the resolver rules in INTERACTION_PROTOCOL.md §5.
 */

import type { JWK } from "jose";
import type { Config } from "../config.js";

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
 * Resolve the signing key from the local JWKS:
 *   1. the only key in the set, if there is exactly one
 *   2. else the first key whose `alg` matches the signing alg
 *   3. else the first key in the set
 */
export function resolveSigningKey(jwks: JWKS, alg: string): JWK {
  if (jwks.keys.length === 1) return jwks.keys[0]!;
  return jwks.keys.find((k) => k.alg === alg) ?? jwks.keys[0]!;
}

// The interaction keypair is deployment-level — one per process, shared by every
// server instance — so these parsed-once caches are deliberately module-scoped.
let cachedAsPrivateJwks: JWKS | null = null;
let cachedAsPublicJwks: JWKS | null = null;

/** The AS's private JWKS, parsed once from AS_SIGNING_JWKS. */
export function getAsPrivateJwks(config: Config): JWKS {
  if (!cachedAsPrivateJwks) {
    if (!config.asSigningJwks) throw new Error("AS_SIGNING_JWKS not configured");
    cachedAsPrivateJwks = parseJwks(config.asSigningJwks);
  }
  return cachedAsPrivateJwks;
}

/** The AS's public JWKS — published at /.well-known/jwks.json. */
export function getAsPublicJwks(config: Config): JWKS {
  if (!cachedAsPublicJwks) {
    cachedAsPublicJwks = config.asSigningJwks ? publicJwks(getAsPrivateJwks(config)) : { keys: [] };
  }
  return cachedAsPublicJwks;
}
