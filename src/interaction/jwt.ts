/**
 * JWT signing and verification for the interaction protocol.
 *
 *   - signJwt: signs a JWT going to `auth-ui` using the AS's private
 *     key from AS_SIGNING_JWKS.
 *   - verifyJwt: verifies a JWT received from `auth-ui` against
 *     auth-ui's published JWKS (<AUTH_UI_URL>/.well-known/jwks.json).
 *
 * Standard envelope claims (iss, sub, aud, iat, exp, jti) are applied per
 * INTERACTION_PROTOCOL.md §4. Per-operation claims are passed in as the payload.
 */

import {
  SignJWT,
  jwtVerify,
  createRemoteJWKSet,
  importJWK,
  type JWTPayload,
  type KeyLike,
} from "jose";
import { randomUUID } from "node:crypto";
import type { Config } from "../config.js";
import { getAsPrivateJwks, resolveSigningKey } from "./jwks.js";

const JWKS_CACHE_MAX_AGE_MS = 5 * 60 * 1000;
const JWKS_COOLDOWN_MS = 30 * 1000;
const DEFAULT_EXP_SECONDS = 60;
const CLOCK_TOLERANCE_SECONDS = 5;
const SIGNING_ALG = "ES256";

type ResolvedSigningKey = { key: KeyLike | Uint8Array; kid: string; alg: string };

// The interaction keypair and the auth-ui peer are deployment-level — one per
// process — so these lazy caches are deliberately module-scoped.
let signingKeyPromise: Promise<ResolvedSigningKey> | undefined;
let remoteAuthUiJwks: ReturnType<typeof createRemoteJWKSet> | undefined;

async function getSigningKey(config: Config): Promise<ResolvedSigningKey> {
  if (!signingKeyPromise) {
    signingKeyPromise = (async () => {
      const jwk = resolveSigningKey(getAsPrivateJwks(config), SIGNING_ALG);
      if (!jwk.kid) throw new Error("AS signing JWK must include a kid");
      const key = await importJWK(jwk, jwk.alg ?? SIGNING_ALG);
      return { key, kid: jwk.kid, alg: jwk.alg ?? SIGNING_ALG };
    })().catch((err) => {
      // Don't pin a rejected promise; let the next call retry.
      signingKeyPromise = undefined;
      throw err;
    });
  }
  return signingKeyPromise;
}

function getRemoteAuthUiJwks(config: Config) {
  if (!remoteAuthUiJwks) {
    remoteAuthUiJwks = createRemoteJWKSet(new URL(config.authUiJwksUri), {
      cacheMaxAge: JWKS_CACHE_MAX_AGE_MS,
      cooldownDuration: JWKS_COOLDOWN_MS,
    });
  }
  return remoteAuthUiJwks;
}

/** Sign a JWT addressed to `auth-ui` (audience = auth-ui's issuer id by default). */
export async function signJwt(
  config: Config,
  payload: Record<string, unknown>,
  opts: { audience?: string; expiresInSeconds?: number } = {},
): Promise<string> {
  const { key, kid, alg } = await getSigningKey(config);
  const audience = opts.audience ?? config.authUiIssuerId;
  const exp = opts.expiresInSeconds ?? DEFAULT_EXP_SECONDS;

  return new SignJWT(payload)
    .setProtectedHeader({ alg, kid, typ: "JWT" })
    .setIssuer(config.asIssuerId)
    .setSubject(config.asIssuerId)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime(`${exp}s`)
    .setJti(randomUUID())
    .sign(key);
}

/** Verify a JWT from `auth-ui`. Throws on any verification failure. */
export async function verifyJwt(config: Config, jwt: string): Promise<JWTPayload> {
  const { payload } = await jwtVerify(jwt, getRemoteAuthUiJwks(config), {
    issuer: config.authUiIssuerId,
    audience: config.asIssuerId,
    clockTolerance: CLOCK_TOLERANCE_SECONDS,
  });
  return payload;
}
