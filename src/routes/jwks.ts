/**
 * /oauth/jwks — RFC 7517 JSON Web Key Set endpoint.
 *
 * Returns the union of:
 *   - Authlete's service JWKS (used by Authlete to sign ID tokens, JARM, etc.;
 *     private keys live inside Authlete).
 *   - The AS's component-protocol public keys (private keys live in this
 *     process's env; used to sign inter-component JWTs to `auth-ui`).
 *
 * Both are signing keys for "the AS as an entity"; verifiers distinguish by
 * `kid` from the JWS header.
 */

import { Hono } from "hono";
import type { JWK } from "jose";
import { authlete } from "../authlete.js";
import { config } from "../config.js";
import { getAsPublicJwks } from "../jwks.js";

export const jwks = new Hono();

jwks.get("/oauth/jwks", async (c) => {
  const authleteRes = await authlete.jwkSetEndpoint.serviceJwksGetApi({
    serviceId: config.authleteServiceId,
  });
  const authleteKeys = (authleteRes?.keys as JWK[] | undefined) ?? [];
  const asKeys = getAsPublicJwks().keys;

  return c.body(JSON.stringify({ keys: [...authleteKeys, ...asKeys] }), 200, {
    "content-type": "application/jwk-set+json",
    "cache-control": "public, max-age=300",
  });
});
