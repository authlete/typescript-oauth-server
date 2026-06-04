/**
 * /oauth/jwks — RFC 7517 JSON Web Key Set endpoint.
 * Thin proxy to Authlete's service JWKS.
 */

import { Hono } from "hono";
import { authlete } from "../authlete.js";
import { config } from "../config.js";

export const jwks = new Hono();

jwks.get("/oauth/jwks", async (c) => {
  const res = await authlete.jwkSetEndpoint.serviceJwksGetApi({
    serviceId: config.authleteServiceId,
  });
  return c.body(JSON.stringify(res ?? { keys: [] }), 200, {
    "content-type": "application/jwk-set+json",
    "cache-control": "public, max-age=300",
  });
});
