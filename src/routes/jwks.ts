/**
 * /oauth/jwks — RFC 7517 JSON Web Key Set.
 *
 * The service's OAuth signing keys (Authlete signs ID tokens, JARM, etc.),
 * advertised via discovery for RPs to verify tokens. The AS's own interaction
 * key lives at /.well-known/jwks.json — see interaction/routes.ts.
 */

import { Hono } from "hono";
import type { JWK } from "jose";
import type { Deps } from "../app.js";

export function jwksRoutes({ authlete, config }: Deps) {
  const jwks = new Hono();

  jwks.get("/oauth/jwks", async (c) => {
    const authleteRes = await authlete.jwkSetEndpoint.serviceJwksGetApi({
      serviceId: config.authleteServiceId,
    });
    const keys = (authleteRes?.keys as JWK[] | undefined) ?? [];
    return c.body(JSON.stringify({ keys }), 200, {
      "content-type": "application/jwk-set+json",
      "cache-control": "public, max-age=300",
    });
  });

  return jwks;
}
