/**
 * JSON Web Key Set endpoints.
 *
 *   /oauth/jwks            — the service's OAuth signing keys (Authlete signs
 *                            ID tokens, JARM, etc.). Advertised via discovery
 *                            for RPs to verify tokens.
 *   /.well-known/jwks.json — the AS's own interaction key, for auth-ui to verify
 *                            the AS's signed messages. See INTERACTION_PROTOCOL.md §1.
 */

import { Hono } from "hono";
import type { JWK } from "jose";
import type { Deps } from "../app.js";
import { getAsPublicJwks } from "../jwks.js";

const JWKS_HEADERS = {
  "content-type": "application/jwk-set+json",
  "cache-control": "public, max-age=300",
} as const;

export function jwksRoutes({ authlete, config }: Deps) {
  const jwks = new Hono();

  jwks.get("/oauth/jwks", async (c) => {
    const authleteRes = await authlete.jwkSetEndpoint.serviceJwksGetApi({
      serviceId: config.authleteServiceId,
    });
    const keys = (authleteRes?.keys as JWK[] | undefined) ?? [];
    return c.body(JSON.stringify({ keys }), 200, JWKS_HEADERS);
  });

  jwks.get("/.well-known/jwks.json", (c) =>
    c.body(JSON.stringify(getAsPublicJwks(config)), 200, JWKS_HEADERS),
  );

  return jwks;
}
