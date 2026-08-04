/**
 * /oauth/introspect — RFC 7662 OAuth 2.0 Token Introspection.
 *
 * Per RFC 7662 §2.2, both active and inactive tokens return 200 with the
 * `{active: ...}` body. Authlete's standard introspection API returns the
 * RFC 7662 body directly.
 *
 * Caller authentication is the minimum bar: an Authorization header must be
 * present. RS-level credential validation is pending an RS registration model.
 */

import { Hono } from "hono";
import type { Deps } from "../app.js";
import { basicChallengeHeaders, noStoreHeaders, sendAuthleteAction } from "../http.js";

export function introspectRoutes({ authlete, config }: Deps) {
  const introspect = new Hono();

  introspect.post("/oauth/introspect", async (c) => {
    if (!c.req.header("authorization")) {
      return c.body(
        JSON.stringify({ error: "invalid_client", error_description: "Authorization required" }),
        401,
        basicChallengeHeaders,
      );
    }

    const parameters = await c.req.text();
    const res = await authlete.introspection.standardProcess({
      serviceId: config.authleteServiceId,
      standardIntrospectionRequest: { parameters },
    });
    return sendAuthleteAction(c, res, {
      OK: { status: 200, body: res.responseContent || '{"active":false}' },
      JWT: {
        status: 200,
        headers: { ...noStoreHeaders, "content-type": "application/token-introspection+jwt" },
      },
      BAD_REQUEST: 400,
      INTERNAL_SERVER_ERROR: 500,
    });
  });

  return introspect;
}
