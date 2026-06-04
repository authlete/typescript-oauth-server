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
import { authlete } from "../authlete.js";
import { config } from "../config.js";
import { basicChallengeHeaders, noStoreJsonHeaders } from "../http.js";

export const introspect = new Hono();

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

  const body = res.responseContent ?? "";
  switch (res.action) {
    case "OK":
      return c.body(body || '{"active":false}', 200, noStoreJsonHeaders);
    case "JWT":
      return c.body(body, 200, {
        ...noStoreJsonHeaders,
        "content-type": "application/token-introspection+jwt",
      });
    case "BAD_REQUEST":
      return c.body(body, 400, noStoreJsonHeaders);
    case "INTERNAL_SERVER_ERROR":
    default:
      return c.body(body, 500, noStoreJsonHeaders);
  }
});
