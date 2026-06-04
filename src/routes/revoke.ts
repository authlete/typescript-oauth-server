/**
 * /oauth/revoke — RFC 7009 OAuth 2.0 Token Revocation.
 *
 * Per RFC 7009 §2.2, 200 OK is returned for both successful revocation and
 * already-invalid tokens (no information leak). 400/401 only for malformed
 * requests / unknown client.
 */

import type { Context } from "hono";
import { Hono } from "hono";
import { authlete } from "../authlete.js";
import { config } from "../config.js";
import { basicCredsFor } from "../auth/basic.js";
import { basicChallengeHeaders, noStoreJsonHeaders } from "../http.js";

export const revoke = new Hono();

revoke.post("/oauth/revoke", async (c) => {
  const parameters = await c.req.text();
  const res = await authlete.revocation.process({
    serviceId: config.authleteServiceId,
    revocationRequest: { parameters, ...basicCredsFor(c) },
  });
  return dispatch(c, res.action, res.responseContent);
});

function dispatch(c: Context, action: string | undefined, responseContent: string | undefined): Response {
  const body = responseContent ?? "";
  switch (action) {
    case "OK":
      return c.body("", 200, noStoreJsonHeaders);
    case "INVALID_CLIENT":
      return c.body(body, 401, basicChallengeHeaders);
    case "BAD_REQUEST":
      return c.body(body, 400, noStoreJsonHeaders);
    case "INTERNAL_SERVER_ERROR":
    default:
      return c.body(body, 500, noStoreJsonHeaders);
  }
}
