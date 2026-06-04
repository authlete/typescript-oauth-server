/**
 * /oauth/par — RFC 9126 Pushed Authorization Requests.
 *
 * RPs POST their authorization-request parameters here ahead of the user-agent
 * /authorize redirect; the AS returns a `request_uri` the RP then passes
 * through /authorize.
 */

import type { Context } from "hono";
import { Hono } from "hono";
import { authlete } from "../authlete.js";
import { config } from "../config.js";
import { basicCredsFor } from "../auth/basic.js";
import { basicChallengeHeaders, noStoreJsonHeaders } from "../http.js";

export const par = new Hono();

par.post("/oauth/par", async (c) => {
  const parameters = await c.req.text();
  const res = await authlete.pushedAuthorization.create({
    serviceId: config.authleteServiceId,
    pushedAuthorizationRequest: { parameters, ...basicCredsFor(c) },
  });
  return dispatch(c, res.action, res.responseContent);
});

function dispatch(c: Context, action: string | undefined, responseContent: string | undefined): Response {
  const body = responseContent ?? "";
  switch (action) {
    case "CREATED":
      return c.body(body || "{}", 201, noStoreJsonHeaders);
    case "UNAUTHORIZED":
      return c.body(body, 401, basicChallengeHeaders);
    case "FORBIDDEN":
      return c.body(body, 403, noStoreJsonHeaders);
    case "PAYLOAD_TOO_LARGE":
      return c.body(body, 413, noStoreJsonHeaders);
    case "BAD_REQUEST":
      return c.body(body, 400, noStoreJsonHeaders);
    case "INTERNAL_SERVER_ERROR":
    default:
      return c.body(body, 500, noStoreJsonHeaders);
  }
}
