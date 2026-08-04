/**
 * /oauth/par — RFC 9126 Pushed Authorization Requests.
 *
 * RPs POST their authorization-request parameters here ahead of the user-agent
 * /authorize redirect; the AS returns a `request_uri` the RP then passes
 * through /authorize.
 */

import { Hono } from "hono";
import type { Deps } from "../app.js";
import { basicChallengeHeaders, basicCredsFor, sendAuthleteAction } from "../http.js";

export function parRoutes({ authlete, config }: Deps) {
  const par = new Hono();

  par.post("/oauth/par", async (c) => {
    const parameters = await c.req.text();
    const res = await authlete.pushedAuthorization.create({
      serviceId: config.authleteServiceId,
      pushedAuthorizationRequest: { parameters, ...basicCredsFor(c) },
    });
    return sendAuthleteAction(c, res, {
      CREATED: { status: 201, body: res.responseContent || "{}" },
      UNAUTHORIZED: { status: 401, headers: basicChallengeHeaders },
      FORBIDDEN: 403,
      PAYLOAD_TOO_LARGE: 413,
      BAD_REQUEST: 400,
      INTERNAL_SERVER_ERROR: 500,
    });
  });

  return par;
}
