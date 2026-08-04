/**
 * /oauth/revoke — RFC 7009 OAuth 2.0 Token Revocation.
 *
 * Per RFC 7009 §2.2, 200 OK is returned for both successful revocation and
 * already-invalid tokens (no information leak). 400/401 only for malformed
 * requests / unknown client.
 */

import { Hono } from "hono";
import type { Deps } from "../app.js";
import { basicChallengeHeaders, basicCredsFor, sendAuthleteAction } from "../http.js";

export function revokeRoutes({ authlete, config }: Deps) {
  const revoke = new Hono();

  revoke.post("/oauth/revoke", async (c) => {
    const parameters = await c.req.text();
    const res = await authlete.revocation.process({
      serviceId: config.authleteServiceId,
      revocationRequest: { parameters, ...basicCredsFor(c) },
    });
    return sendAuthleteAction(c, res, {
      OK: { status: 200, body: "" },
      INVALID_CLIENT: { status: 401, headers: basicChallengeHeaders },
      BAD_REQUEST: 400,
      INTERNAL_SERVER_ERROR: 500,
    });
  });

  return revoke;
}
