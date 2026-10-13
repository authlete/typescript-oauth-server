/** Device Authorization Grant (RFC 8628) — the client-facing device authorization request. Verification + outcome are interaction endpoints (interaction/routes.ts). See INTERACTION_PROTOCOL.md. */

import { Hono } from "hono";
import type { Deps } from "../app.js";
import { basicChallengeHeaders, basicCredsFor, sendAuthleteAction } from "../http.js";

export function deviceRoutes({ authlete, config }: Deps) {
  const device = new Hono();

  device.post("/api/device/authorization", async (c) => {
    const parameters = await c.req.text();
    const res = await authlete.deviceFlow.authorization({
      serviceId: config.authleteServiceId,
      deviceAuthorizationRequest: { parameters, ...basicCredsFor(c) },
    });
    return sendAuthleteAction(c, res, {
      OK: 200,
      BAD_REQUEST: 400,
      UNAUTHORIZED: { status: 401, headers: basicChallengeHeaders },
      INTERNAL_SERVER_ERROR: 500,
    });
  });

  return device;
}
