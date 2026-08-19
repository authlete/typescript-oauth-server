/**
 * /api/gm/{grantId} — Grant Management for OAuth 2.0.
 *
 * Bearer-protected: the RP presents its access token, which the AS forwards to
 * Authlete. GET queries a grant, DELETE revokes it.
 *
 * @see https://openid.net/specs/fapi-grant-management.html
 */

import type { Context } from "hono";
import { Hono } from "hono";
import type { GrantManagementAction } from "@authlete/typescript-sdk/models";
import type { Deps } from "../app.js";
import {
  bearerAuthChallenge,
  bearerChallenge,
  extractBearer,
  noStoreJsonHeaders,
  sendAuthleteAction,
} from "../http.js";
import { onGrantRevoked } from "../grant-lifecycle.js";

export function gmRoutes({ authlete, config }: Deps) {
  const gm = new Hono();

  const handle = (gmAction: GrantManagementAction) => async (c: Context) => {
    const accessToken = extractBearer(c.req.header("authorization"));
    if (!accessToken) return bearerChallenge(c, 401);

    const grantId = c.req.param("grantId");
    const res = await authlete.grantManagement.processRequest({
      serviceId: config.authleteServiceId,
      gMRequest: { gmAction, grantId, accessToken },
    });

    if (gmAction === "REVOKE" && res.action === "NO_CONTENT" && grantId) {
      await onGrantRevoked(config, grantId);
    }

    // 401/403 carry the challenge in WWW-Authenticate, not the body.
    const challenge = {
      ...noStoreJsonHeaders,
      "www-authenticate": res.responseContent || bearerAuthChallenge,
    };
    return sendAuthleteAction(c, res, {
      OK: 200,
      NO_CONTENT: { status: 204, body: null },
      UNAUTHORIZED: { status: 401, headers: challenge, body: null },
      FORBIDDEN: { status: 403, headers: challenge, body: null },
      NOT_FOUND: 404,
      CALLER_ERROR: 500,
      AUTHLETE_ERROR: 500,
    });
  };

  gm.get("/api/gm/:grantId", handle("QUERY"));
  gm.delete("/api/gm/:grantId", handle("REVOKE"));

  return gm;
}
