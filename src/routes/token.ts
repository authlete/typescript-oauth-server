/**
 * /oauth/token — OAuth 2.0 token endpoint.
 *
 * Form body → Authlete /auth/token → dispatch on response action.
 * Authlete picks the client-auth method (basic/post/private_key_jwt/none)
 * based on client registration; we just forward the parsed Basic credentials.
 */

import { Hono } from "hono";
import type { Deps } from "../app.js";
import { basicChallengeHeaders, basicCredsFor, sendAuthleteAction } from "../http.js";
import { onGrantIssued } from "../grant-lifecycle.js";

/** Grant flows Authlete supports but this AS has not implemented. */
const unsupportedGrant = (action: string) => ({
  status: 400,
  body: JSON.stringify({
    error: "unsupported_grant_type",
    error_description: `Grant flow ${action} is not implemented.`,
  }),
});

export function tokenRoutes({ authlete, config }: Deps) {
  const token = new Hono();

  token.post("/oauth/token", async (c) => {
    const parameters = await c.req.text();
    const res = await authlete.token.process({
      serviceId: config.authleteServiceId,
      tokenRequest: { parameters, ...basicCredsFor(c) },
    });

    // A grant surfaces here when grant management was used — run post-processing.
    await onGrantIssued(config, res);

    return sendAuthleteAction(c, res, {
      OK: 200,
      INVALID_CLIENT: { status: 401, headers: basicChallengeHeaders },
      BAD_REQUEST: 400,
      INTERNAL_SERVER_ERROR: 500,
      PASSWORD: unsupportedGrant("PASSWORD"),
      TOKEN_EXCHANGE: unsupportedGrant("TOKEN_EXCHANGE"),
      JWT_BEARER: unsupportedGrant("JWT_BEARER"),
      NATIVE_SSO: unsupportedGrant("NATIVE_SSO"),
      ID_TOKEN_REISSUABLE: unsupportedGrant("ID_TOKEN_REISSUABLE"),
    });
  });

  return token;
}
