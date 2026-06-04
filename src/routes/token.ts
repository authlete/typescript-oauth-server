/**
 * /oauth/token — OAuth 2.0 token endpoint.
 *
 * Form body → Authlete /auth/token → dispatch on response action.
 * Authlete picks the client-auth method (basic/post/private_key_jwt/none)
 * based on client registration; we just forward the parsed Basic credentials.
 */

import type { Context } from "hono";
import { Hono } from "hono";
import { authlete } from "../authlete.js";
import { config } from "../config.js";
import { basicCredsFor } from "../auth/basic.js";
import { basicChallengeHeaders, noStoreJsonHeaders } from "../http.js";

export const token = new Hono();

token.post("/oauth/token", async (c) => {
  const parameters = await c.req.text();
  const res = await authlete.token.process({
    serviceId: config.authleteServiceId,
    tokenRequest: { parameters, ...basicCredsFor(c) },
  });
  return dispatch(c, res.action, res.responseContent);
});

function dispatch(c: Context, action: string | undefined, responseContent: string | undefined): Response {
  const body = responseContent ?? "";
  switch (action) {
    case "OK":
      return c.body(body, 200, noStoreJsonHeaders);
    case "INVALID_CLIENT":
      return c.body(body, 401, basicChallengeHeaders);
    case "BAD_REQUEST":
      return c.body(body, 400, noStoreJsonHeaders);
    case "INTERNAL_SERVER_ERROR":
      return c.body(body, 500, noStoreJsonHeaders);
    case "PASSWORD":
    case "TOKEN_EXCHANGE":
    case "JWT_BEARER":
    case "NATIVE_SSO":
    case "ID_TOKEN_REISSUABLE":
      return c.body(
        JSON.stringify({
          error: "unsupported_grant_type",
          error_description: `Grant flow ${action} is not implemented.`,
        }),
        400,
        noStoreJsonHeaders,
      );
    default:
      return c.body(
        JSON.stringify({
          error: "server_error",
          error_description: `Unexpected Authlete action: ${action ?? "<missing>"}`,
        }),
        500,
        noStoreJsonHeaders,
      );
  }
}
