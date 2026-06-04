/**
 * Bearer-token validation for AS endpoints that auth-ui calls.
 *
 * Validation is delegated to Authlete via the introspection API. We pass the
 * required scopes; Authlete answers FORBIDDEN if they're missing.
 */

import type { Context } from "hono";
import { authlete } from "../authlete.js";
import { config } from "../config.js";
import { bearerAuthChallenge, bearerChallenge, extractBearer } from "../http.js";

export const INTERACTION_SCOPE = "urn:authlete-as:interactions";

export type BearerContext = {
  clientId: number;
  subject?: string;
  scopes: string[];
};

/**
 * Validates the Authorization Bearer header and checks required scopes.
 * Returns either a `BearerContext` (success) or a `Response` the caller
 * should return verbatim (auth failure).
 */
export async function requireBearer(
  c: Context,
  requiredScopes: string[],
): Promise<BearerContext | Response> {
  const token = extractBearer(c.req.header("authorization"));
  if (!token) return bearerChallenge(c, 401);

  const res = await authlete.introspection.process({
    serviceId: config.authleteServiceId,
    introspectionRequest: { token, scopes: requiredScopes },
  });

  const wwwAuth = res.responseContent ?? bearerAuthChallenge;
  switch (res.action) {
    case "OK":
      return {
        clientId: res.clientId ?? 0,
        subject: res.subject,
        scopes: res.scopes ?? [],
      };
    case "UNAUTHORIZED":
      return bearerChallenge(c, 401, wwwAuth);
    case "FORBIDDEN":
      return bearerChallenge(c, 403, wwwAuth);
    case "BAD_REQUEST":
      return c.body(res.responseContent ?? "", 400);
    case "INTERNAL_SERVER_ERROR":
    default:
      return c.body(res.responseContent ?? "", 500);
  }
}
