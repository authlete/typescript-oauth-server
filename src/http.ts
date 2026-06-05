/**
 * HTTP response building blocks shared across endpoints.
 *
 * RFC 6749 §5.1 / §5.2 require Cache-Control: no-store + Pragma: no-cache
 * on every token-bearing response and error.
 */

import type { Context } from "hono";

export const jsonHeaders = { "content-type": "application/json" } as const;

export const noStoreJsonHeaders = {
  "content-type": "application/json",
  "cache-control": "no-store",
  pragma: "no-cache",
} as const;

export const basicAuthChallenge = 'Basic realm="authlete-as"';
export const bearerAuthChallenge = 'Bearer realm="authlete-as"';

export const basicChallengeHeaders = {
  ...noStoreJsonHeaders,
  "www-authenticate": basicAuthChallenge,
} as const;

export function bearerChallenge(
  c: Context,
  status: 400 | 401 | 403,
  wwwAuth: string = bearerAuthChallenge,
): Response {
  return c.body(null, status, { "WWW-Authenticate": wwwAuth });
}

export function extractBearer(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1]?.trim() || undefined;
}

/**
 * Dispatch an Authlete authorization response (the common LOCATION / FORM /
 * BAD_REQUEST / INTERNAL_SERVER_ERROR action set returned by /authorization,
 * /authorization/issue, and /authorization/fail).
 */
export function dispatchAuthleteAction(
  c: Context,
  action: string | undefined,
  responseContent: string | undefined,
): Response {
  switch (action) {
    case "LOCATION":
      return c.redirect(responseContent ?? "", 302);
    case "FORM":
      return c.html(responseContent ?? "");
    case "BAD_REQUEST":
      return c.body(responseContent ?? "{}", 400, jsonHeaders);
    case "INTERNAL_SERVER_ERROR":
    default:
      return c.body(responseContent ?? "{}", 500, jsonHeaders);
  }
}
