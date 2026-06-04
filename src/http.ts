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
