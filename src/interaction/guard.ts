/**
 * Inbound guard for the interaction protocol: verifies the caller's per-request
 * JWT (Authorization Bearer) against the calling app's published JWKS, selected
 * by the token's `iss`, and returns the decoded payload. See
 * INTERACTION_PROTOCOL.md §4–§5.
 */

import type { Context } from "hono";
import type { JWTPayload } from "jose";
import type { Config } from "../config.js";
import { extractBearer, noStoreJsonHeaders } from "../http.js";
import { verifyJwt } from "./jwt.js";

const CHALLENGE = 'Bearer realm="authlete-as", error="invalid_token"';

export type VerifiedCaller = {
  payload: JWTPayload;
};

/**
 * Validate an inbound interaction protocol JWT. Returns either a verified
 * caller context or a `Response` the caller should return verbatim.
 */
export async function requireInteractionJwt(
  c: Context,
  config: Config,
): Promise<VerifiedCaller | Response> {
  const jwt = extractBearer(c.req.header("authorization"));
  if (!jwt) {
    return c.body(
      JSON.stringify({
        error: "invalid_request",
        error_description: "missing Authorization Bearer JWT",
      }),
      401,
      { ...noStoreJsonHeaders, "www-authenticate": CHALLENGE },
    );
  }
  try {
    const payload = await verifyJwt(config, jwt);
    return { payload };
  } catch (err) {
    return c.body(
      JSON.stringify({ error: "invalid_token", error_description: (err as Error).message }),
      401,
      { ...noStoreJsonHeaders, "www-authenticate": CHALLENGE },
    );
  }
}
