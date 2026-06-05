/**
 * Interaction-protocol authentication: per-request JWT in the Authorization
 * Bearer header. Verifies against auth-ui's published JWKS and returns the
 * decoded payload. See INTERACTION_PROTOCOL.md §4–§5.
 */

import type { Context } from "hono";
import type { JWTPayload } from "jose";
import { extractBearer, noStoreJsonHeaders } from "../http.js";
import { verifyJwt } from "../jws.js";

const CHALLENGE = 'Bearer realm="authlete-as", error="invalid_token"';

export type InteractionAuthContext = {
  payload: JWTPayload;
};

/**
 * Validate an inbound interaction protocol JWT. Returns either a verified
 * payload context or a `Response` the caller should return verbatim.
 */
export async function requireJws(c: Context): Promise<InteractionAuthContext | Response> {
  const jwt = extractBearer(c.req.header("authorization"));
  if (!jwt) {
    return c.body(
      JSON.stringify({ error: "invalid_request", error_description: "missing Authorization Bearer JWT" }),
      401,
      { ...noStoreJsonHeaders, "www-authenticate": CHALLENGE },
    );
  }
  try {
    const payload = await verifyJwt(jwt);
    return { payload };
  } catch (err) {
    return c.body(
      JSON.stringify({ error: "invalid_token", error_description: (err as Error).message }),
      401,
      { ...noStoreJsonHeaders, "www-authenticate": CHALLENGE },
    );
  }
}
