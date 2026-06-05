/**
 * Outbound client from the AS to `auth-ui`.
 *
 * Authenticates each request by signing a fresh JWT with the AS's
 * interaction protocol key; auth-ui verifies via the AS's published JWKS.
 * See INTERACTION_PROTOCOL.md §7.3.
 */

import { config } from "./config.js";
import { signJwt } from "./jws.js";

export async function fetchUser(id: string): Promise<Record<string, unknown> | null> {
  const url = `${config.authUiUrl}/api/users/${encodeURIComponent(id)}`;
  const jwt = await signJwt({});
  const res = await fetch(url, {
    headers: { authorization: `Bearer ${jwt}` },
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(`auth-ui /api/users returned ${res.status}: ${await res.text()}`);
  }
  return (await res.json()) as Record<string, unknown>;
}
