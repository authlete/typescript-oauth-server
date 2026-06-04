/**
 * HTTP Basic client authentication parser.
 *
 * Returns empty object on malformed input — Authlete will then either fall back
 * to body params / private_key_jwt or reject the request itself.
 */

import type { Context } from "hono";

export function parseBasicAuth(header: string | undefined): {
  clientId?: string;
  clientSecret?: string;
} {
  if (!header) return {};
  const match = /^Basic\s+(.+)$/i.exec(header);
  if (!match) return {};
  try {
    const decoded = Buffer.from(match[1]!.trim(), "base64").toString("utf-8");
    const sep = decoded.indexOf(":");
    if (sep < 0) return {};
    return {
      clientId: decoded.slice(0, sep),
      clientSecret: decoded.slice(sep + 1),
    };
  } catch {
    return {};
  }
}

/** Read Basic creds from the request and produce a spread-ready Authlete payload. */
export function basicCredsFor(c: Context): { clientId?: string; clientSecret?: string } {
  const { clientId, clientSecret } = parseBasicAuth(c.req.header("authorization"));
  const out: { clientId?: string; clientSecret?: string } = {};
  if (clientId) out.clientId = clientId;
  if (clientSecret) out.clientSecret = clientSecret;
  return out;
}
