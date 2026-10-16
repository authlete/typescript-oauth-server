/**
 * HTTP building blocks shared across endpoints.
 *
 * RFC 6749 §5.1 / §5.2 require Cache-Control: no-store + Pragma: no-cache
 * on every token-bearing response and error.
 */

import type { Context } from "hono";
import type { ContentfulStatusCode, StatusCode } from "hono/utils/http-status";

export const jsonHeaders = { "content-type": "application/json" } as const;

export const noStoreHeaders = {
  "cache-control": "no-store",
  pragma: "no-cache",
} as const;

export const noStoreJsonHeaders = {
  ...noStoreHeaders,
  "content-type": "application/json",
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
  extraHeaders: Record<string, string> = {},
): Response {
  return c.body(null, status, { "WWW-Authenticate": wwwAuth, ...extraHeaders });
}

export function extractBearer(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1]?.trim() || undefined;
}

/** RFC 9449 §7.1: a DPoP-bound access token travels as `Authorization: DPoP <token>`. */
export function extractDpopToken(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const match = /^DPoP\s+(.+)$/i.exec(header);
  return match?.[1]?.trim() || undefined;
}

/**
 * DPoP proof + HTTP method to hand Authlete for proof validation (RFC 9449).
 * `htu` is intentionally omitted: Authlete uses the endpoint URL from the
 * service's own configuration, so the AS holds no endpoint knowledge.
 */
export function dpopParams(c: Context): { dpop: string | undefined; htm: string } {
  return { dpop: c.req.header("DPoP"), htm: c.req.method };
}

/**
 * The `DPoP-Nonce` response header the AS must echo when Authlete supplies a
 * nonce (RFC 9449 §8–§9). Absent otherwise.
 */
export function dpopNonceHeader(res: { dpopNonce?: string | undefined }): Record<string, string> {
  return res.dpopNonce ? { "DPoP-Nonce": res.dpopNonce } : {};
}

/**
 * HTTP Basic client authentication parser. Returns an empty object on
 * malformed input — Authlete then falls back to body params /
 * private_key_jwt or rejects the request itself.
 */
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

/** How one Authlete action maps to HTTP. A bare number is just the status. */
export type ActionMapping =
  | number
  | {
      status: number;
      /** Defaults to no-store JSON. */
      headers?: Record<string, string>;
      /** Defaults to Authlete's responseContent; `null` sends an empty body. */
      body?: string | null;
    };

/**
 * Send an Authlete response by looking its `action` up in a per-endpoint map.
 * Unmapped actions become a 500 `server_error` naming the action. When Authlete
 * returns a DPoP nonce, the `DPoP-Nonce` header is added automatically (RFC 9449),
 * so callers don't repeat that per endpoint.
 */
export function sendAuthleteAction(
  c: Context,
  res: { action?: string; responseContent?: string | undefined; dpopNonce?: string | undefined },
  map: Record<string, ActionMapping>,
): Response {
  const entry = map[res.action ?? ""];
  if (entry === undefined) {
    return c.body(
      JSON.stringify({
        error: "server_error",
        error_description: `Unexpected Authlete action: ${res.action ?? "<missing>"}`,
      }),
      500,
      noStoreJsonHeaders,
    );
  }
  const mapping = typeof entry === "number" ? { status: entry } : entry;
  const headers = { ...(mapping.headers ?? noStoreJsonHeaders), ...dpopNonceHeader(res) };
  const body = mapping.body !== undefined ? mapping.body : (res.responseContent ?? "");
  if (body === null) return c.body(null, mapping.status as StatusCode, headers);
  return c.body(body, mapping.status as ContentfulStatusCode, headers);
}

/**
 * Dispatch an Authlete authorization response (the browser-facing LOCATION /
 * FORM / BAD_REQUEST / INTERNAL_SERVER_ERROR action set returned by
 * /authorization, /authorization/issue, and /authorization/fail).
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
