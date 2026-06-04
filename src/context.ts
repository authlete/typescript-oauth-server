/**
 * Between-steps context store backed by Authlete's ticket/info + ticket/update.
 *
 * The AS holds no local state. Data that must survive across the authorization
 * flow (the /auth/authorization response, then the user's decision) is
 * JSON-encoded and attached to the Authlete ticket itself.
 *
 * Direct fetch, not the SDK: the published SDK's spec declares ticket/update's
 * `info` field as `string`, but the live API requires `info: { context: string }`
 * (matching the response shape). Speakeasy validates the request body before
 * sending, so a cast doesn't bypass it. Reported upstream.
 */

import type { AuthorizationResponse } from "@authlete/typescript-sdk/models/authorizationresponse";
import { config } from "./config.js";

export type Decision =
  | {
      outcome: "approved";
      subject: string;
      acr?: string;
      amr?: string[];
      authenticatedAt?: number;
      grantedScopes?: string[];
      /** Actual user claim values (name, email, …) passed to Authlete /issue. */
      userClaims?: Record<string, unknown>;
      /** OIDC claims-request shape echoed back from the RP, if needed. */
      grantedClaims?: Record<string, unknown>;
    }
  | {
      outcome: "denied";
      error: string;
      errorDescription?: string;
    };

export type StoredContext = {
  v: 1;
  auth: AuthorizationResponse;
  decision?: Decision;
};

function authleteUrl(path: string): string {
  return `${config.authleteBaseUrl}/api/${config.authleteServiceId}${path}`;
}

function authHeaders() {
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${config.authleteApiToken}`,
  };
}

export async function storeContext(ticket: string, ctx: StoredContext): Promise<void> {
  const res = await fetch(authleteUrl("/auth/authorization/ticket/update"), {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({
      ticket,
      info: { context: JSON.stringify(ctx) },
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Authlete ticket/update failed (${res.status}): ${body}`);
  }
}

export async function loadContext(ticket: string): Promise<StoredContext | null> {
  const res = await fetch(authleteUrl("/auth/authorization/ticket/info"), {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify({ ticket }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Authlete ticket/info failed (${res.status}): ${body}`);
  }
  const payload = (await res.json()) as {
    action?: string;
    info?: { context?: string };
  };
  if (payload.action === "NOT_FOUND") return null;
  const raw = payload.info?.context;
  if (!raw) return null;
  try {
    return JSON.parse(raw) as StoredContext;
  } catch {
    return null;
  }
}
