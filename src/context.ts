/**
 * Between-steps context store backed by Authlete's ticket/info + ticket/update.
 *
 * The AS holds no local state. Data that must survive across the authorization
 * flow (the /auth/authorization response, then each interaction's outcome) is
 * JSON-encoded and attached to the Authlete ticket itself.
 *
 * Direct fetch, not the SDK: the published SDK's spec declares ticket/update's
 * `info` field as `string`, but the live API requires `info: { context: string }`
 * (matching the response shape). Speakeasy validates the request body before
 * sending, so a cast doesn't bypass it. Reported upstream.
 */

import type { AuthorizationResponse } from "@authlete/typescript-sdk/models/authorizationresponse";
import type { Config } from "./config.js";

/** Outcome of the authenticate interaction (INTERACTION_PROTOCOL.md §2). */
export type AuthOutcome =
  | {
      subject: string;
      acr?: string;
      amr?: string[];
      authenticatedAt?: number;
      /** Actual user claim values (name, email, …) passed to Authlete /issue. */
      userClaims?: Record<string, unknown>;
    }
  | { error: string; errorDescription?: string };

/** Outcome of the consent interaction. */
export type ConsentOutcome =
  | { grantedScopes: string[] }
  | { error: string; errorDescription?: string };

export type StoredContext = {
  v: 1;
  auth: AuthorizationResponse;
  authOutcome?: AuthOutcome;
  /** Requested scopes the subject had already granted — unioned in at /issue. */
  already?: string[];
  consentOutcome?: ConsentOutcome;
};

function authleteUrl(config: Config, path: string): string {
  return `${config.authleteBaseUrl}/api/${config.authleteServiceId}${path}`;
}

function authHeaders(config: Config) {
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${config.authleteApiToken}`,
  };
}

export async function storeContext(config: Config, ticket: string, ctx: StoredContext): Promise<void> {
  const res = await fetch(authleteUrl(config, "/auth/authorization/ticket/update"), {
    method: "POST",
    headers: authHeaders(config),
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

export async function loadContext(config: Config, ticket: string): Promise<StoredContext | null> {
  const res = await fetch(authleteUrl(config, "/auth/authorization/ticket/info"), {
    method: "POST",
    headers: authHeaders(config),
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
