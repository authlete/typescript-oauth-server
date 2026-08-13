/**
 * The AS side of the Externalized Login & Consent pattern — the one place this
 * server makes decisions of its own. Everything else is a thin relay: Authlete
 * owns the OAuth protocol, auth-ui owns the screens. What's left to the AS is
 * orchestrating the two interactions in between:
 *
 *   authenticate → consent (only for scopes not already granted) → issue/fail
 *
 * State lives on the Authlete ticket (ticket/update + ticket/info) — the AS
 * holds no local state. Data that must survive across the flow (the
 * /auth/authorization response, then each interaction's outcome) is
 * JSON-encoded and attached to the ticket itself.
 */

import type { Authlete } from "@authlete/typescript-sdk/authlete";
import type { AuthorizationResponse } from "@authlete/typescript-sdk/models/authorizationresponse";
import { Prompt } from "@authlete/typescript-sdk/models/prompt";
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
  { grantedScopes: string[] } | { error: string; errorDescription?: string };

export type StoredContext = {
  v: 1;
  auth: AuthorizationResponse;
  authOutcome?: AuthOutcome;
  /** Requested scopes the subject had already granted — unioned in at /issue. */
  already?: string[];
  consentOutcome?: ConsentOutcome;
};

export type Scope = { name: string; description?: string };

export type RarElement = Record<string, unknown>;

/** What auth-ui must do next, decided after a reported outcome. */
export type NextStep =
  | { next: "done" }
  | {
      next: "consent";
      newScopes: Scope[];
      alreadyGranted: Scope[];
      authorizationDetails: RarElement[];
    };

/**
 * Record the authenticate outcome and decide the next step: skip consent when
 * every requested scope is already granted to this subject (unless the request
 * forces it with prompt=consent), else consent — split into new vs already-granted.
 * RAR (authorization_details) is per-request, so its presence always requires consent.
 */
export async function recordAuthentication(
  authlete: Authlete,
  config: Config,
  id: string,
  ctx: StoredContext,
  outcome: AuthOutcome,
): Promise<NextStep> {
  if ("error" in outcome) {
    await storeContext(config, id, { ...ctx, authOutcome: outcome });
    return { next: "done" };
  }

  const requested: Scope[] = (ctx.auth.scopes ?? []).map((s) => ({
    name: s.name ?? "",
    description: s.description,
  }));
  // prompt=consent re-confirms the whole request, so nothing counts as pre-granted.
  const forced = (ctx.auth.prompts ?? []).includes(Prompt.Consent);
  const granted = forced
    ? []
    : await alreadyGrantedScopes(authlete, config, ctx.auth, outcome.subject);
  const newScopes = requested.filter((s) => !granted.includes(s.name));
  const alreadyGranted = requested.filter((s) => granted.includes(s.name));
  const authorizationDetails = normalizeRar(
    (ctx.auth.authorizationDetails?.elements ?? []) as RarElement[],
  );

  await storeContext(config, id, {
    ...ctx,
    authOutcome: outcome,
    already: alreadyGranted.map((s) => s.name),
  });

  if (newScopes.length === 0 && authorizationDetails.length === 0) {
    return { next: "done" };
  }
  return { next: "consent", newScopes, alreadyGranted, authorizationDetails };
}

/** Un-fold Authlete's stringified `otherFields` back into plain RFC 9396 elements. */
function normalizeRar(elements: RarElement[]): RarElement[] {
  return elements.map((el) => {
    const { otherFields, ...rest } = el;
    if (typeof otherFields !== "string") return rest;
    try {
      return { ...rest, ...(JSON.parse(otherFields) as Record<string, unknown>) };
    } catch {
      return rest;
    }
  });
}

/** Record the consent outcome; the flow is then ready to finalize. */
export async function recordConsent(
  config: Config,
  id: string,
  ctx: StoredContext,
  outcome: ConsentOutcome,
): Promise<void> {
  await storeContext(config, id, { ...ctx, consentOutcome: outcome });
}

/**
 * Complete the flow from the accumulated outcomes: `fail` if either interaction
 * was rejected, `issue` with the subject and the final scope grant
 * (already-granted ∪ newly consented) otherwise. Returns `null` if the flow
 * never completed (no authentication outcome recorded).
 */
export async function finalize(
  authlete: Authlete,
  config: Config,
  id: string,
  ctx: StoredContext,
): Promise<{ action?: string; responseContent?: string } | null> {
  const failure =
    (ctx.authOutcome && "error" in ctx.authOutcome ? ctx.authOutcome : null) ??
    (ctx.consentOutcome && "error" in ctx.consentOutcome ? ctx.consentOutcome : null);
  if (failure) {
    return authlete.authorization.fail({
      serviceId: config.authleteServiceId,
      authorizationFailRequest: { ticket: id, reason: mapDenyReason(failure.error) },
    });
  }

  if (!ctx.authOutcome || "error" in ctx.authOutcome) return null;
  const auth = ctx.authOutcome;
  const consent = ctx.consentOutcome;
  const consented = consent && "grantedScopes" in consent ? consent.grantedScopes : [];
  const scopes = [...new Set([...(ctx.already ?? []), ...consented])];

  // TODO(claims-leakage): also pass `consentedClaims` so Authlete persists it
  // and echoes it at /userinfo. See routes/userinfo.ts top-of-file TODO.
  return authlete.authorization.issue({
    serviceId: config.authleteServiceId,
    authorizationIssueRequest: {
      ticket: id,
      subject: auth.subject,
      authTime: auth.authenticatedAt,
      acr: auth.acr,
      claims: auth.userClaims ? JSON.stringify(auth.userClaims) : undefined,
      scopes,
    },
  });
}

/**
 * Scopes the subject has already granted to this client. Best-effort: any
 * failure (feature off, no prior grant, error) yields `[]`, so the flow falls
 * back to full consent. See INTERACTION_PROTOCOL.md §2.
 */
async function alreadyGrantedScopes(
  authlete: Authlete,
  config: Config,
  auth: AuthorizationResponse,
  subject: string,
): Promise<string[]> {
  const clientId = auth.client?.clientId;
  if (typeof clientId !== "number") return [];
  try {
    const res = await authlete.clientManagement.clientGrantedScopesGetApi({
      serviceId: config.authleteServiceId,
      clientId: String(clientId),
      subject,
    });
    return res.mergedGrantedScopes ?? [];
  } catch {
    return [];
  }
}

function mapDenyReason(error: string): "DENIED" | "NOT_LOGGED_IN" | "CONSENT_REQUIRED" | "UNKNOWN" {
  switch (error) {
    case "access_denied":
      return "DENIED";
    case "login_required":
      return "NOT_LOGGED_IN";
    case "consent_required":
      return "CONSENT_REQUIRED";
    default:
      return "UNKNOWN";
  }
}

// --- ticket-backed state store ----------------------------------------------
//
// Direct fetch, not the SDK: the published SDK's spec declares ticket/update's
// `info` field as `string`, but the live API requires `info: { context: string }`
// (matching the response shape). Speakeasy validates the request body before
// sending, so a cast doesn't bypass it. Reported upstream.

function authleteUrl(config: Config, path: string): string {
  return `${config.authleteBaseUrl}/api/${config.authleteServiceId}${path}`;
}

function authHeaders(config: Config) {
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${config.authleteApiToken}`,
  };
}

export async function storeContext(
  config: Config,
  ticket: string,
  ctx: StoredContext,
): Promise<void> {
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
