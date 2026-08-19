/**
 * Orchestration over the interactions: which one is next (the state machine) and
 * finalizing the flow — issue or fail — once every required outcome is in. This is
 * the one place that knows about both interactions.
 */

import type { Authlete } from "@authlete/typescript-sdk/authlete";
import type { Config } from "../config.js";
import type { Interaction, StoredContext } from "./context.js";
import { authenticatePayload, authenticationSatisfied } from "./authenticate.js";
import { consentPayload, consentSatisfied } from "./consent.js";

/** The next interaction still unsatisfied for this authorization, or null when all are. */
export function nextInteraction(ctx: StoredContext): Interaction | null {
  if (ctx.authOutcome && "error" in ctx.authOutcome) return null; // failed auth → finalize (fails)
  if (!authenticationSatisfied(ctx)) return "authenticate";
  if (!consentSatisfied(ctx)) return "consent";
  return null;
}

/** The render params an interaction app needs to run this interaction. */
export function interactionPayload(ctx: StoredContext, interaction: Interaction) {
  return interaction === "authenticate" ? authenticatePayload(ctx) : consentPayload(ctx);
}

/**
 * Complete the flow from the accumulated outcomes: `fail` if either interaction
 * was rejected, else `issue` with the subject and the final scope grant. Returns
 * `null` if the flow never completed (no authentication outcome recorded).
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
  // A suppressed (first-party) client is trusted with the full request; otherwise
  // grant what was pre-granted plus what was consented.
  const scopes = ctx.auth.firstParty
    ? ctx.auth.scopes.map((s) => s.name).filter(Boolean)
    : [...new Set([...(ctx.already ?? []), ...consented])];

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
      // hidden → kept out of the access token and RS introspection.
      properties: ctx.consentId
        ? [{ key: "consent_id", value: ctx.consentId, hidden: true }]
        : undefined,
    },
  });
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
