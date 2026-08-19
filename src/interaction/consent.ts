/**
 * The consent interaction: record its outcome, decide whether it's required for
 * this authorization, and expose whether it's satisfied and what params the app
 * renders.
 */

import type { Config } from "../config.js";
import type { ConsentOutcome, StoredContext } from "./context.js";
import { store } from "./ticket-store.js";

/** Consent is satisfied when it isn't required, or its outcome has been recorded. */
export function consentSatisfied(ctx: StoredContext): boolean {
  return !consentRequired(ctx) || !!ctx.consentOutcome;
}

/**
 * Consent is required unless suppressed (a trusted first-party client), and only
 * when there is something to consent to — new (not-yet-granted) scopes or RAR.
 */
function consentRequired(ctx: StoredContext): boolean {
  if (ctx.auth.firstParty) return false; // trusted client — consent suppressed
  const already = ctx.already ?? [];
  const hasNewScope = ctx.auth.scopes.some((s) => s.name && !already.includes(s.name));
  return hasNewScope || ctx.auth.authorizationDetails.length > 0;
}

/** The params the app renders for the consent interaction. */
export function consentPayload(ctx: StoredContext) {
  const already = ctx.already ?? [];
  return {
    new: ctx.auth.scopes.filter((s) => !already.includes(s.name)),
    already_granted: ctx.auth.scopes.filter((s) => already.includes(s.name)),
    authorization_details: ctx.auth.authorizationDetails,
  };
}

/**
 * Record the consent outcome (and the consent-record id the consent UI reports,
 * so it can be linked to the grant at /token). The flow is then ready to finalize.
 */
export async function recordConsent(
  config: Config,
  id: string,
  ctx: StoredContext,
  outcome: ConsentOutcome,
  consentId?: string,
): Promise<StoredContext> {
  return store(config, id, {
    ...ctx,
    consentOutcome: outcome,
    consentId: consentId ?? ctx.consentId,
  });
}
