/**
 * The authenticate interaction: record its outcome, resolve the facts the consent
 * decision will later need (already-granted scopes, first-party status), and
 * expose whether it's satisfied and what params the app renders.
 */

import type { Authlete } from "@authlete/typescript-sdk/authlete";
import { Prompt } from "@authlete/typescript-sdk/models/prompt";
import type { Config } from "../config.js";
import type { AuthContext, AuthOutcome, StoredContext } from "./context.js";
import { store } from "./ticket-store.js";

/**
 * Whether authentication is satisfied. Today: an outcome is present. Step-up / SCA
 * seam: this is where a required level (acr) would be checked against the reported
 * acr and, if unmet, re-drive authenticate — the AS trusts the reported acr as
 * Authlete does (§2.1), so any enforcement added here must mirror Authlete rather
 * than re-derive policy.
 */
export function authenticationSatisfied(ctx: StoredContext): boolean {
  return !!ctx.authOutcome;
}

/** The params auth-ui renders for the authenticate interaction. */
export function authenticatePayload(ctx: StoredContext) {
  const a = ctx.auth;
  return {
    acr_values: a.acrs,
    max_age: a.maxAge,
    // Authlete returns prompt values UPPERCASE; forward the standard lowercase.
    prompt: a.prompts.map((p) => p.toLowerCase()).join(" ") || undefined,
    login_hint: a.loginHint,
    ui_locales: a.uiLocales,
  };
}

/**
 * Record the authenticate outcome and the facts the consent decision needs: the
 * requested scopes already granted to this subject (prompt=consent re-confirms
 * the whole request, so none count), and whether the client is a trusted
 * first-party client. No policy here — just the recorded facts.
 */
export async function recordAuthentication(
  authlete: Authlete,
  config: Config,
  id: string,
  ctx: StoredContext,
  outcome: AuthOutcome,
): Promise<StoredContext> {
  if ("error" in outcome) return store(config, id, { ...ctx, authOutcome: outcome });

  const forced = ctx.auth.prompts.includes(Prompt.Consent);
  const granted = forced
    ? []
    : await alreadyGrantedScopes(authlete, config, ctx.auth, outcome.subject);
  const already = ctx.auth.scopes.filter((s) => granted.includes(s.name)).map((s) => s.name);
  const firstParty = await isFirstParty(authlete, config, ctx.auth.client);

  return store(config, id, {
    ...ctx,
    auth: { ...ctx.auth, firstParty },
    authOutcome: outcome,
    already,
  });
}

/**
 * Scopes the subject has already granted to this client. Best-effort: any failure
 * (feature off, no prior grant, error) yields `[]`, so the flow falls back to full
 * consent. See INTERACTION_PROTOCOL.md §2.
 */
async function alreadyGrantedScopes(
  authlete: Authlete,
  config: Config,
  auth: AuthContext,
  subject: string,
): Promise<string[]> {
  const clientId = auth.client.clientId;
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

// First-party status is client configuration in Authlete (a `first_party=true`
// attribute), so it's fixed for the process — cache it per client id.
const firstPartyCache = new Map<string, boolean>();

/**
 * Whether the client is marked first-party via a `first_party=true` attribute on
 * its Authlete client record. The authorization response carries only a limited
 * client, so read the full client once (then cache).
 */
async function isFirstParty(
  authlete: Authlete,
  config: Config,
  client: AuthContext["client"],
): Promise<boolean> {
  const clientId = client.clientId != null ? String(client.clientId) : client.clientIdAlias;
  if (!clientId) return false;

  const cached = firstPartyCache.get(clientId);
  if (cached !== undefined) return cached;

  let firstParty = false;
  try {
    const full = await authlete.client.get({ serviceId: config.authleteServiceId, clientId });
    firstParty =
      full.attributes?.some((a) => a.key === "first_party" && a.value === "true") ?? false;
  } catch {
    firstParty = false; // treat an unreadable client as not first-party
  }
  firstPartyCache.set(clientId, firstParty);
  return firstParty;
}
