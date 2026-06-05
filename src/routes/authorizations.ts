/**
 * Component protocol surface on the AS.
 *
 *   API (called by auth-ui server-to-server, JWT-bearer-authenticated):
 *     GET  /api/authorizations/{id}              — fetch in-flight state
 *     POST /api/authorizations/{id}/decision     — submit user's decision
 *
 *   Browser (auth-ui redirects the user back here after the decision):
 *     GET  /authorizations/{id}/resume           — completes the flow,
 *                                                  redirects browser to RP
 *
 * `{id}` is the opaque authorization-transaction id (backed by an Authlete
 * ticket). See INTERACTION_PROTOCOL.md §6–§7.
 */

import type { Context } from "hono";
import { Hono } from "hono";
import { authlete } from "../authlete.js";
import { config } from "../config.js";
import { loadContext, storeContext, type Decision, type StoredContext } from "../context.js";
import { dispatchAuthleteAction } from "../http.js";
import { requireJws, type InteractionAuthContext } from "../auth/interaction-auth.js";

export const authorizations = new Hono();

// --- shared per-route guard -----------------------------------------------

/**
 * Verify the inbound JWT, load the authorization context, and check the JWT's
 * `authorization` claim matches the URL `{id}`. Returns `{auth, ctx}` on
 * success or a `Response` for the caller to return verbatim.
 */
async function requireJwsForAuthorization(
  c: Context,
  id: string,
): Promise<{ auth: InteractionAuthContext; ctx: StoredContext } | Response> {
  const [auth, ctx] = await Promise.all([requireJws(c), loadContext(id)]);
  if (auth instanceof Response) return auth;
  if (!ctx) {
    return c.json({ error: "not_found", error_description: "authorization not found or expired" }, 404);
  }
  if (auth.payload.authorization !== id) {
    return c.json({ error: "invalid_token", error_description: "JWT authorization claim does not match URL" }, 401);
  }
  return { auth, ctx };
}

// --- GET /api/authorizations/:id — fetch in-flight state -------------------

authorizations.get("/api/authorizations/:id", async (c) => {
  const id = c.req.param("id");
  const guard = await requireJwsForAuthorization(c, id);
  if (guard instanceof Response) return guard;

  const a = guard.ctx.auth;
  const client = a.client ?? {};

  return c.json({
    client: {
      client_id: stringIdOrAlias(client),
      name: client.clientName,
      logo_uri: client.logoUri,
      policy_uri: client.policyUri,
      tos_uri: client.tosUri,
    },
    needs: ["authentication", "consent"],
    skip: a.action === "NO_INTERACTION",
    login_hint: a.loginHint,
    prompt: Array.isArray(a.prompts) ? a.prompts.join(" ") : undefined,
    acr_values: a.acrs,
    max_age: typeof a.maxAge === "number" && a.maxAge > 0 ? a.maxAge : undefined,
    ui_locales: a.uiLocales,
    subject: a.subject ?? null,
    requested_scopes: (a.scopes ?? []).map((s) => ({
      name: s.name,
      description: s.description,
    })),
    requested_claims: {
      id_token: a.idTokenClaims,
      userinfo: a.claimsAtUserInfo,
      all: a.claims,
    },
    previously_granted_scopes: [],
  });
});

// --- POST /api/authorizations/:id/decision — submit decision ---------------

type ApprovedDecisionClaim = {
  outcome: "approved";
  subject: string;
  acr?: string;
  amr?: string[];
  authenticated_at?: number;
  granted_scopes?: string[];
  user_claims?: Record<string, unknown>;
  granted_claims?: Record<string, unknown>;
};
type DeniedDecisionClaim = {
  outcome: "denied";
  error: string;
  error_description?: string;
};
type DecisionClaim = ApprovedDecisionClaim | DeniedDecisionClaim;

authorizations.post("/api/authorizations/:id/decision", async (c) => {
  const id = c.req.param("id");
  const guard = await requireJwsForAuthorization(c, id);
  if (guard instanceof Response) return guard;

  const claim = guard.auth.payload.decision as DecisionClaim | undefined;
  if (!claim || !claim.outcome) {
    return c.json({ error: "invalid_token", error_description: "JWT missing decision claim" }, 401);
  }

  const decision: Decision = claim.outcome === "denied"
    ? {
        outcome: "denied",
        error: claim.error,
        errorDescription: claim.error_description,
      }
    : {
        outcome: "approved",
        subject: claim.subject,
        acr: claim.acr,
        amr: claim.amr,
        authenticatedAt: claim.authenticated_at,
        grantedScopes: claim.granted_scopes,
        userClaims: claim.user_claims,
        grantedClaims: claim.granted_claims,
      };

  if (decision.outcome === "approved" && !decision.subject) {
    return c.json(
      { error: "invalid_request", error_description: "subject required for approved decisions" },
      400,
    );
  }

  await storeContext(id, { ...guard.ctx, decision });

  return c.json({
    redirect_to: `${config.asBaseUrl}/authorizations/${encodeURIComponent(id)}/resume`,
  });
});

// --- GET /authorizations/:id/resume — browser returns from auth-ui ---------

authorizations.get("/authorizations/:id/resume", async (c) => {
  const id = c.req.param("id");
  const ctx = await loadContext(id);
  if (!ctx) {
    return c.json({ error: "invalid_request", error_description: "authorization not found or expired" }, 400);
  }
  if (!ctx.decision) {
    return c.json(
      { error: "invalid_request", error_description: "no decision recorded for this authorization" },
      400,
    );
  }

  if (ctx.decision.outcome === "denied") {
    const res = await authlete.authorization.fail({
      serviceId: config.authleteServiceId,
      authorizationFailRequest: {
        ticket: id,
        reason: mapDenyReason(ctx.decision.error),
      },
    });
    return dispatchAuthleteAction(c, res.action, res.responseContent);
  }

  // TODO(claims-leakage): we should also pass `consentedClaims` here so
  // Authlete persists it against the token and echoes it back at /userinfo.
  // Currently we only pass claim VALUES via `claims`; Authlete auto-derives
  // consentedClaims from scopes/values, which breaks once we support
  // per-claim consent. See routes/userinfo.ts top-of-file TODO for the
  // complete contract and the auth-ui-side changes needed.
  const res = await authlete.authorization.issue({
    serviceId: config.authleteServiceId,
    authorizationIssueRequest: {
      ticket: id,
      subject: ctx.decision.subject,
      authTime: ctx.decision.authenticatedAt,
      acr: ctx.decision.acr,
      claims: ctx.decision.userClaims ? JSON.stringify(ctx.decision.userClaims) : undefined,
      scopes: ctx.decision.grantedScopes,
    },
  });
  return dispatchAuthleteAction(c, res.action, res.responseContent);
});

// --- helpers ---------------------------------------------------------------

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

function stringIdOrAlias(client: { clientId?: number; clientIdAlias?: string }): string {
  if (client.clientIdAlias) return client.clientIdAlias;
  if (typeof client.clientId === "number") return String(client.clientId);
  return "";
}
