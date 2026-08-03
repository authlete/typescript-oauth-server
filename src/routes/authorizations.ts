/**
 * Interaction protocol surface on the AS.
 *
 *   API (called by auth-ui server-to-server, JWT-bearer-authenticated):
 *     GET  /api/authorizations/{id}           — the next required interaction
 *     POST /api/authorizations/{id}/outcome   — report an interaction's outcome
 *
 *   Browser (auth-ui redirects the user back here once done):
 *     GET  /authorizations/{id}/resume        — completes the flow, redirects to RP
 *
 * The AS orchestrates two interactions — authenticate, then consent — replying to
 * each outcome with what's `next` (`authenticate` | `consent` | `done`). See
 * INTERACTION_PROTOCOL.md.
 */

import type { Context } from "hono";
import { Hono } from "hono";
import type { Deps } from "../app.js";
import { Prompt } from "@authlete/typescript-sdk/models/prompt";
import { loadContext, storeContext, type StoredContext } from "../context.js";
import { dispatchAuthleteAction } from "../http.js";
import { requireJws, type InteractionAuthContext } from "../auth/interaction-auth.js";

type Scope = { name: string; description?: string };

/** The outcome auth-ui reports (carried as the `outcome` claim of the request JWT). */
type Outcome =
  | {
      type: "authenticate";
      subject: string;
      acr?: string;
      amr?: string[];
      authenticated_at?: number;
      user_claims?: Record<string, unknown>;
    }
  | { type: "consent"; granted_scopes?: string[] }
  | { type: "authenticate" | "consent"; error: string; error_description?: string };

export function authorizationsRoutes({ authlete, config }: Deps) {
  const authorizations = new Hono();

  const resumeUrl = (id: string) => `${config.asBaseUrl}/authorizations/${encodeURIComponent(id)}/resume`;

  /**
   * Verify the inbound JWT, load the authorization context, and check the JWT's
   * `authorization` claim matches the URL `{id}`. Returns `{auth, ctx}` on
   * success or a `Response` for the caller to return verbatim.
   */
  async function requireJwsForAuthorization(
    c: Context,
    id: string,
  ): Promise<{ auth: InteractionAuthContext; ctx: StoredContext } | Response> {
    const [auth, ctx] = await Promise.all([requireJws(c, config), loadContext(config, id)]);
    if (auth instanceof Response) return auth;
    if (!ctx) {
      return c.json({ error: "not_found", error_description: "authorization not found or expired" }, 404);
    }
    if (auth.payload.authorization !== id) {
      return c.json({ error: "invalid_token", error_description: "JWT authorization claim does not match URL" }, 401);
    }
    return { auth, ctx };
  }

  /**
   * Scopes the subject has already granted to this client. Best-effort: any
   * failure (feature off, no prior grant, error) yields `[]`, so the flow falls
   * back to full consent. See INTERACTION_PROTOCOL.md §2.
   */
  async function alreadyGrantedScopes(auth: StoredContext["auth"], subject: string): Promise<string[]> {
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

  // --- GET /api/authorizations/:id — the next required interaction ---------
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
      next: "authenticate",
      authenticate: {
        acr_values: a.acrs,
        max_age: a.maxAge,
        // Authlete returns prompt values UPPERCASE; forward the standard
        // lowercase OIDC values auth-ui expects.
        prompt: (a.prompts ?? []).map((p) => p.toLowerCase()).join(" ") || undefined,
        login_hint: a.loginHint,
        ui_locales: a.uiLocales,
      },
    });
  });

  // --- POST /api/authorizations/:id/outcome — report an outcome ------------
  authorizations.post("/api/authorizations/:id/outcome", async (c) => {
    const id = c.req.param("id");
    const guard = await requireJwsForAuthorization(c, id);
    if (guard instanceof Response) return guard;

    const outcome = guard.auth.payload.outcome as Outcome | undefined;
    if (!outcome?.type) {
      return c.json({ error: "invalid_token", error_description: "JWT missing outcome claim" }, 401);
    }
    const done = { next: "done", redirect_to: resumeUrl(id) };

    if (outcome.type === "authenticate") {
      if ("error" in outcome) {
        await storeContext(config, id, {
          ...guard.ctx,
          authOutcome: { error: outcome.error, errorDescription: outcome.error_description },
        });
        return c.json(done);
      }
      if (!outcome.subject) {
        return c.json({ error: "invalid_request", error_description: "subject required" }, 400);
      }

      // Reconcile consent for this subject: subtract what's already granted.
      const requested: Scope[] = (guard.ctx.auth.scopes ?? []).map((s) => ({
        name: s.name ?? "",
        description: s.description,
      }));
      const granted = await alreadyGrantedScopes(guard.ctx.auth, outcome.subject);
      const isNew = requested.filter((s) => !granted.includes(s.name));
      const already = requested.filter((s) => granted.includes(s.name));
      const forced = (guard.ctx.auth.prompts ?? []).includes(Prompt.Consent);

      await storeContext(config, id, {
        ...guard.ctx,
        authOutcome: {
          subject: outcome.subject,
          acr: outcome.acr,
          amr: outcome.amr,
          authenticatedAt: outcome.authenticated_at,
          userClaims: outcome.user_claims,
        },
        already: already.map((s) => s.name),
      });

      if (isNew.length === 0 && !forced) return c.json(done);
      return c.json({ next: "consent", consent: { new: isNew, already_granted: already } });
    }

    // consent
    const consentOutcome = "error" in outcome
      ? { error: outcome.error, errorDescription: outcome.error_description }
      : { grantedScopes: outcome.granted_scopes ?? [] };
    await storeContext(config, id, { ...guard.ctx, consentOutcome });
    return c.json(done);
  });

  // --- GET /authorizations/:id/resume — complete the flow ------------------
  authorizations.get("/authorizations/:id/resume", async (c) => {
    const id = c.req.param("id");
    const ctx = await loadContext(config, id);
    if (!ctx) {
      return c.json({ error: "invalid_request", error_description: "authorization not found or expired" }, 400);
    }

    const failure =
      (ctx.authOutcome && "error" in ctx.authOutcome ? ctx.authOutcome : null) ??
      (ctx.consentOutcome && "error" in ctx.consentOutcome ? ctx.consentOutcome : null);
    if (failure) {
      const res = await authlete.authorization.fail({
        serviceId: config.authleteServiceId,
        authorizationFailRequest: { ticket: id, reason: mapDenyReason(failure.error) },
      });
      return dispatchAuthleteAction(c, res.action, res.responseContent);
    }

    if (!ctx.authOutcome || "error" in ctx.authOutcome) {
      return c.json({ error: "invalid_request", error_description: "authorization not completed" }, 400);
    }
    const auth = ctx.authOutcome;
    const consent = ctx.consentOutcome;
    const consented = consent && "grantedScopes" in consent ? consent.grantedScopes : [];
    const scopes = [...new Set([...(ctx.already ?? []), ...consented])];

    // TODO(claims-leakage): also pass `consentedClaims` so Authlete persists it
    // and echoes it at /userinfo. See routes/userinfo.ts top-of-file TODO.
    const res = await authlete.authorization.issue({
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
    return dispatchAuthleteAction(c, res.action, res.responseContent);
  });

  return authorizations;
}

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
