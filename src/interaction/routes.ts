/**
 * The AS's HTTP surface for the interaction protocol (INTERACTION_PROTOCOL.md).
 *
 *   API (called by auth-ui server-to-server, JWT-bearer-authenticated):
 *     GET  /api/authorizations/{id}           — the next required interaction
 *     POST /api/authorizations/{id}/outcome   — report an interaction's outcome
 *
 *   Browser (auth-ui redirects the user back here once done):
 *     GET  /authorizations/{id}/resume        — completes the flow, redirects to RP
 *
 *   Key publication:
 *     GET  /.well-known/jwks.json             — the AS's interaction public key,
 *                                               for auth-ui to verify the AS's JWTs
 *
 * Transport only: verify the JWT, translate wire JSON ↔ domain, delegate the
 * actual orchestration to login-consent.ts.
 */

import type { Context } from "hono";
import { Hono } from "hono";
import type { Deps } from "../app.js";
import { dispatchAuthleteAction } from "../http.js";
import {
  finalize,
  loadContext,
  recordAuthentication,
  recordConsent,
  type StoredContext,
} from "../login-consent.js";
import { requireJws, type InteractionAuthContext } from "./auth.js";
import { getAsPublicJwks } from "./jwks.js";

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

export function interactionRoutes({ authlete, config }: Deps) {
  const interaction = new Hono();

  const resumeUrl = (id: string) =>
    `${config.asBaseUrl}/authorizations/${encodeURIComponent(id)}/resume`;

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
      return c.json(
        { error: "not_found", error_description: "authorization not found or expired" },
        404,
      );
    }
    if (auth.payload.authorization !== id) {
      return c.json(
        { error: "invalid_token", error_description: "JWT authorization claim does not match URL" },
        401,
      );
    }
    return { auth, ctx };
  }

  // --- GET /.well-known/jwks.json — the AS's interaction public key --------
  interaction.get("/.well-known/jwks.json", (c) =>
    c.body(JSON.stringify(getAsPublicJwks(config)), 200, {
      "content-type": "application/jwk-set+json",
      "cache-control": "public, max-age=300",
    }),
  );

  // --- GET /api/authorizations/:id — the next required interaction ---------
  interaction.get("/api/authorizations/:id", async (c) => {
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
  interaction.post("/api/authorizations/:id/outcome", async (c) => {
    const id = c.req.param("id");
    const guard = await requireJwsForAuthorization(c, id);
    if (guard instanceof Response) return guard;

    const outcome = guard.auth.payload.outcome as Outcome | undefined;
    if (!outcome?.type) {
      return c.json(
        { error: "invalid_token", error_description: "JWT missing outcome claim" },
        401,
      );
    }
    const done = { next: "done", redirect_to: resumeUrl(id) };

    if (outcome.type === "authenticate") {
      if (!("error" in outcome) && !outcome.subject) {
        return c.json({ error: "invalid_request", error_description: "subject required" }, 400);
      }
      const step = await recordAuthentication(
        authlete,
        config,
        id,
        guard.ctx,
        "error" in outcome
          ? { error: outcome.error, errorDescription: outcome.error_description }
          : {
              subject: outcome.subject,
              acr: outcome.acr,
              amr: outcome.amr,
              authenticatedAt: outcome.authenticated_at,
              userClaims: outcome.user_claims,
            },
      );
      if (step.next === "done") return c.json(done);
      return c.json({
        next: "consent",
        consent: { new: step.newScopes, already_granted: step.alreadyGranted },
      });
    }

    await recordConsent(
      config,
      id,
      guard.ctx,
      "error" in outcome
        ? { error: outcome.error, errorDescription: outcome.error_description }
        : { grantedScopes: outcome.granted_scopes ?? [] },
    );
    return c.json(done);
  });

  // --- GET /authorizations/:id/resume — complete the flow ------------------
  interaction.get("/authorizations/:id/resume", async (c) => {
    const id = c.req.param("id");
    const ctx = await loadContext(config, id);
    if (!ctx) {
      return c.json(
        { error: "invalid_request", error_description: "authorization not found or expired" },
        400,
      );
    }

    const res = await finalize(authlete, config, id, ctx);
    if (!res) {
      return c.json(
        { error: "invalid_request", error_description: "authorization not completed" },
        400,
      );
    }
    return dispatchAuthleteAction(c, res.action, res.responseContent);
  });

  return interaction;
}

function stringIdOrAlias(client: { clientId?: number; clientIdAlias?: string }): string {
  if (client.clientIdAlias) return client.clientIdAlias;
  if (typeof client.clientId === "number") return String(client.clientId);
  return "";
}
