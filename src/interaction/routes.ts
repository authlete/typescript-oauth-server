/**
 * The AS's HTTP surface for the interaction protocol (INTERACTION_PROTOCOL.md).
 *
 *   API (called by an interaction app server-to-server, JWT-bearer-authenticated):
 *     GET  /api/authorizations/{id}           — the next interaction for the caller
 *     POST /api/authorizations/{id}/outcome   — report an interaction's outcome
 *
 *   Browser (an interaction app redirects the user back here once its part is done):
 *     GET  /authorizations/{id}/resume        — hand off to the next app, or finish
 *
 *   Key publication:
 *     GET  /.well-known/jwks.json             — the AS's interaction public key
 *
 * The model: an authorization has required interactions (authenticate, consent);
 * each yields an outcome. An app is handed the browser and runs the interactions
 * served at its own URL, reporting each outcome, until the AS says it's done;
 * then the browser returns to /resume, which either hands off to the next app or
 * finalizes once every outcome is in. auth-ui and the consent UI are identical
 * here — the only difference is which URL serves the `consent` interaction.
 */

import type { Context } from "hono";
import { Hono } from "hono";
import type { Deps } from "../app.js";
import type { Config } from "../config.js";
import { dispatchAuthleteAction } from "../http.js";
import type { Interaction, StoredContext } from "./context.js";
import { loadContext } from "./ticket-store.js";
import { recordAuthentication } from "./authenticate.js";
import { recordConsent } from "./consent.js";
import { finalize, interactionPayload, nextInteraction } from "./steps.js";
import { requireInteractionJwt, type VerifiedCaller } from "./guard.js";
import { getAsPublicJwks } from "./jwks.js";
import { signJwt } from "./jwt.js";

/** The outcome an app reports (carried as the `outcome` claim of the request JWT). */
type Outcome =
  | {
      type: "authenticate";
      subject: string;
      acr?: string;
      amr?: string[];
      authenticated_at?: number;
      user_claims?: Record<string, unknown>;
    }
  | { type: "consent"; granted_scopes?: string[]; consent_id?: string }
  | { type: "authenticate" | "consent"; error: string; error_description?: string };

const resumeUrl = (config: Config, id: string) =>
  `${config.asBaseUrl}/authorizations/${encodeURIComponent(id)}/resume`;

/**
 * The issuer (identity, == base URL) of the app that runs an interaction. The
 * consent interaction goes to the consent UI when one is configured; otherwise
 * auth-ui runs everything.
 */
function interactionIssuerId(config: Config, interaction: Interaction): string {
  if (interaction === "consent" && config.consentUiIssuerId) return config.consentUiIssuerId;
  return config.authUiIssuerId;
}

/**
 * The URL to hand the browser to so its app can run the interaction. The entry
 * convention is identical for every interaction app — same path, same param, same
 * signed token (carrying the AS callback base, §1). Only the base URL differs,
 * and that is just the app's issuer.
 */
async function interactionUrl(
  config: Config,
  interaction: Interaction,
  id: string,
): Promise<string> {
  const base = interactionIssuerId(config, interaction); // issuer == the app's base URL
  const token = await signJwt(
    config,
    { authorization: id, as_base: config.asBaseUrl },
    { audience: base, expiresInSeconds: 600 },
  );
  const url = new URL(`/authorizations/${encodeURIComponent(id)}`, base);
  url.searchParams.set("interaction", token);
  return url.toString();
}

/**
 * What to tell the calling app: run the next interaction if it's served at the
 * caller's own URL, else it's finished (go to resume). Shared by GET and POST.
 * Wire shape: `{ next: "consent", consent: {…} }` or `{ next: "done", redirect_to }`.
 */
function nextForApp(config: Config, id: string, ctx: StoredContext, callerIssuerId?: string) {
  const next = nextInteraction(ctx);
  if (!next || interactionIssuerId(config, next) !== callerIssuerId) {
    return { next: "done", redirect_to: resumeUrl(config, id) };
  }
  return { next, [next]: interactionPayload(ctx, next) };
}

export function interactionRoutes({ authlete, config }: Deps) {
  const interaction = new Hono();

  /**
   * Verify the inbound JWT, load the authorization context, and check the JWT's
   * `authorization` claim matches the URL `{id}`. Returns `{auth, ctx}` on
   * success or a `Response` for the caller to return verbatim.
   */
  async function requireAuthorization(
    c: Context,
    id: string,
  ): Promise<{ auth: VerifiedCaller; ctx: StoredContext } | Response> {
    const [auth, ctx] = await Promise.all([
      requireInteractionJwt(c, config),
      loadContext(config, id),
    ]);
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

  // --- GET /api/authorizations/:id — the next interaction for the caller ---
  interaction.get("/api/authorizations/:id", async (c) => {
    const id = c.req.param("id");
    const guard = await requireAuthorization(c, id);
    if (guard instanceof Response) return guard;

    const client = guard.ctx.auth.client;
    return c.json({
      client: {
        client_id: stringIdOrAlias(client),
        name: client.clientName,
        logo_uri: client.logoUri,
        policy_uri: client.policyUri,
        tos_uri: client.tosUri,
      },
      ...nextForApp(config, id, guard.ctx, guard.auth.payload.iss),
    });
  });

  // --- POST /api/authorizations/:id/outcome — report an outcome -----------
  interaction.post("/api/authorizations/:id/outcome", async (c) => {
    const id = c.req.param("id");
    const guard = await requireAuthorization(c, id);
    if (guard instanceof Response) return guard;

    const outcome = guard.auth.payload.outcome as Outcome | undefined;
    if (!outcome?.type) {
      return c.json(
        { error: "invalid_token", error_description: "JWT missing outcome claim" },
        401,
      );
    }

    let ctx = guard.ctx;
    if (outcome.type === "authenticate") {
      if (!("error" in outcome) && !outcome.subject) {
        return c.json({ error: "invalid_request", error_description: "subject required" }, 400);
      }
      ctx = await recordAuthentication(
        authlete,
        config,
        id,
        ctx,
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
    } else {
      ctx = await recordConsent(
        config,
        id,
        ctx,
        "error" in outcome
          ? { error: outcome.error, errorDescription: outcome.error_description }
          : { grantedScopes: outcome.granted_scopes ?? [] },
        "error" in outcome ? undefined : outcome.consent_id,
      );
    }
    return c.json(nextForApp(config, id, ctx, guard.auth.payload.iss));
  });

  // --- GET /authorizations/:id/resume — hand off to the next app, or finish
  interaction.get("/authorizations/:id/resume", async (c) => {
    const id = c.req.param("id");
    const ctx = await loadContext(config, id);
    if (!ctx) {
      return c.json(
        { error: "invalid_request", error_description: "authorization not found or expired" },
        400,
      );
    }

    const next = nextInteraction(ctx);
    if (next) return c.redirect(await interactionUrl(config, next, id), 302);

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
