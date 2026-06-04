/**
 * Component protocol — the bespoke 2-endpoint contract between AS and auth-ui.
 *
 *   GET  /api/interactions/{ticket}  — fetch render details for the UI.
 *   POST /api/interactions/{ticket}  — submit the user's decision.
 *
 * Both are bearer-protected and require the `urn:authlete-as:interactions`
 * scope. auth-ui obtains the token via /oauth/token with client_credentials +
 * private_key_jwt.
 *
 * `{ticket}` is the opaque Authlete ticket; auth-ui treats it as an opaque
 * interaction id.
 */

import { Hono } from "hono";
import { config } from "../config.js";
import { loadContext, storeContext, type Decision } from "../context.js";
import { INTERACTION_SCOPE, requireBearer } from "../auth/bearer.js";
import { storeClaims } from "../userstore.js";

export const interactions = new Hono();

interactions.get("/api/interactions/:ticket", async (c) => {
  const ticket = c.req.param("ticket");
  const [auth, ctx] = await Promise.all([
    requireBearer(c, [INTERACTION_SCOPE]),
    loadContext(ticket),
  ]);
  if (auth instanceof Response) return auth;
  if (!ctx) {
    return c.json({ error: "not_found", error_description: "ticket not found or expired" }, 404);
  }

  const a = ctx.auth;
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

type SuccessBody = {
  subject: string;
  acr?: string;
  amr?: string[];
  authenticated_at?: number;
  granted_scopes?: string[];
  user_claims?: Record<string, unknown>;
  granted_claims?: Record<string, unknown>;
};

type FailureBody = {
  error: string;
  error_description?: string;
};

interactions.post("/api/interactions/:ticket", async (c) => {
  const ticket = c.req.param("ticket");
  const [auth, ctx] = await Promise.all([
    requireBearer(c, [INTERACTION_SCOPE]),
    loadContext(ticket),
  ]);
  if (auth instanceof Response) return auth;
  if (!ctx) {
    return c.json({ error: "not_found", error_description: "ticket not found or expired" }, 404);
  }

  let body: SuccessBody | FailureBody;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "invalid_request", error_description: "body must be JSON" }, 400);
  }

  const decision: Decision = isFailure(body)
    ? {
        outcome: "denied",
        error: body.error,
        errorDescription: body.error_description,
      }
    : {
        outcome: "approved",
        subject: body.subject,
        acr: body.acr,
        amr: body.amr,
        authenticatedAt: body.authenticated_at,
        grantedScopes: body.granted_scopes,
        userClaims: body.user_claims,
        grantedClaims: body.granted_claims,
      };

  if (decision.outcome === "approved" && !decision.subject) {
    return c.json(
      { error: "invalid_request", error_description: "subject required for approved decisions" },
      400,
    );
  }

  // Cache claim values for /userinfo to read later (no user DB).
  if (decision.outcome === "approved" && decision.userClaims) {
    storeClaims(decision.subject, decision.userClaims);
  }

  await storeContext(ticket, { ...ctx, decision });

  return c.json({
    redirect_to: `${config.asBaseUrl}/oauth/authorize/finalize?ticket=${encodeURIComponent(ticket)}`,
  });
});

function isFailure(body: SuccessBody | FailureBody): body is FailureBody {
  return typeof (body as FailureBody).error === "string";
}

function stringIdOrAlias(client: { clientId?: number; clientIdAlias?: string }): string {
  if (client.clientIdAlias) return client.clientIdAlias;
  if (typeof client.clientId === "number") return String(client.clientId);
  return "";
}
