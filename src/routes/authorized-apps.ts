/** /api/authorized-apps — a user's granted apps + revoke, over Authlete's grant state. auth-ui-facing (mutual JWT, `subject` claim). */

import type { Context } from "hono";
import { Hono } from "hono";
import type { Deps } from "../app.js";
import { requireInteractionJwt } from "../interaction/guard.js";

export function authorizedAppsRoutes({ authlete, config }: Deps) {
  const routes = new Hono();
  const serviceId = config.authleteServiceId;

  async function subjectOf(c: Context): Promise<string | Response> {
    const auth = await requireInteractionJwt(c, config);
    if (auth instanceof Response) return auth;
    const subject = auth.payload.subject;
    if (typeof subject !== "string" || subject.length === 0) {
      return c.json(
        { error: "invalid_request", error_description: "JWT missing subject claim" },
        400,
      );
    }
    return subject;
  }

  // Scopes the subject granted this client; best-effort ([] on any failure).
  async function grantedScopes(clientId: string, subject: string): Promise<string[]> {
    try {
      const res = await authlete.clientManagement.clientGrantedScopesGetApi({
        serviceId,
        clientId,
        subject,
      });
      return res.mergedGrantedScopes ?? [];
    } catch {
      return [];
    }
  }

  // No subject→grants list API — fan out over clients (one page of 100), keep those granted.
  routes.get("/api/authorized-apps", async (c) => {
    const subject = await subjectOf(c);
    if (subject instanceof Response) return subject;

    const { clients = [] } = await authlete.client.list({ serviceId, start: 0, end: 100 });
    const apps = [];
    for (const client of clients) {
      if (typeof client.clientId !== "number") continue;
      const clientId = String(client.clientId);
      const scopes = await grantedScopes(clientId, subject);
      if (scopes.length === 0) continue;
      apps.push({
        client: {
          client_id: clientId,
          name: client.clientName,
          logo_uri: client.logoUri,
          client_uri: client.clientUri,
          redirect_uris: client.redirectUris ?? [],
        },
        scopes,
      });
    }
    return c.json({ apps });
  });

  // Revoke: clears remembered scopes + kills tokens, so a later request re-consents.
  routes.delete("/api/authorized-apps/:clientId", async (c) => {
    const subject = await subjectOf(c);
    if (subject instanceof Response) return subject;
    await authlete.clientManagement.clientAuthorizationDeleteApi({
      serviceId,
      clientId: c.req.param("clientId"),
      subject,
    });
    return c.body(null, 204);
  });

  return routes;
}
