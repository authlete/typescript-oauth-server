/**
 * Grant revocation for a consent control panel, over the interaction protocol
 * (mutual JWT). The AS is a thin pass-through: it forwards the caller-asserted
 * `subject` + the grantId, and Authlete enforces ownership — a grant is addressed
 * by (service, subject, grantId), so a grantId belonging to another subject
 * matches nothing. The ownership check lives where the data does, not here.
 *
 *   POST /api/grants/:grantId/revoke  precise, one grant — Authlete's first-party
 *                                     Grant API (spike). Gated; 501 when off (prod).
 *   POST /api/grants/revoke           client-level fallback (subject+client_id),
 *                                     always available.
 */

import { Hono } from "hono";
import type { Deps } from "../app.js";
import { requireInteractionJwt } from "../interaction/guard.js";

export function grantsRoutes({ authlete, config }: Deps) {
  const routes = new Hono();

  // Precise per-grant revoke — a thin forward to Authlete's first-party Grant API.
  // Authlete validates (subject required) and enforces ownership: a grant is keyed
  // by (service, subject, grantId), so another subject's grantId matches nothing.
  // We pass the caller's asserted subject through and return Authlete's response
  // verbatim. Gated only so a non-spike (prod) Authlete answers 501 → the caller
  // falls back to client-level revoke.
  routes.post("/api/grants/:grantId/revoke", async (c) => {
    const auth = await requireInteractionJwt(c, config);
    if (auth instanceof Response) return auth;
    if (!config.grantApiEnabled) {
      return c.json(
        { error: "not_supported", error_description: "first-party grant API not enabled" },
        501,
      );
    }
    const res = await fetch(
      `${config.authleteBaseUrl}/api/${config.authleteServiceId}/auth/grant/revoke`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${config.authleteApiToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ grantId: c.req.param("grantId"), subject: auth.payload.subject }),
      },
    );
    return new Response(await res.text(), {
      status: res.status,
      headers: { "content-type": "application/json" },
    });
  });

  // Client-level fallback (no grant_id, or per-grant API unavailable): revoke the
  // subject's whole authorization for the client via Authlete's SDK.
  routes.post("/api/grants/revoke", async (c) => {
    const auth = await requireInteractionJwt(c, config);
    if (auth instanceof Response) return auth;
    const subject = auth.payload.subject;
    const clientId = auth.payload.client_id;
    if (typeof subject !== "string" || typeof clientId !== "string") {
      return c.json(
        { error: "invalid_request", error_description: "subject and client_id required" },
        400,
      );
    }
    await authlete.clientManagement.clientAuthorizationDeleteApi({
      serviceId: config.authleteServiceId,
      clientId,
      subject,
    });
    return c.json({ status: "revoked" });
  });

  return routes;
}
