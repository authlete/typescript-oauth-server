/**
 * /oauth/authorize (GET, POST).
 *
 * Standard OAuth 2.0 / OIDC authorization endpoint. On INTERACTION /
 * NO_INTERACTION, stores the authorization context and redirects the browser
 * to auth-ui at <AUTH_UI_URL>/authorizations/<id>. Completion happens at
 * /authorizations/{id}/resume — see authorizations.ts.
 */

import type { Context } from "hono";
import { Hono } from "hono";
import { authlete } from "../authlete.js";
import { config } from "../config.js";
import { storeContext } from "../context.js";
import { dispatchAuthleteAction } from "../http.js";

export const authorize = new Hono();

async function handleAuthorize(c: Context, parameters: string): Promise<Response> {
  const res = await authlete.authorization.processRequest({
    serviceId: config.authleteServiceId,
    authorizationRequest: { parameters },
  });

  switch (res.action) {
    case "INTERACTION":
    case "NO_INTERACTION": {
      if (!res.ticket) {
        return c.json(
          { error: "server_error", error_description: "Authlete returned INTERACTION without a ticket" },
          500,
        );
      }
      await storeContext(res.ticket, { v: 1, auth: res });
      const target = new URL(
        `/authorizations/${encodeURIComponent(res.ticket)}`,
        config.authUiUrl,
      );
      return c.redirect(target.toString(), 302);
    }
    default:
      return dispatchAuthleteAction(c, res.action, res.responseContent);
  }
}

authorize.get("/oauth/authorize", async (c) => {
  const search = new URL(c.req.url).search;
  const parameters = search.startsWith("?") ? search.slice(1) : search;
  return handleAuthorize(c, parameters);
});

authorize.post("/oauth/authorize", async (c) => {
  const parameters = await c.req.text();
  return handleAuthorize(c, parameters);
});
