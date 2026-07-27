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
import type { Deps } from "../app.js";
import { storeContext } from "../context.js";
import { dispatchAuthleteAction } from "../http.js";
import { signJwt } from "../jws.js";

export function authorizeRoutes({ authlete, config }: Deps) {
  const authorize = new Hono();

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
        await storeContext(config, res.ticket, { v: 1, auth: res });
        // Signed interaction token carrying the AS callback base, so auth-ui
        // reaches the right deployment without static config. See §1 of
        // INTERACTION_PROTOCOL.md. Long-lived: spans sign-in + consent.
        const interaction = await signJwt(
          config,
          { authorization: res.ticket, as_base: config.asBaseUrl },
          { expiresInSeconds: 600 },
        );
        const target = new URL(
          `/authorizations/${encodeURIComponent(res.ticket)}`,
          config.authUiUrl,
        );
        target.searchParams.set("interaction", interaction);
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

  return authorize;
}
