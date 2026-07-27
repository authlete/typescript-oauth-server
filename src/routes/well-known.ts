/**
 * OIDC discovery + OAuth 2.0 Authorization Server Metadata.
 * Both standard paths delegate to Authlete's /service/configuration.
 */

import { Hono } from "hono";
import type { Deps } from "../app.js";

export function wellKnownRoutes({ authlete, config }: Deps) {
  const wellKnown = new Hono();

  const configuration = () => authlete.service.getConfiguration({ serviceId: config.authleteServiceId });

  wellKnown.get("/.well-known/openid-configuration", async (c) => c.json(await configuration()));
  wellKnown.get("/.well-known/oauth-authorization-server", async (c) => c.json(await configuration()));

  return wellKnown;
}
