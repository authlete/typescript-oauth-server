/**
 * OIDC discovery + OAuth 2.0 Authorization Server Metadata.
 * Both standard paths delegate to Authlete's /service/configuration.
 */

import { Hono } from "hono";
import type { Deps } from "../app.js";

export function wellKnownRoutes({ authlete, config }: Deps) {
  const wellKnown = new Hono();

  // TEMPORARY (authlete-java-common#178): merge PROTECTED_RESOURCES until Authlete emits it.
  const configuration = async () => {
    const metadata = await authlete.service.getConfiguration({
      serviceId: config.authleteServiceId,
    });
    if (config.protectedResources.length > 0) {
      metadata.protected_resources = config.protectedResources;
    }
    return metadata;
  };

  wellKnown.get("/.well-known/openid-configuration", async (c) => c.json(await configuration()));
  wellKnown.get("/.well-known/oauth-authorization-server", async (c) =>
    c.json(await configuration()),
  );

  return wellKnown;
}
