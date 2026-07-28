/**
 * OIDC discovery + OAuth 2.0 Authorization Server Metadata.
 * Both standard paths delegate to Authlete's /service/configuration.
 */

import { Hono } from "hono";
import { authlete } from "../authlete.js";
import { config } from "../config.js";

export const wellKnown = new Hono();

/**
 * Endpoint URLs the service does not define are filled from AS_BASE_URL.
 *
 * Ideally these live in the Authlete service settings so the discovery
 * document comes back complete, but Authlete rejects non-https endpoint
 * URLs (A031219), which rules out plain-http localhost deployments like
 * this example. Values set on the service always win; only missing ones
 * are filled here.
 *
 * TODO: when this example gets an https deployment story, document setting
 * the endpoint URLs (and issuer) in the service settings instead.
 */
async function configuration() {
  const metadata = (await authlete.service.getConfiguration({
    serviceId: config.authleteServiceId,
  })) as Record<string, unknown>;

  const base = config.asBaseUrl;
  const fallbacks: Record<string, string> = {
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    userinfo_endpoint: `${base}/oauth/userinfo`,
    jwks_uri: `${base}/oauth/jwks`,
    introspection_endpoint: `${base}/oauth/introspect`,
    revocation_endpoint: `${base}/oauth/revoke`,
  };
  for (const [key, url] of Object.entries(fallbacks)) {
    if (!metadata[key]) metadata[key] = url;
  }
  return metadata;
}

wellKnown.get("/.well-known/openid-configuration", async (c) => c.json(await configuration()));
wellKnown.get("/.well-known/oauth-authorization-server", async (c) => c.json(await configuration()));
