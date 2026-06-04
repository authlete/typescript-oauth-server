/**
 * OIDC discovery + OAuth 2.0 Authorization Server Metadata.
 * Both standard paths delegate to Authlete's /service/configuration.
 */

import { Hono } from "hono";
import { authlete } from "../authlete.js";
import { config } from "../config.js";

export const wellKnown = new Hono();

async function configuration() {
  return await authlete.service.getConfiguration({ serviceId: config.authleteServiceId });
}

wellKnown.get("/.well-known/openid-configuration", async (c) => c.json(await configuration()));
wellKnown.get("/.well-known/oauth-authorization-server", async (c) => c.json(await configuration()));
