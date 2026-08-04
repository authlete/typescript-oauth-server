/**
 * Builds the Authlete SDK client from a config.
 *
 * `createOAuthServer` calls this once and hands the client to the routes as a
 * plain dependency — no module-global singleton, no request-scoped magic.
 */

import { Authlete } from "@authlete/typescript-sdk/authlete";
import type { Config } from "./config.js";

export function makeAuthlete(config: Config): Authlete {
  return new Authlete({
    serverURL: config.authleteBaseUrl,
    bearer: config.authleteApiToken,
  });
}
