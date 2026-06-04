/**
 * Authlete SDK client. Single shared instance configured from env.
 *
 * The SDK's `serviceId` constructor option auto-injects the service ID into
 * every API call, so call sites don't repeat it.
 */

import { Authlete } from "@authlete/typescript-sdk/authlete";
import { config } from "./config.js";

/**
 * Imported from the SDK's `/authlete` subpath which exports the overlay class.
 * Note: the overlay injects `serviceId` at runtime via a Proxy, but the
 * Speakeasy-generated TypeScript types still require `serviceId` as a property
 * of each request — so call sites must pass it explicitly anyway.
 * Pass `config.authleteServiceId` at each call site for type-safety.
 */
export const authlete = new Authlete({
  serverURL: config.authleteBaseUrl,
  bearer: config.authleteApiToken,
});
