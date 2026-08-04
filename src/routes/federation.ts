/**
 * OpenID Federation 1.0 endpoints.
 *
 * Routes are mounted unconditionally. When the Authlete service has federation
 * disabled, Authlete returns action=NOT_FOUND and we relay 404 — plain
 * operators never have to think about these routes.
 *
 * @see https://openid.net/specs/openid-federation-1_0.html
 */

import { Hono } from "hono";
import type { FederationRegistrationRequest } from "@authlete/typescript-sdk/models";
import type { Deps } from "../app.js";
import { noStoreHeaders, noStoreJsonHeaders, sendAuthleteAction } from "../http.js";

const ENTITY_STATEMENT_JWT = "application/entity-statement+jwt";
const TRUST_CHAIN_JSON = "application/trust-chain+json";

const entityStatementHeaders = {
  ...noStoreHeaders,
  "content-type": ENTITY_STATEMENT_JWT,
} as const;

export function federationRoutes({ authlete, config }: Deps) {
  const federation = new Hono();

  federation.get("/.well-known/openid-federation", async (c) => {
    const res = await authlete.federation.configuration({
      serviceId: config.authleteServiceId,
      // The live API rejects a missing body even though the SDK types it optional.
      requestBody: {},
    });
    return sendAuthleteAction(c, res, {
      OK: { status: 200, headers: entityStatementHeaders },
      NOT_FOUND: 404,
      INTERNAL_SERVER_ERROR: 500,
    });
  });

  federation.post("/api/federation/register", async (c) => {
    const contentType = c.req.header("content-type")?.split(";")[0]?.trim();

    let federationRegistrationRequest: FederationRegistrationRequest;
    if (contentType === ENTITY_STATEMENT_JWT) {
      federationRegistrationRequest = { entityConfiguration: await c.req.text() };
    } else if (contentType === TRUST_CHAIN_JSON) {
      federationRegistrationRequest = { trustChain: await c.req.text() };
    } else {
      return c.body(
        JSON.stringify({
          error: "unsupported_media_type",
          error_description: `Expected ${ENTITY_STATEMENT_JWT} or ${TRUST_CHAIN_JSON}`,
        }),
        415,
        noStoreJsonHeaders,
      );
    }

    const res = await authlete.federation.registration({
      serviceId: config.authleteServiceId,
      federationRegistrationRequest,
    });
    return sendAuthleteAction(c, res, {
      OK: { status: 200, headers: entityStatementHeaders },
      BAD_REQUEST: 400,
      NOT_FOUND: 404,
      INTERNAL_SERVER_ERROR: 500,
    });
  });

  return federation;
}
