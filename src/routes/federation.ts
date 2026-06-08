/**
 * OpenID Federation 1.0 endpoints — mirrors java-oauth-server verbatim.
 *
 * Routes are mounted unconditionally. When the Authlete service has federation
 * disabled, Authlete returns action=NOT_FOUND and we relay 404 — plain
 * operators never have to think about these routes.
 *
 * @see https://openid.net/specs/openid-federation-1_0.html
 */

import type { Context } from "hono";
import { Hono } from "hono";
import {
  FederationConfigurationResponseAction,
  FederationRegistrationResponseAction,
  type FederationConfigurationResponse,
  type FederationRegistrationRequest,
  type FederationRegistrationResponse,
} from "@authlete/typescript-sdk/models";
import { authlete } from "../authlete.js";
import { config } from "../config.js";
import { noStoreHeaders } from "../http.js";

export const federation = new Hono();

const ENTITY_STATEMENT_JWT = "application/entity-statement+jwt";
const TRUST_CHAIN_JSON = "application/trust-chain+json";

const entityStatementHeaders = {
  ...noStoreHeaders,
  "content-type": ENTITY_STATEMENT_JWT,
} as const;

const errorJsonHeaders = {
  ...noStoreHeaders,
  "content-type": "application/json",
} as const;

federation.get("/.well-known/openid-federation", async (c) => {
  const res = await authlete.federation.configuration({
    serviceId: config.authleteServiceId,
    // SDK gap (#2 + #3 in docs/AUTHLETE_SDK_GAPS.md): empty `{}` is required
    // (typed optional but isn't) and `entityTypes` filter cannot be passed.
    requestBody: {},
  });
  return dispatchConfiguration(c, res);
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
      errorJsonHeaders,
    );
  }

  const res = await authlete.federation.registration({
    serviceId: config.authleteServiceId,
    federationRegistrationRequest,
  });
  return dispatchRegistration(c, res);
});

function dispatchConfiguration(c: Context, res: FederationConfigurationResponse): Response {
  const content = res.responseContent ?? "";
  switch (res.action) {
    case FederationConfigurationResponseAction.Ok:
      return c.body(content, 200, entityStatementHeaders);
    case FederationConfigurationResponseAction.NotFound:
      return c.body(content, 404, errorJsonHeaders);
    case FederationConfigurationResponseAction.InternalServerError:
    default:
      return c.body(content, 500, errorJsonHeaders);
  }
}

function dispatchRegistration(c: Context, res: FederationRegistrationResponse): Response {
  const content = res.responseContent ?? "";
  switch (res.action) {
    case FederationRegistrationResponseAction.Ok:
      return c.body(content, 200, entityStatementHeaders);
    case FederationRegistrationResponseAction.BadRequest:
      return c.body(content, 400, errorJsonHeaders);
    case FederationRegistrationResponseAction.NotFound:
      return c.body(content, 404, errorJsonHeaders);
    case FederationRegistrationResponseAction.InternalServerError:
    default:
      return c.body(content, 500, errorJsonHeaders);
  }
}
