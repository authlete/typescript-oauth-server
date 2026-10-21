/**
 * /oauth/token — OAuth 2.0 token endpoint.
 *
 * Form body → Authlete /auth/token → dispatch on response action.
 * Authlete picks the client-auth method (basic/post/private_key_jwt/none)
 * based on client registration; we just forward the parsed Basic credentials.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import type { Deps } from "../app.js";
import {
  basicChallengeHeaders,
  basicCredsFor,
  dpopParams,
  noStoreJsonHeaders,
  sendAuthleteAction,
} from "../http.js";
import { onGrantIssued } from "../grant-lifecycle.js";

/** Grant flows Authlete supports but this AS has not implemented. */
const unsupportedGrant = (action: string) => ({
  status: 400,
  body: JSON.stringify({
    error: "unsupported_grant_type",
    error_description: `Grant flow ${action} is not implemented.`,
  }),
});

export function tokenRoutes({ authlete, config }: Deps) {
  const token = new Hono();

  token.post("/oauth/token", async (c) => {
    const parameters = await c.req.text();
    const res = await authlete.token.process({
      serviceId: config.authleteServiceId,
      tokenRequest: { parameters, ...basicCredsFor(c), ...dpopParams(c) },
    });

    // A grant surfaces here when grant management was used — run post-processing.
    await onGrantIssued(config, res);

    // RFC 7523 JWT bearer grant: verify the client-signed assertion, then mint a token.
    if (res.action === "JWT_BEARER") {
      return handleJwtBearer(c, authlete, config.authleteServiceId, res);
    }

    return sendAuthleteAction(c, res, {
      OK: 200,
      INVALID_CLIENT: { status: 401, headers: basicChallengeHeaders },
      BAD_REQUEST: 400,
      INTERNAL_SERVER_ERROR: 500,
      PASSWORD: unsupportedGrant("PASSWORD"),
      TOKEN_EXCHANGE: unsupportedGrant("TOKEN_EXCHANGE"),
      NATIVE_SSO: unsupportedGrant("NATIVE_SSO"),
      ID_TOKEN_REISSUABLE: unsupportedGrant("ID_TOKEN_REISSUABLE"),
    });
  });

  return token;
}

/**
 * RFC 7523 JWT bearer authorization grant.
 *
 * Trust model: the assertion is issued and signed by the requesting client itself (the same key model
 * as private_key_jwt client auth). Authlete validated the assertion's claims and handed back the raw
 * assertion; we verify its signature against the client's own registered keys via jose/verify and mint
 * a token only if the signature is valid. Assertions signed by a third party (issuer != client) are
 * out of scope.
 */
async function handleJwtBearer(
  c: Context,
  authlete: Deps["authlete"],
  serviceId: string,
  res: {
    assertion?: string | undefined;
    clientId?: number | undefined;
    scopes?: string[] | undefined;
  },
): Promise<Response> {
  const assertion = res.assertion ?? "";

  const verify = await authlete.joseObject.joseVerifyApi({
    serviceId,
    joseVerifyRequest: {
      jose: assertion,
      clientIdentifier: res.clientId != null ? String(res.clientId) : undefined,
      signedByClient: true,
    },
  });
  if (!verify.valid) {
    return jwtBearerError(c, "Assertion signature verification failed.");
  }

  const created = await authlete.token.management.create({
    serviceId,
    tokenCreateRequest: {
      grantType: "JWT_BEARER",
      clientId: res.clientId,
      subject: jwtSubject(assertion),
      scopes: res.scopes,
    },
  });
  if (created.action !== "OK" || !created.accessToken) {
    return jwtBearerError(c, "Token creation failed.");
  }

  const out: Record<string, unknown> = {
    access_token: created.accessToken,
    token_type: created.tokenType ?? "Bearer",
    expires_in: created.expiresIn,
  };
  if (created.scopes?.length) out.scope = created.scopes.join(" ");
  return c.body(JSON.stringify(out), 200, noStoreJsonHeaders);
}

const jwtBearerError = (c: Context, description: string): Response =>
  c.body(
    JSON.stringify({ error: "invalid_grant", error_description: description }),
    400,
    noStoreJsonHeaders,
  );

/** Read the `sub` claim from a JWT without verifying it — Authlete already verified the signature. */
function jwtSubject(jwt: string): string | undefined {
  const payload = jwt.split(".")[1];
  if (!payload) return undefined;
  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf-8"));
    return typeof claims.sub === "string" ? claims.sub : undefined;
  } catch {
    return undefined;
  }
}
