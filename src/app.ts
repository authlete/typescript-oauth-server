/**
 * The OAuth/OIDC Authorization Server, built from a Config.
 *
 * `createOAuthServer(config)` is the reusable entry: config in, request handler
 * out — no global state, no request-scoped magic. Importing this module has no
 * side effects (it reads no env): the standalone/Vercel entry (server.ts) builds
 * the server from process env, and a multi-tenant host calls it once per tenant.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import type { Authlete } from "@authlete/typescript-sdk/authlete";
import type { Config } from "./config.js";
import { makeAuthlete } from "./authlete.js";
import { wellKnownRoutes } from "./routes/well-known.js";
import { authorizeRoutes } from "./routes/authorize.js";
import { authorizationsRoutes } from "./routes/authorizations.js";
import { tokenRoutes } from "./routes/token.js";
import { userinfoRoutes } from "./routes/userinfo.js";
import { jwksRoutes } from "./routes/jwks.js";
import { introspectRoutes } from "./routes/introspect.js";
import { revokeRoutes } from "./routes/revoke.js";
import { parRoutes } from "./routes/par.js";
import { federationRoutes } from "./routes/federation.js";
import { registerRoutes } from "./routes/register.js";

/** The dependencies every route factory receives. */
export interface Deps {
  authlete: Authlete;
  config: Config;
}

export function createOAuthServer(config: Config): Hono {
  const deps: Deps = { authlete: makeAuthlete(config), config };
  const app = new Hono();

  // Cross-origin access for browser callers (e.g. the OAuth Playground). Driven
  // by CORS_ORIGINS so each deployment configures its own allowlist. Scoped
  // to endpoints a browser RP legitimately hits — OAuth + discovery + federation
  // registration. /api/authorizations/* is intentionally excluded; it's the
  // AS↔auth-ui interaction protocol, server-to-server only.
  if (config.corsOrigins.length > 0) {
    const allowAll = config.corsOrigins.includes("*");
    const corsMiddleware = cors({
      origin: allowAll
        ? "*"
        : (origin) => (config.corsOrigins.includes(origin) ? origin : null),
      allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowHeaders: ["Authorization", "Content-Type", "DPoP"],
      exposeHeaders: ["WWW-Authenticate"],
      maxAge: 600,
    });
    app.use("/.well-known/*", corsMiddleware);
    app.use("/oauth/*", corsMiddleware);
    app.use("/api/federation/*", corsMiddleware);
    app.use("/api/register", corsMiddleware);
    app.use("/api/register/*", corsMiddleware);
  }

  // Root signpost.
  app.get("/", (c) =>
    c.json({
      name: "typescript-oauth-server",
      status: "ok",
      authlete: { baseUrl: config.authleteBaseUrl, serviceId: config.authleteServiceId },
      interactionApp: config.authUiUrl,
      discovery: `${config.asBaseUrl}/.well-known/openid-configuration`,
    }),
  );
  app.get("/health", (c) => c.json({ status: "ok" }));

  app.route("/", wellKnownRoutes(deps));
  app.route("/", authorizeRoutes(deps));
  app.route("/", authorizationsRoutes(deps));
  app.route("/", tokenRoutes(deps));
  app.route("/", userinfoRoutes(deps));
  app.route("/", jwksRoutes(deps));
  app.route("/", introspectRoutes(deps));
  app.route("/", revokeRoutes(deps));
  app.route("/", parRoutes(deps));
  app.route("/", federationRoutes(deps));
  app.route("/", registerRoutes(deps));

  return app;
}

// Re-exported so a consumer can build a Config and call createOAuthServer —
// importing this module runs no env reads (nothing here has side effects).
export { fromEnv, type Config } from "./config.js";
