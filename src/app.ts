/**
 * The OAuth/OIDC Authorization Server as an app built from a config.
 *
 * `createApp(config)` is the reusable entry: config in, Hono app out — no
 * global state, no request-scoped magic. The default export is the single
 * app built from the process env (what standalone and Vercel serve). A
 * multi-tenant host imports `createApp` and calls it per tenant.
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

export function createApp(cfg: Config): Hono {
  const deps: Deps = { authlete: makeAuthlete(cfg), config: cfg };
  const app = new Hono();

  // Cross-origin access for browser callers (e.g. the OAuth Playground). Driven
  // by AS_CORS_ORIGINS so each deployment configures its own allowlist. Scoped
  // to endpoints a browser RP legitimately hits — OAuth + discovery + federation
  // registration. /api/authorizations/* is intentionally excluded; it's the
  // AS↔auth-ui interaction protocol, server-to-server only.
  if (cfg.corsOrigins.length > 0) {
    const allowAll = cfg.corsOrigins.includes("*");
    const corsMiddleware = cors({
      origin: allowAll
        ? "*"
        : (origin) => (cfg.corsOrigins.includes(origin) ? origin : null),
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
      authlete: { baseUrl: cfg.authleteBaseUrl, serviceId: cfg.authleteServiceId },
      interactionApp: cfg.authUiUrl,
      discovery: `${cfg.asBaseUrl}/.well-known/openid-configuration`,
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

// Re-exported so a consumer can build a Config and call createApp — importing
// this module runs no env reads (nothing here has side effects).
export { fromEnv, type Config } from "./config.js";
