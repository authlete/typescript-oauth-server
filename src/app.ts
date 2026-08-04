/**
 * The OAuth/OIDC Authorization Server.
 *
 * `createOAuthServer(config)` builds a server from an explicit Config — no env,
 * no globals — so it is testable and embeddable. The default export is the
 * standalone server, built lazily on the first request so importing this
 * module reads no env.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import type { Authlete } from "@authlete/typescript-sdk/authlete";
import { fromEnv, type Config } from "./config.js";
import { makeAuthlete } from "./authlete.js";
import { wellKnownRoutes } from "./routes/well-known.js";
import { authorizeRoutes } from "./routes/authorize.js";
import { interactionRoutes } from "./interaction/routes.js";
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

  // Unexpected failures (Authlete unreachable, bad credentials, …) become a
  // JSON server_error with the cause logged, instead of Hono's plain-text 500.
  app.onError((err, c) => {
    console.error(`[${c.req.method} ${c.req.path}]`, err);
    return c.json(
      { error: "server_error", error_description: "Unexpected error — see server logs." },
      500,
    );
  });

  // Cross-origin access for browser callers (e.g. the OAuth Playground). Driven
  // by CORS_ORIGINS so each deployment configures its own allowlist. Scoped
  // to endpoints a browser RP legitimately hits — OAuth + discovery + federation
  // registration. /api/authorizations/* is intentionally excluded; it's the
  // AS↔auth-ui interaction protocol, server-to-server only.
  if (config.corsOrigins.length > 0) {
    const allowAll = config.corsOrigins.includes("*");
    const corsMiddleware = cors({
      origin: allowAll ? "*" : (origin) => (config.corsOrigins.includes(origin) ? origin : null),
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

  // Standard OAuth/OIDC surface — routes/.
  app.route("/", wellKnownRoutes(deps));
  app.route("/", authorizeRoutes(deps));
  app.route("/", tokenRoutes(deps));
  app.route("/", userinfoRoutes(deps));
  app.route("/", jwksRoutes(deps));
  app.route("/", introspectRoutes(deps));
  app.route("/", revokeRoutes(deps));
  app.route("/", parRoutes(deps));
  app.route("/", federationRoutes(deps));
  app.route("/", registerRoutes(deps));

  // AS ↔ auth-ui contract — interaction/ (INTERACTION_PROTOCOL.md).
  app.route("/", interactionRoutes(deps));

  return app;
}

export { fromEnv, type Config } from "./config.js";

// Default export: the standalone server. Built lazily on the first request so
// importing this module stays side-effect-free (env is read only when serving,
// never at import). The deployment serves this for every route; server.ts runs it locally.
let standalone: Hono | undefined;
export default {
  fetch(request: Request) {
    standalone ??= createOAuthServer(fromEnv());
    return standalone.fetch(request);
  },
};
