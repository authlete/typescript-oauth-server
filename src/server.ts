/**
 * Hono app. Mounts route modules and exports the app as the default export.
 *
 * The default export is what Vercel serves directly (each route becomes a
 * Vercel Function). For local development, `src/dev.ts` wraps this app in a
 * Node HTTP listener.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { config } from "./config.js";
import { wellKnown } from "./routes/well-known.js";
import { authorize } from "./routes/authorize.js";
import { authorizations } from "./routes/authorizations.js";
import { token } from "./routes/token.js";
import { userinfo } from "./routes/userinfo.js";
import { jwks } from "./routes/jwks.js";
import { introspect } from "./routes/introspect.js";
import { revoke } from "./routes/revoke.js";
import { par } from "./routes/par.js";
import { federation } from "./routes/federation.js";
import { register } from "./routes/register.js";

const app = new Hono();

// Cross-origin access for browser callers (e.g. the OAuth Playground). Driven
// by AS_CORS_ORIGINS so each deployment configures its own allowlist. Scoped
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
    authlete: {
      baseUrl: config.authleteBaseUrl,
      serviceId: config.authleteServiceId,
    },
    interactionApp: config.authUiUrl,
    discovery: `${config.asBaseUrl}/.well-known/openid-configuration`,
  }),
);

app.get("/health", (c) => c.json({ status: "ok" }));
app.route("/", wellKnown);
app.route("/", authorize);
app.route("/", authorizations);
app.route("/", token);
app.route("/", userinfo);
app.route("/", jwks);
app.route("/", introspect);
app.route("/", revoke);
app.route("/", par);
app.route("/", federation);
app.route("/", register);

export default app;
