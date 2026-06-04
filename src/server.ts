/**
 * Hono app entry. Mounts route modules and starts the runtime adapter.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { serve } from "@hono/node-server";
import { config } from "./config.js";
import { wellKnown } from "./routes/well-known.js";
import { authorize } from "./routes/authorize.js";
import { interactions } from "./routes/interactions.js";
import { token } from "./routes/token.js";
import { userinfo } from "./routes/userinfo.js";
import { jwks } from "./routes/jwks.js";
import { introspect } from "./routes/introspect.js";
import { revoke } from "./routes/revoke.js";
import { par } from "./routes/par.js";

const app = new Hono();

// Cross-origin access for browser callers (e.g. the OAuth Playground). Driven
// by AS_CORS_ORIGINS so each deployment configures its own allowlist. Scoped
// to OAuth + discovery endpoints; /api/interactions/* is server-to-server.
if (config.corsOrigins.length > 0) {
  const allowAll = config.corsOrigins.includes("*");
  const corsMiddleware = cors({
    origin: allowAll
      ? "*"
      : (origin) => (config.corsOrigins.includes(origin) ? origin : null),
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Authorization", "Content-Type", "DPoP"],
    exposeHeaders: ["WWW-Authenticate"],
    maxAge: 600,
  });
  app.use("/.well-known/*", corsMiddleware);
  app.use("/oauth/*", corsMiddleware);
}

app.get("/health", (c) => c.json({ status: "ok" }));
app.route("/", wellKnown);
app.route("/", authorize);
app.route("/", interactions);
app.route("/", token);
app.route("/", userinfo);
app.route("/", jwks);
app.route("/", introspect);
app.route("/", revoke);
app.route("/", par);

serve({ fetch: app.fetch, port: config.port }, ({ port }) => {
  // eslint-disable-next-line no-console
  console.log(`typescript-oauth-server listening on http://localhost:${port}`);
});
