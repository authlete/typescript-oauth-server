/**
 * Local development runner: wraps the standalone app in a Node HTTP listener.
 * Not used on Vercel, which serves the app's default export directly.
 */

import { serve } from "@hono/node-server";
import app from "./server.js";
import { fromEnv } from "./app.js";

const { port } = fromEnv();
serve({ fetch: app.fetch, port }, () => {
  console.log(`typescript-oauth-server listening on http://localhost:${port}`);
});
