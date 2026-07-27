/**
 * Local development runner: hosts the standalone server in a Node HTTP listener.
 * A deployed standalone server instead has the platform invoke app.ts's default export.
 */

import { serve } from "@hono/node-server";
import app, { fromEnv } from "./app.js";

const { port } = fromEnv();
serve({ fetch: app.fetch, port }, () => {
  console.log(`typescript-oauth-server listening on http://localhost:${port}`);
});
