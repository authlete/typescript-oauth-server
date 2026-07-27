/**
 * Local development runner: hosts the OAuth server in a Node HTTP listener.
 * Not used on Vercel, which serves the server's default export directly.
 */

import { serve } from "@hono/node-server";
import server from "./server.js";
import { fromEnv } from "./app.js";

const { port } = fromEnv();
serve({ fetch: server.fetch, port }, () => {
  console.log(`typescript-oauth-server listening on http://localhost:${port}`);
});
