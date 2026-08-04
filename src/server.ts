/**
 * Server entry point: hosts the app in a Node HTTP listener. Used by
 * `npm run dev` and `npm start`; serverless deployments instead invoke
 * app.ts's default export directly.
 */

import { serve } from "@hono/node-server";
import app, { fromEnv } from "./app.js";

const { port } = fromEnv();
serve({ fetch: app.fetch, port }, () => {
  console.log(`typescript-oauth-server listening on http://localhost:${port}`);
});
