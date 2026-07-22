/**
 * Local development server.
 *
 * Wraps the Hono app in a Node HTTP listener for `npm run dev` / `npm start`.
 * Not used on Vercel, where the app's default export is served directly.
 */

import { serve } from "@hono/node-server";
import app from "./server.js";
import { config } from "./config.js";

serve({ fetch: app.fetch, port: config.port }, ({ port }) => {
  console.log(`typescript-oauth-server listening on http://localhost:${port}`);
});
