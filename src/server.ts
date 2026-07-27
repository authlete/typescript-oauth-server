/**
 * Standalone / Vercel entry: the OAuth server built from the process environment.
 *
 * Vercel serves this default export. Local `npm run dev` / `npm start` run it
 * via the Node listener in dev.ts. Package consumers import `./app.js` (the
 * side-effect-free library) — importing this file reads env via fromEnv().
 */

import { createOAuthServer, fromEnv } from "./app.js";

export default createOAuthServer(fromEnv());
