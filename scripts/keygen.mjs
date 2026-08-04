#!/usr/bin/env node
/**
 * Generate the AS's interaction-protocol signing key (ES256).
 *
 * Prints a ready-to-paste `AS_SIGNING_JWKS=...` line on stdout, so both work:
 *   npm run keygen              # copy the line into .env or the Vercel env UI
 *   npm run keygen >> .env      # append it directly
 */

import { generateKeyPair, exportJWK, calculateJwkThumbprint } from "jose";

const { privateKey } = await generateKeyPair("ES256", { extractable: true });
const jwk = await exportJWK(privateKey);
jwk.kid = await calculateJwkThumbprint(jwk);
jwk.alg = "ES256";
jwk.use = "sig";

console.error("New ES256 interaction signing key (private — keep it secret):\n");
console.log(`AS_SIGNING_JWKS=${JSON.stringify({ keys: [jwk] })}`);
console.error("\nThe public half is served automatically at /.well-known/jwks.json.");
