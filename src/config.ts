/**
 * Environment configuration for the AS.
 *
 * Single source of truth for env vars. Imports throughout the app should pull
 * from here so the env surface is explicit and easy to audit.
 */

function required(name: string): string {
  const v = process.env[name];
  if (!v || v.length === 0) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return v;
}

function optional(name: string, fallback: string): string {
  const v = process.env[name];
  return v && v.length > 0 ? v : fallback;
}

function list(name: string): string[] {
  const v = process.env[name];
  if (!v) return [];
  return v.split(",").map((s) => s.trim()).filter(Boolean);
}

const asBaseUrl = required("AS_BASE_URL");
const authUiUrl = required("AUTH_UI_URL");

export const config = {
  authleteBaseUrl: optional("AUTHLETE_BASE_URL", "https://us.authlete.com"),
  authleteServiceId: required("AUTHLETE_SERVICE_ID"),
  authleteApiToken: required("AUTHLETE_API_TOKEN"),
  asBaseUrl,
  authUiUrl,
  port: parseInt(optional("PORT", "3000"), 10),
  nodeEnv: optional("NODE_ENV", "development"),
  // Origins allowed to call OAuth endpoints from a browser (the Playground, etc.).
  // Comma-separated. Use "*" only for permissive dev. Empty = no CORS.
  corsOrigins: list("AS_CORS_ORIGINS"),

  // Issuer/audience identifiers for inter-component JWTs; default to base URLs.
  asIssuerId: optional("AS_ISSUER_ID", asBaseUrl),
  authUiIssuerId: optional("AUTH_UI_ISSUER_ID", authUiUrl),
  authUiJwksUri: optional("AUTH_UI_JWKS_URI", `${authUiUrl}/.well-known/jwks.json`),
  interactionChannel: optional("INTERACTION_CHANNEL", "backchannel") as
    | "backchannel"
    | "frontchannel",
  // The AS's private JWKS for component-protocol signing. Public counterparts
  // must be registered with the Authlete service so they appear in /oauth/jwks.
  asSigningJwks: optional("AS_SIGNING_JWKS", ""),
  asSigningKid: optional("AS_SIGNING_KID", ""),
} as const;

export type Config = typeof config;
