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

export const config = {
  authleteBaseUrl: optional("AUTHLETE_BASE_URL", "https://us.authlete.com"),
  authleteServiceId: required("AUTHLETE_SERVICE_ID"),
  authleteApiToken: required("AUTHLETE_API_TOKEN"),
  asBaseUrl: required("AS_BASE_URL"),
  authUiUrl: required("AUTH_UI_URL"),
  port: parseInt(optional("PORT", "3000"), 10),
  nodeEnv: optional("NODE_ENV", "development"),
  // Origins allowed to call OAuth endpoints from a browser (the Playground, etc.).
  // Comma-separated. Use "*" only for permissive dev. Empty = no CORS.
  corsOrigins: list("AS_CORS_ORIGINS"),
} as const;

export type Config = typeof config;
