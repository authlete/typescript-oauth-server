/**
 * Configuration for the AS.
 *
 * `fromEnv()` builds a Config from the process environment. Importing this
 * module has NO side effects — nothing reads env until `fromEnv()` is called
 * (by the standalone entry). A package consumer (e.g. a multi-tenant host that
 * builds its own per-tenant Config) can import the library without needing any
 * single service's env.
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

export interface Config {
  authleteBaseUrl: string;
  authleteServiceId: string;
  authleteApiToken: string;
  asBaseUrl: string;
  authUiUrl: string;
  port: number;
  nodeEnv: string;
  corsOrigins: string[];
  asIssuerId: string;
  authUiIssuerId: string;
  authUiJwksUri: string;
  asSigningJwks: string;
  asSigningKid: string;
}

// The AS's public origin. Prefer the explicit AS_BASE_URL; on Vercel preview
// deployments (unique per-deploy domain) fall back to VERCEL_URL so the issuer
// resolves without hardcoding. Production should set AS_BASE_URL explicitly.
function resolveAsBaseUrl(): string {
  const explicit = process.env.AS_BASE_URL;
  if (explicit && explicit.length > 0) return explicit;
  const vercelUrl = process.env.VERCEL_URL;
  if (vercelUrl && vercelUrl.length > 0) return `https://${vercelUrl}`;
  throw new Error("Missing required env var: AS_BASE_URL");
}

/** Build a Config from the process environment. Throws if a required var is missing. */
export function fromEnv(): Config {
  const asBaseUrl = resolveAsBaseUrl();
  const authUiUrl = required("AUTH_UI_URL");
  return {
    authleteBaseUrl: optional("AUTHLETE_BASE_URL", "https://us.authlete.com"),
    authleteServiceId: required("AUTHLETE_SERVICE_ID"),
    authleteApiToken: required("AUTHLETE_API_TOKEN"),
    asBaseUrl,
    authUiUrl,
    port: parseInt(optional("PORT", "3000"), 10),
    nodeEnv: optional("NODE_ENV", "development"),
    corsOrigins: list("CORS_ORIGINS"),
    // Own identity is the base URL; the peer's identity and JWKS derive from its
    // URL — same convention on both sides of the interaction protocol.
    asIssuerId: asBaseUrl,
    authUiIssuerId: authUiUrl,
    authUiJwksUri: `${authUiUrl}/.well-known/jwks.json`,
    asSigningJwks: optional("AS_SIGNING_JWKS", ""),
    asSigningKid: "",
  };
}
