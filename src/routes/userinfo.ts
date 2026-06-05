/**
 * /oauth/userinfo — OIDC Core 1.0 §5.3.
 *
 * Two-step Authlete protocol:
 *  1. POST /auth/userinfo  → validates the token, lists the claim names
 *     the RP is entitled to (filtered by granted scopes).
 *  2. POST /auth/userinfo/issue with values for those claims → final response
 *     body (JSON or signed JWT, depending on client configuration).
 *
 * Claim values are sourced live from `auth-ui` at userinfo-call time, matching
 * OIDC convention (Google, Auth0, Okta, Keycloak). The AS fetches the user
 * resource from `GET <AUTH_UI>/api/users/{id}` and projects it onto the OIDC
 * claim names the user consented to release.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * TODO(claims-leakage): The end-to-end consent contract is INCOMPLETE.
 *
 * Per Authlete's KB on customising userinfo claims, the right model is:
 *   • The OP MUST explicitly pass `consentedClaims` (the list of claim names
 *     the end-user agreed to release) at /auth/authorization/issue time.
 *   • Authlete persists `consentedClaims` against the access token; it then
 *     echoes it back in /auth/userinfo and /auth/introspection.
 *   • The OP, at /userinfo handling time, reads `consentedClaims` from the
 *     /auth/userinfo response and returns ONLY those claim values via
 *     /auth/userinfo/issue.
 *
 * What this AS does today (and what's still broken):
 *   ✓ /userinfo reads `consentedClaims` (fallback `claims`, then []) and
 *     projects the user resource through that filter — see `projectClaims`.
 *   ✗ /authorizations/{id}/resume calls /auth/authorization/issue WITHOUT
 *     an explicit `consentedClaims` parameter (see routes/authorizations.ts).
 *     The fact that `consentedClaims` shows up populated in /auth/userinfo
 *     responses today is INCIDENTAL — Authlete is auto-deriving it from
 *     either the granted scopes or the claim VALUES we pass. That auto-
 *     derivation is not contractual and can quietly become wrong when:
 *       · auth-ui supports per-claim consent (user unchecks a specific claim
 *         under a granted scope) — Authlete won't know the user de-selected
 *         it, so /userinfo will keep returning it.
 *       · The RP requests claims via the OIDC `claims` request parameter
 *         (RFC 7517 §5.5) — Authlete may include all requested ones in
 *         consentedClaims even though the user only saw scope-level consent.
 *   ✗ auth-ui's decision payload only carries `granted_scopes`. It does NOT
 *     carry the per-claim grant set. We need a `granted_claims` (claim-name
 *     list) field on the Decision and we must forward it to Authlete at
 *     /issue time as `consentedClaims`.
 *
 * Properly fixing this requires changes on three layers in lock-step:
 *   1. auth-ui consent UI: support per-claim toggles (or derive the granted
 *      claim list from the granted scopes if not exposing per-claim UI).
 *   2. auth-ui → AS decision JWT: add `granted_claims: string[]`.
 *   3. AS /authorizations/{id}/resume: pass `consentedClaims` to Authlete
 *      /auth/authorization/issue.
 * Once that's done, the filter here becomes authoritative end-to-end.
 *
 * Reference: https://www.authlete.com/kb/oauth-and-openid-connect/userinfo-endpoint/customize-userinfo-claims/
 * ─────────────────────────────────────────────────────────────────────────────
 */

import type { Context } from "hono";
import { Hono } from "hono";
import { authlete } from "../authlete.js";
import { config } from "../config.js";
import { bearerAuthChallenge, bearerChallenge, extractBearer, noStoreJsonHeaders } from "../http.js";
import { fetchUser } from "../auth-ui-client.js";

export const userinfo = new Hono();

userinfo.get("/oauth/userinfo", async (c) => handle(c, extractAccessToken(c)));

userinfo.post("/oauth/userinfo", async (c) => {
  // OIDC §5.3.1: the token may come via Authorization header OR form body.
  // A POST without a form body is also legal (openid/connect#1137).
  let formToken: string | undefined;
  if (c.req.header("content-type")?.includes("application/x-www-form-urlencoded")) {
    const v = (await c.req.parseBody())["access_token"];
    if (typeof v === "string") formToken = v;
  }
  return handle(c, extractAccessToken(c, formToken));
});

async function handle(c: Context, token: string | undefined): Promise<Response> {
  if (!token) return bearerChallenge(c, 401);

  const proc = await authlete.userinfo.process({
    serviceId: config.authleteServiceId,
    userinfoRequest: { token },
  });

  if (proc.action !== "OK") {
    return mapErrorAction(c, proc.action, proc.responseContent);
  }

  // If Authlete didn't supply values itself, fetch the user live from auth-ui
  // and project onto the claims the user actually consented to release.
  // `consentedClaims` is authoritative (user's actual grant); `claims` is the
  // requested set (may be wider). Falling through to "no filter" would leak
  // claims the user did not consent to.
  let claimsJson = proc.userInfoClaims;
  if (!claimsJson && proc.subject) {
    const user = await fetchUser(proc.subject);
    if (user) {
      const consented = proc.consentedClaims ?? proc.claims ?? [];
      claimsJson = JSON.stringify(projectClaims(user, consented));
    }
  }

  const issue = await authlete.userinfo.issue({
    serviceId: config.authleteServiceId,
    userinfoIssueRequest: {
      token,
      claims: claimsJson,
      sub: proc.subject,
    },
  });

  switch (issue.action) {
    case "JSON":
      return c.body(issue.responseContent ?? "{}", 200, noStoreJsonHeaders);
    case "JWT":
      return c.body(issue.responseContent ?? "", 200, {
        ...noStoreJsonHeaders,
        "content-type": "application/jwt",
      });
    default:
      return mapErrorAction(c, issue.action, issue.responseContent);
  }
}

function mapErrorAction(c: Context, action: string | undefined, responseContent: string | undefined): Response {
  const wwwAuth = responseContent || bearerAuthChallenge;
  switch (action) {
    case "UNAUTHORIZED":
      return bearerChallenge(c, 401, wwwAuth);
    case "FORBIDDEN":
      return bearerChallenge(c, 403, wwwAuth);
    case "BAD_REQUEST":
      return bearerChallenge(c, 400, wwwAuth);
    case "INTERNAL_SERVER_ERROR":
    default:
      return c.body(responseContent ?? "", 500, noStoreJsonHeaders);
  }
}

/**
 * Project a user resource onto the OIDC claim shape Authlete requested.
 *
 * `wanted` is the authoritative filter (per Authlete's KB, prefer
 * `consentedClaims` over `claims`). `sub` is always added because OIDC
 * Core §5.3.2 requires it in every UserInfo response.
 */
function projectClaims(
  user: Record<string, unknown>,
  wanted: string[],
): Record<string, unknown> {
  const mappings: Array<[claim: string, value: unknown]> = [
    ["sub", user.id],
    ["name", user.name],
    ["email", user.email],
    ["email_verified", user.email_verified],
    ["picture", user.picture],
  ];
  const allowed = new Set([...wanted, "sub"]);
  const out: Record<string, unknown> = {};
  for (const [claim, value] of mappings) {
    if (value === undefined) continue;
    if (!allowed.has(claim)) continue;
    out[claim] = value;
  }
  return out;
}

/** Authorization header → form body → query string (RFC 6750 §2). */
function extractAccessToken(c: Context, formToken?: string): string | undefined {
  return extractBearer(c.req.header("authorization")) || formToken || c.req.query("access_token") || undefined;
}
