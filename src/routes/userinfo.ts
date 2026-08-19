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
 * TODO(claims-leakage): per-claim consent is not yet plumbed end-to-end. The
 * outcome payload from auth-ui carries only `granted_scopes`, and /resume does
 * not pass `consentedClaims` to Authlete /auth/authorization/issue — so the
 * `consentedClaims` filter used below is Authlete's scope-derived default, not
 * an explicit user grant. Fix requires a `granted_claims` field in the
 * interaction protocol plus forwarding it at /issue time. See
 * https://www.authlete.com/kb/oauth-and-openid-connect/userinfo-endpoint/customize-userinfo-claims/
 */

import type { Context } from "hono";
import { Hono } from "hono";
import type { Deps } from "../app.js";
import {
  bearerAuthChallenge,
  bearerChallenge,
  extractBearer,
  noStoreJsonHeaders,
} from "../http.js";
import { fetchUser } from "../interaction/auth-ui-client.js";

export function userinfoRoutes({ authlete, config }: Deps) {
  const userinfo = new Hono();

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
      const user = await fetchUser(config, proc.subject);
      if (user) {
        const consented = proc.consentedClaims ?? proc.claims ?? [];
        claimsJson = JSON.stringify(projectClaims(user, consented));
      }
    }

    const issue = await authlete.userinfo.issue({
      serviceId: config.authleteServiceId,
      userinfoIssueRequest: { token, claims: claimsJson, sub: proc.subject },
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

  return userinfo;
}

function mapErrorAction(
  c: Context,
  action: string | undefined,
  responseContent: string | undefined,
): Response {
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
function projectClaims(user: Record<string, unknown>, wanted: string[]): Record<string, unknown> {
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
  return (
    extractBearer(c.req.header("authorization")) ||
    formToken ||
    c.req.query("access_token") ||
    undefined
  );
}
