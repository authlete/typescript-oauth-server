/**
 * /oauth/userinfo — OIDC Core 1.0 §5.3.
 *
 * Two-step Authlete protocol:
 *  1. POST /auth/userinfo  → validates the token, lists the claim names
 *     the RP is entitled to (filtered by granted scopes).
 *  2. POST /auth/userinfo/issue with values for those claims → final response
 *     body (JSON or signed JWT, depending on client configuration).
 *
 * Claim values come from `userstore` — populated when auth-ui submits an
 * approved decision.
 */

import type { Context } from "hono";
import { Hono } from "hono";
import { authlete } from "../authlete.js";
import { config } from "../config.js";
import { bearerAuthChallenge, bearerChallenge, extractBearer, noStoreJsonHeaders } from "../http.js";
import { getClaims } from "../userstore.js";

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

  // Only look up cached claim values when Authlete didn't supply them itself.
  let claimsJson = proc.userInfoClaims;
  if (!claimsJson) {
    const cached = getClaims(proc.subject);
    if (cached) claimsJson = JSON.stringify(pickClaims(cached, proc.claims));
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

function pickClaims(all: Record<string, unknown>, wanted: string[] | undefined): Record<string, unknown> {
  if (!wanted?.length) return all;
  const out: Record<string, unknown> = {};
  for (const name of wanted) if (name in all) out[name] = all[name];
  return out;
}

/** Authorization header → form body → query string (RFC 6750 §2). */
function extractAccessToken(c: Context, formToken?: string): string | undefined {
  return extractBearer(c.req.header("authorization")) || formToken || c.req.query("access_token") || undefined;
}
