/**
 * Dynamic Client Registration — RFC 7591 (registration) + RFC 7592 (management).
 *
 * Extract the bearer token, forward the raw body to Authlete, and map the
 * response action to HTTP. The AS holds no client state — Authlete owns it all.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7591
 * @see https://datatracker.ietf.org/doc/html/rfc7592
 */

import type { Context } from "hono";
import { Hono } from "hono";
import type { ClientRegistrationResponse } from "@authlete/typescript-sdk/models";
import { authlete } from "../authlete.js";
import { config } from "../config.js";
import { extractBearer, noStoreJsonHeaders } from "../http.js";

export const register = new Hono();

// RFC 7591 §3.1 — register a client. The bearer token, if present, is the
// initial access token; Authlete decides whether one is required.
register.post("/api/register", async (c) => {
  const res = await authlete.dynamicClientRegistration.register({
    serviceId: config.authleteServiceId,
    requestBody: {
      json: await c.req.text(),
      token: extractBearer(c.req.header("authorization")),
    },
  });
  return dispatch(c, res);
});

// RFC 7592 §2.1 — read the current registration. The bearer token is the
// registration access token issued at creation.
register.get("/api/register/:id", async (c) => {
  const res = await authlete.dynamicClientRegistration.get({
    serviceId: config.authleteServiceId,
    requestBody: {
      clientId: c.req.param("id"),
      token: extractBearer(c.req.header("authorization")) ?? "",
    },
  });
  return dispatch(c, res);
});

// RFC 7592 §2.2 — replace the client's metadata.
register.put("/api/register/:id", async (c) => {
  const res = await authlete.dynamicClientRegistration.update({
    serviceId: config.authleteServiceId,
    requestBody: {
      clientId: c.req.param("id"),
      json: await c.req.text(),
      token: extractBearer(c.req.header("authorization")) ?? "",
    },
  });
  return dispatch(c, res);
});

// RFC 7592 §2.3 — deregister the client.
register.delete("/api/register/:id", async (c) => {
  const res = await authlete.dynamicClientRegistration.delete({
    serviceId: config.authleteServiceId,
    requestBody: {
      clientId: c.req.param("id"),
      token: extractBearer(c.req.header("authorization")) ?? "",
    },
  });
  return dispatch(c, res);
});

function dispatch(c: Context, res: ClientRegistrationResponse): Response {
  const body = res.responseContent ?? "";
  switch (res.action) {
    case "CREATED":
      return c.body(body, 201, noStoreJsonHeaders);
    case "UPDATED":
    case "OK":
      return c.body(body, 200, noStoreJsonHeaders);
    case "DELETED":
      return c.body(null, 204, noStoreJsonHeaders);
    case "BAD_REQUEST":
      return c.body(body, 400, noStoreJsonHeaders);
    case "UNAUTHORIZED":
      return c.body(body, 401, noStoreJsonHeaders);
    case "INTERNAL_SERVER_ERROR":
    default:
      return c.body(body, 500, noStoreJsonHeaders);
  }
}
