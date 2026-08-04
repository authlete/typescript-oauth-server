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
import type { Deps } from "../app.js";
import { extractBearer, sendAuthleteAction } from "../http.js";

export function registerRoutes({ authlete, config }: Deps) {
  const register = new Hono();

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

  return register;
}

function dispatch(c: Context, res: ClientRegistrationResponse): Response {
  return sendAuthleteAction(c, res, {
    CREATED: 201,
    UPDATED: 200,
    OK: 200,
    DELETED: { status: 204, body: null },
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    INTERNAL_SERVER_ERROR: 500,
  });
}
