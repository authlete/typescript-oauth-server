/** CIBA (backchannel authentication): the client request, and the auth device's outcome. See INTERACTION_PROTOCOL.md. */

import { Hono } from "hono";
import type { Deps } from "../app.js";
import { basicChallengeHeaders, basicCredsFor, sendAuthleteAction } from "../http.js";
import { normalizeRar, type RarElement } from "../interaction/context.js";
import { requireInteractionJwt } from "../interaction/guard.js";
import { notifyAuthDevice } from "../ciba/auth-device.js";
import { completeCiba, failCiba, type CibaOutcome } from "../ciba/complete.js";

export function backchannelRoutes({ authlete, config }: Deps) {
  const bc = new Hono();

  bc.post("/api/backchannel/authentication", async (c) => {
    const parameters = await c.req.text();
    const res = await authlete.ciba.processAuthentication({
      serviceId: config.authleteServiceId,
      backchannelAuthenticationRequest: { parameters, ...basicCredsFor(c) },
    });
    if (res.action !== "USER_IDENTIFICATION" || !res.ticket) {
      return sendAuthleteAction(c, res, {
        BAD_REQUEST: 400,
        UNAUTHORIZED: { status: 401, headers: basicChallengeHeaders },
        INTERNAL_SERVER_ERROR: 500,
      });
    }

    const issued = await authlete.ciba.issue({
      serviceId: config.authleteServiceId,
      backchannelAuthenticationIssueRequest: { ticket: res.ticket },
    });
    if (issued.action !== "OK") {
      return sendAuthleteAction(c, issued, { INVALID_TICKET: 500, INTERNAL_SERVER_ERROR: 500 });
    }

    const expiresIn = issued.expiresIn ?? 600;
    try {
      await notifyAuthDevice(config, {
        ticket: res.ticket,
        login_hint: res.hint,
        client_name: res.clientName,
        scopes: (res.scopes ?? []).map((s) => ({ name: s.name ?? "", description: s.description })),
        authorization_details: normalizeRar(
          (res.authorizationDetails?.elements ?? []) as RarElement[],
        ),
        binding_message: res.bindingMessage,
        expires_at: Math.floor(Date.now() / 1000) + expiresIn,
      });
    } catch (err) {
      // Delivery is best-effort; Fail the transaction so its poll ends fast instead of hanging until expiry.
      console.error("[backchannel] auth device unreachable; failing transaction", err);
      await failCiba(authlete, config, res.ticket, "authentication device unreachable").catch((e) =>
        console.error("[backchannel] failing transaction failed", e),
      );
    }

    return sendAuthleteAction(c, issued, { OK: 200 });
  });

  bc.post("/api/backchannel/outcome", async (c) => {
    const caller = await requireInteractionJwt(c, config);
    if (caller instanceof Response) return caller;

    const ticket = caller.payload.ticket as string | undefined;
    const outcome = caller.payload.outcome as CibaOutcome | undefined;
    if (!ticket || !outcome) {
      return c.json(
        { error: "invalid_request", error_description: "ticket and outcome required" },
        400,
      );
    }

    await completeCiba(authlete, config, ticket, outcome);
    return c.body(null, 204);
  });

  return bc;
}
