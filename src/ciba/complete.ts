/** Finalize a CIBA transaction from the device's decision — the CIBA counterpart of steps.ts finalize(). */

import type { Authlete } from "@authlete/typescript-sdk/authlete";
import type { BackchannelAuthenticationCompleteResponse } from "@authlete/typescript-sdk/models/backchannelauthenticationcompleteresponse";
import type { Config } from "../config.js";

/** The device's outcome, on the wire (snake_case, as in interaction §2). */
export type CibaOutcome =
  | {
      subject: string;
      acr?: string;
      auth_time?: number;
      user_claims?: Record<string, unknown>;
      granted_scopes?: string[];
    }
  | { error: string; error_description?: string };

export async function completeCiba(
  authlete: Authlete,
  config: Config,
  ticket: string,
  outcome: CibaOutcome,
): Promise<void> {
  const req =
    "error" in outcome
      ? // subject required by the API, ignored unless AUTHORIZED
        {
          ticket,
          result: "ACCESS_DENIED" as const,
          subject: "",
          errorDescription: outcome.error_description,
        }
      : {
          ticket,
          result: "AUTHORIZED" as const,
          subject: outcome.subject,
          authTime: outcome.auth_time,
          acr: outcome.acr,
          claims: outcome.user_claims ? JSON.stringify(outcome.user_claims) : undefined,
          scopes: outcome.granted_scopes,
        };

  const res = await authlete.ciba.complete({
    serviceId: config.authleteServiceId,
    backchannelAuthenticationCompleteRequest: req,
  });
  if (res.action === "NOTIFICATION") await pingClient(res);
}

/** Fail a live transaction (e.g. the device was unreachable) so the client's poll ends fast. */
export async function failCiba(
  authlete: Authlete,
  config: Config,
  ticket: string,
  errorDescription: string,
): Promise<void> {
  await authlete.ciba.complete({
    serviceId: config.authleteServiceId,
    backchannelAuthenticationCompleteRequest: {
      ticket,
      result: "TRANSACTION_FAILED",
      subject: "", // required by the API, ignored unless AUTHORIZED
      errorDescription,
    },
  });
}

/** ping/push delivery: hand Authlete's responseContent to the client's endpoint. */
async function pingClient(res: BackchannelAuthenticationCompleteResponse): Promise<void> {
  if (!res.clientNotificationEndpoint) return;
  const r = await fetch(res.clientNotificationEndpoint, {
    method: "POST",
    redirect: "manual", // never follow redirects
    headers: {
      "content-type": "application/json",
      ...(res.clientNotificationToken
        ? { authorization: `Bearer ${res.clientNotificationToken}` }
        : {}),
    },
    body: res.responseContent ?? "{}",
  });
  if (r.status !== 200 && r.status !== 204) {
    throw new Error(`client notification failed (${r.status})`);
  }
}
