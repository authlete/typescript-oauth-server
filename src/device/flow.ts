/**
 * Device Authorization Grant (RFC 8628) — verification lookup + completion.
 * Both are keyed by user_code (the device-flow handle); Authlete owns the state.
 */

import type { Authlete } from "@authlete/typescript-sdk/authlete";
import type { Config } from "../config.js";
import { normalizeRar, type RarElement, type Scope } from "../interaction/context.js";

/** What the device-verification UI needs to render consent, or why it can't. */
export type DeviceVerification =
  | {
      ok: true;
      client_name?: string;
      scopes: Scope[];
      authorization_details: RarElement[];
      expires_at?: number;
    }
  | { ok: false; reason: "not_found" | "expired" };

export async function verifyDevice(
  authlete: Authlete,
  config: Config,
  userCode: string,
): Promise<DeviceVerification> {
  const res = await authlete.deviceFlow.verification({
    serviceId: config.authleteServiceId,
    deviceVerificationRequest: { userCode },
  });
  switch (res.action) {
    case "VALID":
      return {
        ok: true,
        client_name: res.clientName,
        scopes: (res.scopes ?? []).map((s) => ({ name: s.name ?? "", description: s.description })),
        authorization_details: normalizeRar(
          (res.authorizationDetails?.elements ?? []) as RarElement[],
        ),
        expires_at: res.expiresAt ? Math.floor(res.expiresAt / 1000) : undefined, // ms → s
      };
    case "NOT_EXIST":
      return { ok: false, reason: "not_found" };
    case "EXPIRED":
      return { ok: false, reason: "expired" };
    default:
      throw new Error(`device/verification returned ${res.action}`);
  }
}

/** The decision the device UI reports (same shape as CIBA's outcome). */
export type DeviceOutcome =
  | {
      subject: string;
      acr?: string;
      auth_time?: number;
      user_claims?: Record<string, unknown>;
      granted_scopes?: string[];
    }
  | { error: string; error_description?: string };

/** Finalize the device transaction. Returns Authlete's action for the caller to map. */
export async function completeDevice(
  authlete: Authlete,
  config: Config,
  userCode: string,
  outcome: DeviceOutcome,
): Promise<string | undefined> {
  const req =
    "error" in outcome
      ? // subject required by the API, ignored unless AUTHORIZED
        {
          userCode,
          result: "ACCESS_DENIED" as const,
          subject: "",
          errorDescription: outcome.error_description,
        }
      : {
          userCode,
          result: "AUTHORIZED" as const,
          subject: outcome.subject,
          authTime: outcome.auth_time,
          acr: outcome.acr,
          claims: outcome.user_claims ? JSON.stringify(outcome.user_claims) : undefined,
          scopes: outcome.granted_scopes,
        };
  const res = await authlete.deviceFlow.complete({
    serviceId: config.authleteServiceId,
    deviceCompleteRequest: req,
  });
  return res.action;
}
