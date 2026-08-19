/**
 * The AS's client to the external consent service — used only in the
 * full CMF-style deployment where a separate consent service is the system-of-record
 * (CONSENT_UI_URL set). Grant-lifecycle side effects call these: `linkGrant`
 * (grant → consent record) after issue, and `notifyConsent` (Revoked | Expired).
 * Both no-op when no consent service is configured. Same mutual-JWT primitive as
 * AS ↔ auth-ui, addressed to the consent service.
 */

import type { Config } from "./config.js";
import { signJwt } from "./interaction/jwt.js";

/** Link the minted grant to its consent record, keyed by the record PK. */
export async function linkGrant(config: Config, consentId: string, grantId: string): Promise<void> {
  await post(config, "/consent/link-grant", { consent_id: consentId, grant_id: grantId });
}

/** Notify Revoked | Expired (out-of-band lifecycle), keyed by grant. */
export async function notifyConsent(
  config: Config,
  grantId: string,
  event: "revoked" | "expired",
): Promise<void> {
  await post(config, "/consent/notify", { grant_id: grantId, event });
}

async function post(config: Config, path: string, claims: Record<string, unknown>): Promise<void> {
  if (!config.consentUiUrl) return; // no consent service — nothing to push to
  const jwt = await signJwt(config, claims, { audience: config.consentUiIssuerId });
  const res = await fetch(`${config.consentUiUrl}${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
    body: "{}",
  });
  if (!res.ok) {
    throw new Error(`consent ${path} failed (${res.status}): ${await res.text()}`);
  }
}
