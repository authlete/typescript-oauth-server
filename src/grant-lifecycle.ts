/**
 * Post-processing for OAuth grants, fired by the generic protocol endpoints: a
 * grant surfaces at /token (grant management was used) and is revoked at /gm.
 * Those endpoints stay generic — they just call these hooks. The side effects
 * (here, syncing an external consent store) live behind this seam, so /token and
 * /gm never reference the consent service.
 */

import type { Config } from "./config.js";
import { linkGrant, notifyConsent } from "./external-consent-client.js";

/** A grant surfaced at token issue (grant management was used). */
export async function onGrantIssued(
  config: Config,
  res: { action?: string; grantId?: string; properties?: { key?: string; value?: string }[] },
): Promise<void> {
  if (res.action !== "OK" || !res.grantId) return;
  // If the grant carries a consent-record id (set as a hidden property at issue),
  // link the two in the consent store.
  const consentId = res.properties?.find((p) => p.key === "consent_id")?.value;
  if (consentId) {
    await linkGrant(config, consentId, res.grantId).catch((e) =>
      console.error("grant post-processing: consent link-grant failed", e),
    );
  }
}

/** A grant was revoked via grant management. */
export async function onGrantRevoked(config: Config, grantId: string): Promise<void> {
  await notifyConsent(config, grantId, "revoked").catch((e) =>
    console.error("grant post-processing: consent notify revoked failed", e),
  );
}
