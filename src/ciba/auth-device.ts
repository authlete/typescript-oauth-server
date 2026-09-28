/**
 * The AS's client to the CIBA authentication device (auth-ui by default): pushes a
 * pending backchannel request over mutual-JWT. See INTERACTION_PROTOCOL.md.
 */

import type { Config } from "../config.js";
import type { RarElement, Scope } from "../interaction/context.js";
import { signJwt } from "../interaction/jwt.js";

/** Pushed to the device, on the wire (snake_case). Mirrors the consent payload so the device renders scopes + RAR. */
type PendingAuthorization = {
  /** Authlete ticket — the device returns it with the outcome. */
  ticket: string;
  login_hint?: string;
  client_name?: string;
  scopes: Scope[];
  authorization_details: RarElement[];
  binding_message?: string;
  expires_at: number;
};

export async function notifyAuthDevice(
  config: Config,
  pending: PendingAuthorization,
): Promise<void> {
  const jwt = await signJwt(config, { ...pending }, { audience: config.authDeviceIssuerId });
  const res = await fetch(`${config.authDeviceUrl}/ciba/requests`, {
    method: "POST",
    headers: { authorization: `Bearer ${jwt}`, "content-type": "application/json" },
    body: "{}",
  });
  if (!res.ok) {
    throw new Error(`auth-device notify failed (${res.status}): ${await res.text()}`);
  }
}
