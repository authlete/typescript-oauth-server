/**
 * The interaction transaction context lives on the Authlete ticket — the AS keeps
 * no local state. `ticket/update` attaches the JSON context; `ticket/info` reads
 * it back.
 *
 * Direct fetch, not the SDK: the published SDK's spec declares ticket/update's
 * `info` field as `string`, but the live API requires `info: { context: string }`
 * (matching the response shape). Speakeasy validates the request body before
 * sending, so a cast doesn't bypass it. Reported upstream.
 */

import type { Config } from "../config.js";
import type { StoredContext } from "./context.js";

function authleteUrl(config: Config, path: string): string {
  return `${config.authleteBaseUrl}/api/${config.authleteServiceId}${path}`;
}

function authHeaders(config: Config) {
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${config.authleteApiToken}`,
  };
}

/** Persist the context on the ticket and return it (for chaining after a record). */
export async function store(
  config: Config,
  id: string,
  ctx: StoredContext,
): Promise<StoredContext> {
  await storeContext(config, id, ctx);
  return ctx;
}

export async function storeContext(
  config: Config,
  ticket: string,
  ctx: StoredContext,
): Promise<void> {
  const res = await fetch(authleteUrl(config, "/auth/authorization/ticket/update"), {
    method: "POST",
    headers: authHeaders(config),
    body: JSON.stringify({ ticket, info: { context: JSON.stringify(ctx) } }),
  });
  if (!res.ok) {
    throw new Error(`Authlete ticket/update failed (${res.status}): ${await res.text()}`);
  }
}

export async function loadContext(config: Config, ticket: string): Promise<StoredContext | null> {
  const res = await fetch(authleteUrl(config, "/auth/authorization/ticket/info"), {
    method: "POST",
    headers: authHeaders(config),
    body: JSON.stringify({ ticket }),
  });
  if (!res.ok) {
    throw new Error(`Authlete ticket/info failed (${res.status}): ${await res.text()}`);
  }
  const payload = (await res.json()) as { action?: string; info?: { context?: string } };
  if (payload.action === "NOT_FOUND") return null;
  const raw = payload.info?.context;
  if (!raw) return null;
  try {
    return JSON.parse(raw) as StoredContext;
  } catch {
    return null;
  }
}
