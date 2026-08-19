/**
 * The interaction transaction context: the projection of Authlete's authorization
 * response the flow needs, the per-interaction outcomes recorded against it, and
 * the shared vocabulary (Interaction, Scope, RAR). Persistence is ticket-store.ts;
 * the two interactions and the orchestration (steps.ts) build on this.
 */

import type { AuthorizationResponse } from "@authlete/typescript-sdk/models/authorizationresponse";
import { Prompt } from "@authlete/typescript-sdk/models/prompt";

export type Interaction = "authenticate" | "consent";

export type Scope = { name: string; description?: string };

export type RarElement = Record<string, unknown>;

/** Outcome of the authenticate interaction (INTERACTION_PROTOCOL.md §2). */
export type AuthOutcome =
  | {
      subject: string;
      acr?: string;
      amr?: string[];
      authenticatedAt?: number;
      /** Actual user claim values (name, email, …) passed to Authlete /issue. */
      userClaims?: Record<string, unknown>;
    }
  | { error: string; errorDescription?: string };

/** Outcome of the consent interaction. */
export type ConsentOutcome =
  { grantedScopes: string[] } | { error: string; errorDescription?: string };

/**
 * Projection of Authlete's authorization response the flow needs — stored on the
 * ticket instead of the full response (whose client + service blob we never read).
 */
export type AuthContext = {
  client: {
    clientId?: number;
    clientIdAlias?: string;
    clientName?: string;
    logoUri?: string;
    policyUri?: string;
    tosUri?: string;
  };
  scopes: Scope[];
  prompts: Prompt[];
  /** RAR elements normalized to plain RFC 9396 (otherFields un-folded) once here. */
  authorizationDetails: RarElement[];
  gmAction?: string;
  acrs?: string[];
  maxAge?: number;
  loginHint?: string;
  uiLocales?: string[];
  /** Resolved once at authenticate time: a trusted first-party client (consent suppressed). */
  firstParty?: boolean;
};

export type StoredContext = {
  v: 1;
  auth: AuthContext;
  authOutcome?: AuthOutcome;
  /** Requested scopes the subject had already granted — unioned in at /issue. */
  already?: string[];
  consentOutcome?: ConsentOutcome;
  /** Consent record PK (two-UI mode) — carried to /token via a hidden property so the minted grant_id links back. */
  consentId?: string;
};

export function toAuthContext(res: AuthorizationResponse): AuthContext {
  const client = res.client ?? {};
  return {
    client: {
      clientId: client.clientId,
      clientIdAlias: client.clientIdAlias,
      clientName: client.clientName,
      logoUri: client.logoUri,
      policyUri: client.policyUri,
      tosUri: client.tosUri,
    },
    scopes: (res.scopes ?? []).map((s) => ({ name: s.name ?? "", description: s.description })),
    prompts: res.prompts ?? [],
    authorizationDetails: normalizeRar((res.authorizationDetails?.elements ?? []) as RarElement[]),
    gmAction: res.gmAction,
    acrs: res.acrs,
    maxAge: res.maxAge,
    loginHint: res.loginHint,
    uiLocales: res.uiLocales,
  };
}

/** Un-fold Authlete's stringified `otherFields` back into plain RFC 9396 elements. */
function normalizeRar(elements: RarElement[]): RarElement[] {
  return elements.map((el) => {
    const { otherFields, ...rest } = el;
    if (typeof otherFields !== "string") return rest;
    try {
      return { ...rest, ...(JSON.parse(otherFields) as Record<string, unknown>) };
    } catch {
      return rest;
    }
  });
}
