import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { dpopNonceHeader, dpopParams, extractDpopToken, sendAuthleteAction } from "../src/http.js";

describe("extractDpopToken", () => {
  it("extracts a DPoP-bound access token (RFC 9449 §7.1)", () => {
    expect(extractDpopToken("DPoP abc.def.ghi")).toBe("abc.def.ghi");
    expect(extractDpopToken("dpop abc")).toBe("abc");
  });

  it("returns undefined for missing, Bearer, or empty headers", () => {
    expect(extractDpopToken(undefined)).toBeUndefined();
    expect(extractDpopToken("Bearer abc")).toBeUndefined();
    expect(extractDpopToken("DPoP ")).toBeUndefined();
  });
});

describe("dpopNonceHeader", () => {
  it("emits DPoP-Nonce only when Authlete supplies a nonce", () => {
    expect(dpopNonceHeader({ dpopNonce: "n0nce" })).toEqual({ "DPoP-Nonce": "n0nce" });
    expect(dpopNonceHeader({})).toEqual({});
    expect(dpopNonceHeader({ dpopNonce: undefined })).toEqual({});
  });
});

describe("dpopParams", () => {
  const app = new Hono().all("/e", (c) => c.json(dpopParams(c)));

  it("forwards the DPoP header and HTTP method, omitting htu", async () => {
    const res = await app.request("/e", {
      method: "POST",
      headers: { DPoP: "proof.jwt.sig" },
    });
    expect(await res.json()).toEqual({ dpop: "proof.jwt.sig", htm: "POST" });
  });

  it("reports the method even without a DPoP header", async () => {
    const res = await app.request("/e", { method: "GET" });
    // htu is intentionally absent; htm reflects the real request method.
    expect(await res.json()).toEqual({ htm: "GET" });
  });
});

describe("sendAuthleteAction DPoP-Nonce echo", () => {
  it("adds DPoP-Nonce when the Authlete response carries one", async () => {
    const app = new Hono().get("/t", (c) =>
      sendAuthleteAction(
        c,
        { action: "OK", responseContent: "{}", dpopNonce: "abc123" },
        { OK: 200 },
      ),
    );
    const res = await app.request("/t");
    expect(res.status).toBe(200);
    expect(res.headers.get("DPoP-Nonce")).toBe("abc123");
  });

  it("omits DPoP-Nonce when the Authlete response has none", async () => {
    const app = new Hono().get("/t", (c) =>
      sendAuthleteAction(c, { action: "OK", responseContent: "{}" }, { OK: 200 }),
    );
    const res = await app.request("/t");
    expect(res.headers.get("DPoP-Nonce")).toBeNull();
  });
});
