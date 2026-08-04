import { describe, expect, it } from "vitest";
import { parseJwks, publicJwks, resolveSigningKey } from "../src/interaction/jwks.js";

const ec = (kid: string, alg = "ES256") => ({
  kty: "EC",
  crv: "P-256",
  kid,
  alg,
  x: "x",
  y: "y",
  d: "private-scalar",
});

describe("parseJwks", () => {
  it("parses a valid JWKS", () => {
    const jwks = parseJwks(JSON.stringify({ keys: [ec("k1")] }));
    expect(jwks.keys).toHaveLength(1);
  });

  it("rejects non-JSON, missing keys, and empty keys", () => {
    expect(() => parseJwks("not json")).toThrow(/not JSON/);
    expect(() => parseJwks("{}")).toThrow(/missing 'keys'/);
    expect(() => parseJwks('{"keys":[]}')).toThrow(/empty/);
  });
});

describe("publicJwks", () => {
  it("strips private fields", () => {
    const pub = publicJwks({ keys: [ec("k1")] });
    expect(pub.keys[0]).not.toHaveProperty("d");
    expect(pub.keys[0]).toMatchObject({ kid: "k1", x: "x", y: "y" });
  });
});

describe("resolveSigningKey", () => {
  it("uses the only key when there is exactly one", () => {
    expect(resolveSigningKey({ keys: [ec("solo", "RS256")] }, "ES256").kid).toBe("solo");
  });

  it("prefers the alg match, else falls back to the first key", () => {
    const jwks = { keys: [ec("first", "RS256"), ec("match", "ES256")] };
    expect(resolveSigningKey(jwks, "ES256").kid).toBe("match");
    expect(resolveSigningKey(jwks, "EdDSA").kid).toBe("first");
  });
});
