import { describe, expect, it } from "vitest";
import { extractBearer, parseBasicAuth } from "../src/http.js";

describe("extractBearer", () => {
  it("extracts the token from a Bearer header", () => {
    expect(extractBearer("Bearer abc.def.ghi")).toBe("abc.def.ghi");
    expect(extractBearer("bearer abc")).toBe("abc");
  });

  it("returns undefined for missing or non-Bearer headers", () => {
    expect(extractBearer(undefined)).toBeUndefined();
    expect(extractBearer("Basic dXNlcjpwYXNz")).toBeUndefined();
    expect(extractBearer("Bearer ")).toBeUndefined();
  });
});

describe("parseBasicAuth", () => {
  it("decodes client id and secret", () => {
    const header = `Basic ${Buffer.from("client:s3cret").toString("base64")}`;
    expect(parseBasicAuth(header)).toEqual({ clientId: "client", clientSecret: "s3cret" });
  });

  it("keeps colons in the secret", () => {
    const header = `Basic ${Buffer.from("client:a:b:c").toString("base64")}`;
    expect(parseBasicAuth(header)).toEqual({ clientId: "client", clientSecret: "a:b:c" });
  });

  it("returns empty object on malformed input", () => {
    expect(parseBasicAuth(undefined)).toEqual({});
    expect(parseBasicAuth("Bearer abc")).toEqual({});
    expect(parseBasicAuth(`Basic ${Buffer.from("no-colon").toString("base64")}`)).toEqual({});
  });
});
