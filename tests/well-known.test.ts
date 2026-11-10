import { describe, expect, it } from "vitest";
import { wellKnownRoutes } from "../src/routes/well-known.js";
import type { Config } from "../src/config.js";

// TEMPORARY (authlete-java-common#178): covers the PROTECTED_RESOURCES workaround.
const baseConfig = { authleteServiceId: "svc" } as Config;

function routesWith(protectedResources: string[]) {
  const authlete = {
    service: {
      getConfiguration: async () => ({ issuer: "https://as.example" }),
    },
  } as never;
  return wellKnownRoutes({ authlete, config: { ...baseConfig, protectedResources } });
}

describe("well-known protected_resources", () => {
  it("merges PROTECTED_RESOURCES into the metadata when set", async () => {
    const app = routesWith(["https://rs.example", "https://api.example"]);
    const res = await app.request("/.well-known/oauth-authorization-server");
    const body = await res.json();
    expect(body.protected_resources).toEqual(["https://rs.example", "https://api.example"]);
  });

  it("omits protected_resources when the list is empty", async () => {
    const app = routesWith([]);
    const res = await app.request("/.well-known/oauth-authorization-server");
    const body = await res.json();
    expect(body).not.toHaveProperty("protected_resources");
  });
});
