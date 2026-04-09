import { describe, it, expect } from "vitest";
import {
  AdapterRegistry,
  AdapterRegistrationError,
  NoOpOAuthEngineAdapter,
  NoOpFoundryAdapter,
  createDefaultRegistry,
} from "../adapters.js";
import type { OAuthEngineAdapter, FoundryAdapter } from "../adapters.js";

describe("AdapterRegistry", () => {
  it("registers adapters from trusted namespaces", async () => {
    const registry = new AdapterRegistry();
    const adapter = new NoOpOAuthEngineAdapter();
    await registry.register(adapter);

    const retrieved = registry.getOAuthEngine("noop-oauth");
    expect(retrieved).toBeDefined();
    expect(retrieved?.name).toBe("noop-oauth");
  });

  it("rejects adapters from untrusted namespaces", async () => {
    const registry = new AdapterRegistry();
    const adapter: OAuthEngineAdapter = {
      adapterType: "A",
      name: "evil-adapter",
      packageNamespace: "@evil/hacks",
      async issueToken() { return ""; },
      async introspectToken() { return { active: false }; },
      async revokeToken() {},
      async getJWKS() { return {}; },
    };

    await expect(registry.register(adapter)).rejects.toThrow(AdapterRegistrationError);
  });

  it("prevents duplicate registration", async () => {
    const registry = new AdapterRegistry();
    const adapter = new NoOpOAuthEngineAdapter();
    await registry.register(adapter);

    await expect(registry.register(adapter)).rejects.toThrow(AdapterRegistrationError);
  });

  it("lists registered adapters", async () => {
    const registry = new AdapterRegistry();
    await registry.register(new NoOpOAuthEngineAdapter());
    await registry.register(new NoOpFoundryAdapter());

    const list = registry.list();
    expect(list).toHaveLength(2);
    expect(list.map((a) => a.name)).toContain("noop-oauth");
    expect(list.map((a) => a.name)).toContain("noop-foundry");
  });

  it("unregisters adapters", async () => {
    const registry = new AdapterRegistry();
    await registry.register(new NoOpOAuthEngineAdapter());

    expect(registry.unregister("A", "noop-oauth")).toBe(true);
    expect(registry.getOAuthEngine("noop-oauth")).toBeUndefined();
    expect(registry.unregister("A", "noop-oauth")).toBe(false);
  });

  it("supports custom trusted namespaces", async () => {
    const registry = new AdapterRegistry({ trustedNamespaces: ["@custom/"] });
    const adapter: OAuthEngineAdapter = {
      adapterType: "A",
      name: "custom-adapter",
      packageNamespace: "@custom/oauth",
      async issueToken() { return ""; },
      async introspectToken() { return { active: false }; },
      async revokeToken() {},
      async getJWKS() { return {}; },
    };

    await registry.register(adapter);
    expect(registry.getOAuthEngine("custom-adapter")).toBeDefined();
  });

  it("enforces signature requirement when configured", async () => {
    const registry = new AdapterRegistry({
      requireSignature: true,
      signatureVerifier: async () => false,
    });
    const adapter = new NoOpOAuthEngineAdapter();

    await expect(registry.register(adapter, "bad-sig")).rejects.toThrow("signature verification failed");
  });

  it("rejects missing signature when required", async () => {
    const registry = new AdapterRegistry({ requireSignature: true });
    const adapter = new NoOpOAuthEngineAdapter();

    await expect(registry.register(adapter)).rejects.toThrow("requires a cryptographic signature");
  });
});

describe("NoOpOAuthEngineAdapter", () => {
  it("throws on issueToken", async () => {
    const adapter = new NoOpOAuthEngineAdapter();
    await expect(adapter.issueToken({} as any, {})).rejects.toThrow("not implemented");
  });

  it("returns inactive on introspect", async () => {
    const adapter = new NoOpOAuthEngineAdapter();
    const result = await adapter.introspectToken("any-token");
    expect(result.active).toBe(false);
  });

  it("returns empty JWKS", async () => {
    const adapter = new NoOpOAuthEngineAdapter();
    const jwks = await adapter.getJWKS();
    expect(jwks).toEqual({ keys: [] });
  });
});

describe("NoOpFoundryAdapter", () => {
  it("returns failure on executeAction", async () => {
    const adapter = new NoOpFoundryAdapter();
    const result = await adapter.executeAction("test", "resource", {});
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("returns invalid environment", async () => {
    const adapter = new NoOpFoundryAdapter();
    const result = await adapter.validateEnvironment();
    expect(result.valid).toBe(false);
    expect(result.capabilities).toEqual([]);
  });
});

describe("createDefaultRegistry", () => {
  it("returns an empty registry with default trusted namespaces", () => {
    const registry = createDefaultRegistry();
    expect(registry.list()).toHaveLength(0);
  });
});
