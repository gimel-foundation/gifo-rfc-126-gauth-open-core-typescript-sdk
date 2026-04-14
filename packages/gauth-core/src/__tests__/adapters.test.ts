import { describe, it, expect } from "vitest";
import {
  AdapterRegistry,
  AdapterRegistrationError,
  ConnectorSlotRegistry,
  NoOpPolicyDecisionAdapter,
  NoOpOAuthEngineAdapter,
  NoOpFoundryAdapter,
  NoOpWalletAdapter,
  NoOpGovernanceAdapter,
  NoOpWeb3IdentityAdapter,
  NoOpDNAIdentityAdapter,
  NoOpBillingAdapter,
  createDefaultRegistry,
  computeS2SHeaders,
  verifyS2SSignature,
} from "../adapters.js";
import type { OAuthEngineAdapter } from "../adapters.js";
import { CONNECTOR_SLOT_CONFIGS, DEPLOYMENT_POLICY_MATRIX, DEFAULT_CUSTOMER_LICENSE_STATE, tariffEffectiveLevel } from "../types.js";

const TEST_ED25519_PUBLIC_KEY = "302a300506032b6570032100e518032d136e2cdeb080a76f68b8253e0664e48cf958e3ce476dc52f9c2ace5b";
const VALID_SIG_NOOP_GOV = "0e80f5018ac58f076b2e65a1fd8d8e090364b671286935639e774ff2a0564140fbc688b13861877f53ae499531c2e46d5aff343b271a53ca288028145688ff0f";
const VALID_SIG_REAL_GOV = "2acef38764c89cec68d4c9acbd1913704a7103cf75eaac66510faff846eedb71caca024818dbff627364fa77d628b5e1eb61254908349d17d71e0fafd24bb30f";
const VALID_SIG_REAL_AI_GOV = "92e5c4ae0472fcfdfd4fd0184509954fcb63c41843c80eff20e5686074c3eb603c241076825651aac5261fd026c88da4d8e5aba86e25952875e99bdc45de090f";

const GIMEL_TRUST_KEYS = [{ public_key_hex: TEST_ED25519_PUBLIC_KEY, issuer: "gimel-foundation" }];

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
    const adapter = {
      adapterType: "A" as const,
      name: "evil-adapter",
      packageNamespace: "@evil/hacks",
      async issueToken() { return { token: "", expiresAt: "" }; },
      async validateToken() { return { valid: false }; },
      async revokeToken(id: string) { return { revoked: false, tokenId: id }; },
      async getJWKS() { return { keys: [] }; },
      async introspect() { return { active: false }; },
      async beforeTokenIssuance() { return {}; },
      async afterTokenIssuance() {},
      async healthCheck() { return { healthy: false, latencyMs: 0 }; },
    } satisfies OAuthEngineAdapter;

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
    const adapter = {
      adapterType: "A" as const,
      name: "custom-adapter",
      packageNamespace: "@custom/oauth",
      async issueToken() { return { token: "", expiresAt: "" }; },
      async validateToken() { return { valid: false }; },
      async revokeToken(id: string) { return { revoked: false, tokenId: id }; },
      async getJWKS() { return { keys: [] }; },
      async introspect() { return { active: false }; },
      async beforeTokenIssuance() { return {}; },
      async afterTokenIssuance() {},
      async healthCheck() { return { healthy: false, latencyMs: 0 }; },
    } satisfies OAuthEngineAdapter;

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

  it("retrieves wallet adapters", async () => {
    const registry = new AdapterRegistry();
    const wallet = new NoOpWalletAdapter();
    await registry.register(wallet);
    expect(registry.getWallet("noop-wallet")).toBeDefined();
  });
});

describe("ConnectorSlotRegistry", () => {
  it("initializes all 7 slots as null", () => {
    const reg = new ConnectorSlotRegistry("O");
    const statuses = reg.getAllSlotStatuses();
    expect(statuses).toHaveLength(7);
    for (const s of statuses) {
      expect(s.status).toBe("null");
      expect(s.implementationLabel).toBe("None");
    }
  });

  it("registers Type A adapter to active immediately", () => {
    const reg = new ConnectorSlotRegistry("M");
    const adapter = new NoOpOAuthEngineAdapter();
    const result = reg.register("oauth_engine", adapter, "Ory Hydra");
    expect(result.success).toBe(true);
    const status = reg.getSlotStatus("oauth_engine");
    expect(status.status).toBe("active");
    expect(status.implementationLabel).toBe("Ory Hydra");
  });

  it("registers Type B adapter to active immediately", () => {
    const reg = new ConnectorSlotRegistry("S");
    const adapter = new NoOpFoundryAdapter();
    const result = reg.register("foundry", adapter, "Gimel Foundry");
    expect(result.success).toBe(true);
    expect(reg.getSlotStatus("foundry").status).toBe("active");
  });

  it("registers NoOp Type C adapter as active immediately", () => {
    const reg = new ConnectorSlotRegistry("M");
    const adapter = new NoOpGovernanceAdapter();
    const result = reg.register("ai_governance", adapter, "G-Agent Governance");
    expect(result.success).toBe(true);
    expect(reg.getSlotStatus("ai_governance").status).toBe("active");
  });

  it("transitions non-NoOp Type C from pending to active on attestation", () => {
    const reg = new ConnectorSlotRegistry("M", GIMEL_TRUST_KEYS);
    const realAdapter = { name: "real-governance", __gauthNoOp: false as const, packageNamespace: "@gimel/gov" } as unknown as import("../adapters.js").GAuthAdapter;
    reg.register("ai_governance", realAdapter, "Real-Gov");
    expect(reg.getSlotStatus("ai_governance").status).toBe("pending");

    const validManifest = {
      manifest_version: "1.0" as const,
      adapter_name: "real-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/gov",
      issued_at: "2025-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: TEST_ED25519_PUBLIC_KEY,
      signature: VALID_SIG_REAL_GOV,
    };
    const attest = reg.satisfyAttestation("ai_governance", validManifest);
    expect(attest.success).toBe(true);
    expect(reg.getSlotStatus("ai_governance").status).toBe("active");
  });

  it("rejects attestation on non-Type-C slot", () => {
    const reg = new ConnectorSlotRegistry("M");
    const result = reg.satisfyAttestation("foundry");
    expect(result.success).toBe(false);
    expect(result.error).toContain("does not require attestation");
  });

  it("rejects unregistering mandatory slots", () => {
    const reg = new ConnectorSlotRegistry("O");
    const result = reg.unregister("pdp");
    expect(result.success).toBe(false);
    expect(result.error).toContain("mandatory");
  });

  it("unregisters optional slots and resets state", () => {
    const reg = new ConnectorSlotRegistry("S");
    reg.register("foundry", new NoOpFoundryAdapter(), "Gimel Foundry");
    expect(reg.getSlotStatus("foundry").status).toBe("active");

    const result = reg.unregister("foundry");
    expect(result.success).toBe(true);
    const status = reg.getSlotStatus("foundry");
    expect(status.status).toBe("null");
    expect(status.implementationLabel).toBe("None");
  });

  it("records license acceptance", () => {
    const reg = new ConnectorSlotRegistry("M");
    const result = reg.acceptLicense("ai_governance", "2026.1");
    expect(result.success).toBe(true);
    const status = reg.getSlotStatus("ai_governance");
    expect(status.licenseType).toBe("gimel_tos");
    expect(status.licenseVersion).toBe("2026.1");
  });
});

describe("Tariff Gating", () => {
  it("blocks Type C for tariff O", () => {
    const reg = new ConnectorSlotRegistry("O");
    const result = reg.checkTariffGate("ai_governance");
    expect(result.allowed).toBe(false);
    expect(result.availability).toBe("null");
  });

  it("blocks Type C for tariff S", () => {
    const reg = new ConnectorSlotRegistry("S");
    const result = reg.checkTariffGate("ai_governance");
    expect(result.allowed).toBe(false);
    expect(result.availability).toBe("null");
  });

  it("allows Type C for tariff M (after attestation)", () => {
    const reg = new ConnectorSlotRegistry("M");
    const gate = reg.checkTariffGate("ai_governance");
    expect(gate.availability).toBe("attested_gimel");

    reg.satisfyAttestation("ai_governance");
    const gateAfter = reg.checkTariffGate("ai_governance");
    expect(gateAfter.allowed).toBe(true);
  });

  it("blocks dna_identity for tariff M (requires L)", () => {
    const reg = new ConnectorSlotRegistry("M");
    const result = reg.checkTariffGate("dna_identity");
    expect(result.allowed).toBe(false);
    expect(result.availability).toBe("null");
  });

  it("allows dna_identity for tariff L", () => {
    const reg = new ConnectorSlotRegistry("L");
    const gate = reg.checkTariffGate("dna_identity");
    expect(gate.availability).toBe("attested_gimel");
  });

  it("allows user-provided OAuth engine for tariff O", () => {
    const reg = new ConnectorSlotRegistry("O");
    const gate = reg.checkTariffGate("oauth_engine");
    expect(gate.allowed).toBe(true);
    expect(gate.provenance).toBe("user_must_provide");
  });

  it("allows PDP for all tariffs", () => {
    for (const tariff of ["O", "S", "M", "L"] as const) {
      const reg = new ConnectorSlotRegistry(tariff);
      const gate = reg.checkTariffGate("pdp");
      expect(gate.allowed).toBe(true);
      expect(gate.provenance).toBe("gimel_managed");
    }
  });

  it("web3_identity is null_or_attested_gimel for tariff M", () => {
    const reg = new ConnectorSlotRegistry("M");
    const gate = reg.checkTariffGate("web3_identity");
    expect(gate.allowed).toBe(true);
    expect(gate.provenance).toBe("null_fallback_until_attested");
  });
});

describe("Connector Slot Configs", () => {
  it("has all 7 slots defined", () => {
    const names = Object.keys(CONNECTOR_SLOT_CONFIGS);
    expect(names).toHaveLength(7);
    expect(names).toContain("pdp");
    expect(names).toContain("ai_governance");
    expect(names).toContain("dna_identity");
  });

  it("marks pdp and oauth_engine as mandatory", () => {
    expect(CONNECTOR_SLOT_CONFIGS.pdp.mandatory).toBe(true);
    expect(CONNECTOR_SLOT_CONFIGS.oauth_engine.mandatory).toBe(true);
    expect(CONNECTOR_SLOT_CONFIGS.foundry.mandatory).toBe(false);
  });

  it("marks Type C slots as requiring attestation", () => {
    expect(CONNECTOR_SLOT_CONFIGS.ai_governance.attestationRequired).toBe(true);
    expect(CONNECTOR_SLOT_CONFIGS.web3_identity.attestationRequired).toBe(true);
    expect(CONNECTOR_SLOT_CONFIGS.dna_identity.attestationRequired).toBe(true);
    expect(CONNECTOR_SLOT_CONFIGS.foundry.attestationRequired).toBe(false);
  });
});

describe("Deployment Policy Matrix", () => {
  it("has entries for all slot × tariff combinations", () => {
    const slotNames = Object.keys(CONNECTOR_SLOT_CONFIGS);
    for (const slot of slotNames) {
      const entry = DEPLOYMENT_POLICY_MATRIX[slot as keyof typeof DEPLOYMENT_POLICY_MATRIX];
      expect(entry).toBeDefined();
      expect(entry.O).toBeDefined();
      expect(entry.S).toBeDefined();
      expect(entry.M).toBeDefined();
      expect(entry.L).toBeDefined();
    }
  });

  it("blocks ai_governance for O and S", () => {
    expect(DEPLOYMENT_POLICY_MATRIX.ai_governance.O).toBe("null");
    expect(DEPLOYMENT_POLICY_MATRIX.ai_governance.S).toBe("null");
    expect(DEPLOYMENT_POLICY_MATRIX.ai_governance.M).toBe("attested_gimel");
  });
});

describe("License State", () => {
  it("defaults to mpl_2_0", () => {
    expect(DEFAULT_CUSTOMER_LICENSE_STATE.license_type).toBe("mpl_2_0");
    expect(DEFAULT_CUSTOMER_LICENSE_STATE.license_accepted_at).toBeNull();
  });
});

describe("NoOp Adapters", () => {
  it("NoOpPolicyDecisionAdapter always permits", async () => {
    const adapter = new NoOpPolicyDecisionAdapter();
    expect(adapter.adapterType).toBe("Internal");
    const result = await adapter.evaluateMandate({} as any, {} as any);
    expect(result.allowed).toBe(true);
    const health = await adapter.healthCheck();
    expect(health.healthy).toBe(true);
  });

  it("NoOpOAuthEngineAdapter throws on issueToken", async () => {
    const adapter = new NoOpOAuthEngineAdapter();
    await expect(adapter.issueToken({}, {})).rejects.toThrow("not implemented");
  });

  it("NoOpOAuthEngineAdapter returns inactive on introspect", async () => {
    const adapter = new NoOpOAuthEngineAdapter();
    const result = await adapter.introspect("any-token");
    expect(result.active).toBe(false);
  });

  it("NoOpOAuthEngineAdapter returns empty JWKS", async () => {
    const adapter = new NoOpOAuthEngineAdapter();
    const jwks = await adapter.getJWKS();
    expect(jwks).toEqual({ keys: [] });
  });

  it("NoOpOAuthEngineAdapter has healthCheck", async () => {
    const adapter = new NoOpOAuthEngineAdapter();
    const health = await adapter.healthCheck();
    expect(health.healthy).toBe(false);
  });

  it("NoOpFoundryAdapter returns failure on executeAction", async () => {
    const adapter = new NoOpFoundryAdapter();
    const result = await adapter.executeAction({} as any, {} as any);
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("NoOpFoundryAdapter returns empty catalog", async () => {
    const adapter = new NoOpFoundryAdapter();
    const catalog = await adapter.getAgentCatalog();
    expect(catalog).toEqual([]);
  });

  it("NoOpFoundryAdapter has healthCheck", async () => {
    const adapter = new NoOpFoundryAdapter();
    const health = await adapter.healthCheck();
    expect(health.healthy).toBe(false);
  });

  it("NoOpWalletAdapter throws on storeCredential (fail-closed)", async () => {
    const adapter = new NoOpWalletAdapter();
    expect(adapter.adapterType).toBe("B");
    await expect(adapter.storeCredential({})).rejects.toThrow("not connected");
  });

  it("NoOpWalletAdapter returns empty array on listCredentials", async () => {
    const adapter = new NoOpWalletAdapter();
    const creds = await adapter.listCredentials();
    expect(creds).toEqual([]);
  });

  it("NoOpGovernanceAdapter returns rule-based-only fallback", async () => {
    const adapter = new NoOpGovernanceAdapter();
    expect(adapter.adapterType).toBe("C");
    const result = await adapter.checkAccess({} as any);
    expect(result.allowed).toBe(true);
    expect(result.reason).toContain("rule-based");
  });

  it("NoOpWeb3IdentityAdapter resolves to null", async () => {
    const adapter = new NoOpWeb3IdentityAdapter();
    expect(adapter.adapterType).toBe("C");
    const result = await adapter.resolveIdentity("did:example:123");
    expect(result).toBeNull();
  });

  it("NoOpDNAIdentityAdapter resolves to null", async () => {
    const adapter = new NoOpDNAIdentityAdapter();
    expect(adapter.adapterType).toBe("C");
    const result = await adapter.resolveIdentity("dna:sample:456");
    expect(result).toBeNull();
  });

  it("NoOpBillingAdapter allows all credits (inactive)", async () => {
    const adapter = new NoOpBillingAdapter();
    expect(adapter.adapterType).toBe("D");
    const result = await adapter.checkCredits("org-1", "operation");
    expect(result.allowed).toBe(true);
    const health = await adapter.healthCheck();
    expect(health.healthy).toBe(true);
  });
});

describe("S2S Authentication", () => {
  it("computes and verifies HMAC-SHA256 signatures", () => {
    const body = { action: "test", data: "payload" };
    const platformKey = "test-platform-key";
    const secret = "test-webhook-secret";

    const headers = computeS2SHeaders(body, platformKey, secret);
    expect(headers["X-GAuth-Platform-Key"]).toBe(platformKey);
    expect(headers["X-GAuth-HMAC-Signature"]).toMatch(/^sha256=[a-f0-9]+$/);

    const valid = verifyS2SSignature(body, headers["X-GAuth-HMAC-Signature"], secret);
    expect(valid).toBe(true);
  });

  it("rejects tampered payload", () => {
    const body = { action: "test" };
    const secret = "secret";
    const headers = computeS2SHeaders(body, "key", secret);

    const valid = verifyS2SSignature({ action: "tampered" }, headers["X-GAuth-HMAC-Signature"], secret);
    expect(valid).toBe(false);
  });

  it("rejects wrong secret", () => {
    const body = { action: "test" };
    const headers = computeS2SHeaders(body, "key", "correct-secret");

    const valid = verifyS2SSignature(body, headers["X-GAuth-HMAC-Signature"], "wrong-secret");
    expect(valid).toBe(false);
  });
});

describe("createDefaultRegistry", () => {
  it("returns an empty registry with default trusted namespaces", () => {
    const registry = createDefaultRegistry();
    expect(registry.list()).toHaveLength(0);
  });
});

describe("CT-TM: Tariff hybrid codes", () => {
  it("CT-TM-001: M+O hybrid resolves to effective level M", () => {
    expect(tariffEffectiveLevel("M+O")).toBe("M");
  });

  it("CT-TM-002: L+O hybrid resolves to effective level L", () => {
    expect(tariffEffectiveLevel("L+O")).toBe("L");
  });

  it("CT-TM-003: base codes resolve to themselves", () => {
    expect(tariffEffectiveLevel("O")).toBe("O");
    expect(tariffEffectiveLevel("S")).toBe("S");
    expect(tariffEffectiveLevel("M")).toBe("M");
    expect(tariffEffectiveLevel("L")).toBe("L");
  });

  it("CT-TM-004: ConnectorSlotRegistry at M+O resolves ai_governance same as M", () => {
    const registryMO = new ConnectorSlotRegistry("M+O" as import("../types.js").TariffCode);
    const registryM = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const gateMO = registryMO.checkTariffGate("ai_governance");
    const gateM = registryM.checkTariffGate("ai_governance");
    expect(gateMO.availability).toBe(gateM.availability);
  });

  it("CT-TM-005: ConnectorSlotRegistry at L+O resolves dna_identity same as L", () => {
    const registryLO = new ConnectorSlotRegistry("L+O" as import("../types.js").TariffCode);
    const registryL = new ConnectorSlotRegistry("L" as import("../types.js").TariffCode);
    const gateLO = registryLO.checkTariffGate("dna_identity");
    const gateL = registryL.checkTariffGate("dna_identity");
    expect(gateLO.availability).toBe(gateL.availability);
  });
});

describe("CT-REG: Manifest verification and namespace enforcement", () => {
  it("CT-REG-019: rejects Type C adapter with non-@gimel/ namespace", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const badAdapter = {
      adapterType: "C" as const,
      name: "bad-governance",
      packageNamespace: "@evil/governance",
      async checkAccess() { return { allowed: true, reason: "" }; },
      async getRecommendations() { return []; },
      async healthCheck() { return { healthy: true, latencyMs: 0 }; },
    };
    const result = registry.register("ai_governance", badAdapter, "bad-gov-v1");
    expect(result.success).toBe(false);
    expect(result.error).toContain("@gimel/");
  });

  it("CT-REG-020: accepts Type C adapter with @gimel/ namespace", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const goodAdapter = new NoOpGovernanceAdapter();
    const result = registry.register("ai_governance", goodAdapter, "noop-gov-v1");
    expect(result.success).toBe(true);
  });

  it("CT-REG-021: manifest verification rejects expired manifest", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const goodAdapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", goodAdapter, "noop-gov-v1");

    const expiredManifest = {
      manifest_version: "1.0" as const,
      adapter_name: "test-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/ai-governance",
      issued_at: "2020-01-01T00:00:00Z",
      expires_at: "2021-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: "test-key",
      signature: "a".repeat(128),
    };

    const result = registry.satisfyAttestation("ai_governance", expiredManifest);
    expect(result.success).toBe(false);
    expect(result.error).toContain("expired");
  });

  it("CT-REG-022: manifest verification rejects non-@gimel/ namespace in manifest", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", adapter, "noop-gov-v1");

    const badManifest = {
      manifest_version: "1.0" as const,
      adapter_name: "test-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@evil/governance",
      issued_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() + 86400000).toISOString(),
      issuer: "gimel-foundation" as const,
      public_key: "test-key",
      signature: "a".repeat(128),
    };

    const result = registry.satisfyAttestation("ai_governance", badManifest);
    expect(result.success).toBe(false);
    expect(result.error).toContain("@gimel/");
  });

  it("CT-REG-023: manifest verification rejects wrong slot_name", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", adapter, "noop-gov-v1");

    const wrongSlotManifest = {
      manifest_version: "1.0" as const,
      adapter_name: "test-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "web3_identity" as const,
      namespace: "@gimel/ai-governance",
      issued_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() + 86400000).toISOString(),
      issuer: "gimel-foundation" as const,
      public_key: "test-key",
      signature: "a".repeat(128),
    };

    const result = registry.satisfyAttestation("ai_governance", wrongSlotManifest);
    expect(result.success).toBe(false);
    expect(result.error).toContain("slot_name");
  });

  it("CT-REG-024: register() with invalid manifest rejects non-NoOp Type C adapter", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const realAdapter = { name: "real-governance", packageNamespace: "@gimel/gov" } as unknown as import("../adapters.js").GAuthAdapter;

    const badManifest = {
      manifest_version: "1.0" as const,
      adapter_name: "real-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/gov",
      issued_at: "2025-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: TEST_ED25519_PUBLIC_KEY,
      signature: "00".repeat(64),
    };

    const result = registry.register("ai_governance", realAdapter, "real-gov-v1", badManifest);
    expect(result.success).toBe(false);
    expect(result.error).toContain("signature");
  });

  it("CT-REG-024a: two-step register+attestation activates non-NoOp Type C adapter", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const realAdapter = { name: "real-governance", packageNamespace: "@gimel/gov" } as unknown as import("../adapters.js").GAuthAdapter;
    registry.register("ai_governance", realAdapter, "real-gov-v1");
    expect(registry.getSlotStatus("ai_governance").status).toBe("pending");

    const validManifest = {
      manifest_version: "1.0" as const,
      adapter_name: "real-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/gov",
      issued_at: "2025-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: TEST_ED25519_PUBLIC_KEY,
      signature: VALID_SIG_REAL_GOV,
    };
    const attest = registry.satisfyAttestation("ai_governance", validManifest);
    expect(attest.success).toBe(true);
    expect(registry.getSlotStatus("ai_governance").status).toBe("active");
  });

  it("CT-REG-024b: NoOp Type C adapter activates immediately on register without manifest", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = new NoOpGovernanceAdapter();
    const result = registry.register("ai_governance", adapter, "noop-gov-v1");
    expect(result.success).toBe(true);
    expect(registry.getSlotStatus("ai_governance").status).toBe("active");
  });

  it("CT-REG-024c: non-NoOp Type C adapter without manifest stays pending", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const realAdapter = { name: "real-governance", packageNamespace: "@gimel/gov" } as unknown as import("../adapters.js").GAuthAdapter;
    const result = registry.register("ai_governance", realAdapter, "real-gov-v1");
    expect(result.success).toBe(true);
    expect(registry.getSlotStatus("ai_governance").status).toBe("pending");
  });
});

describe("CT-REG: Tariff downgrade re-evaluation", () => {
  it("CT-REG-025: setTariff downgrades and deactivates non-compliant adapters", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", adapter, "gov-v1");
    registry.satisfyAttestation("ai_governance");

    expect(registry.getSlotStatus("ai_governance").status).toBe("active");

    const result = registry.setTariff("S" as import("../types.js").TariffCode);
    expect(result.deactivated).toContain("ai_governance");
    expect(registry.getSlotStatus("ai_governance").status).toBe("null");
  });

  it("CT-REG-026: setTariff upgrade does not deactivate adapters", () => {
    const registry = new ConnectorSlotRegistry("S" as import("../types.js").TariffCode);
    const adapter = new NoOpOAuthEngineAdapter();
    registry.register("oauth_engine", adapter, "oauth-v1");

    expect(registry.getSlotStatus("oauth_engine").status).toBe("active");

    const result = registry.setTariff("M" as import("../types.js").TariffCode);
    expect(result.deactivated).toHaveLength(0);
    expect(registry.getSlotStatus("oauth_engine").status).toBe("active");
  });

  it("CT-REG-027: tariff downgrade logs compliance audit entries", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", adapter, "gov-v1");
    registry.satisfyAttestation("ai_governance");
    registry.setTariff("O" as import("../types.js").TariffCode);

    const log = registry.getComplianceLog();
    expect(log.length).toBeGreaterThanOrEqual(2);
    expect(log.some(e => e.event_type === "TARIFF_DOWNGRADE")).toBe(true);
    expect(log.some(e => e.event_type === "ADAPTER_DEACTIVATED")).toBe(true);
  });
});

describe("CT-REG: Ed25519 signature verification", () => {
  it("CT-REG-031: rejects manifest with invalid Ed25519 signature", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", adapter, "noop-gov-v1");

    const tamperedManifest = {
      manifest_version: "1.0" as const,
      adapter_name: "noop-ai-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/ai-governance",
      issued_at: "2025-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: TEST_ED25519_PUBLIC_KEY,
      signature: "ff".repeat(64),
    };

    const result = registry.satisfyAttestation("ai_governance", tamperedManifest);
    expect(result.success).toBe(false);
    expect(result.error).toContain("Ed25519 signature verification failed");
  });

  it("CT-REG-032: rejects manifest with tampered payload (sig mismatch)", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", adapter, "noop-gov-v1");

    const tamperedManifest = {
      manifest_version: "1.0" as const,
      adapter_name: "tampered-name",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/ai-governance",
      issued_at: "2025-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: TEST_ED25519_PUBLIC_KEY,
      signature: VALID_SIG_NOOP_GOV,
    };

    const result = registry.satisfyAttestation("ai_governance", tamperedManifest);
    expect(result.success).toBe(false);
    expect(result.error).toContain("Ed25519 signature verification failed");
  });
});

describe("CT-REG: Non-NoOp Type C attestation requires manifest", () => {
  it("CT-REG-028: non-NoOp Type C adapter cannot satisfy attestation without manifest", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const realAdapter = {
      adapterType: "C" as const,
      name: "real-ai-governance",
      packageNamespace: "@gimel/ai-governance",
      async checkAccess() { return { allowed: true, reason: "" }; },
      async getRecommendations() { return []; },
      async healthCheck() { return { healthy: true, latencyMs: 0 }; },
    };
    registry.register("ai_governance", realAdapter, "real-gov-v1");
    const result = registry.satisfyAttestation("ai_governance");
    expect(result.success).toBe(false);
    expect(result.error).toContain("SealedAdapterManifest is required");
  });

  it("CT-REG-033: name-spoofed noop- adapter still requires manifest", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const spoofedAdapter = {
      adapterType: "C" as const,
      name: "noop-spoofed-governance",
      packageNamespace: "@gimel/ai-governance",
      async checkAccess() { return { allowed: true, reason: "" }; },
      async getRecommendations() { return []; },
      async healthCheck() { return { healthy: true, latencyMs: 0 }; },
    };
    registry.register("ai_governance", spoofedAdapter, "spoofed-v1");
    const result = registry.satisfyAttestation("ai_governance");
    expect(result.success).toBe(false);
    expect(result.error).toContain("SealedAdapterManifest is required");
  });

  it("CT-REG-029: NoOp Type C adapter can satisfy attestation without manifest", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", adapter, "noop-gov-v1");
    const result = registry.satisfyAttestation("ai_governance");
    expect(result.success).toBe(true);
  });

  it("CT-REG-030: non-NoOp Type C adapter succeeds attestation with valid manifest", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const realAdapter = {
      adapterType: "C" as const,
      name: "real-ai-governance",
      packageNamespace: "@gimel/ai-governance",
      async checkAccess() { return { allowed: true, reason: "" }; },
      async getRecommendations() { return []; },
      async healthCheck() { return { healthy: true, latencyMs: 0 }; },
    };
    registry.register("ai_governance", realAdapter, "real-gov-v1");
    const validManifest = {
      manifest_version: "1.0" as const,
      adapter_name: "real-ai-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/ai-governance",
      issued_at: "2025-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: TEST_ED25519_PUBLIC_KEY,
      signature: VALID_SIG_REAL_AI_GOV,
    };
    const result = registry.satisfyAttestation("ai_governance", validManifest);
    expect(result.success).toBe(true);
    expect(registry.getSlotStatus("ai_governance").status).toBe("active");
  });
});

describe("CT-LIC: License compliance checks", () => {
  it("CT-LIC-010: checkLicenseCompliance reports clean when all adapters comply", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", adapter, "noop-gov-v1");
    registry.satisfyAttestation("ai_governance");

    const violations = registry.checkLicenseCompliance();
    expect(violations.length).toBe(0);
  });

  it("CT-LIC-012: checkLicenseCompliance detects tariff violation after downgrade", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", adapter, "noop-gov-v1");
    registry.satisfyAttestation("ai_governance");

    expect(registry.getSlotStatus("ai_governance").status).toBe("active");

    registry.setTariff("O" as import("../types.js").TariffCode);
    expect(registry.getSlotStatus("ai_governance").status).toBe("null");

    const log = registry.getComplianceLog();
    expect(log.some(e => e.event_type === "TARIFF_DOWNGRADE")).toBe(true);
    expect(log.some(e => e.event_type === "ADAPTER_DEACTIVATED")).toBe(true);
  });

  it("CT-LIC-011: compliance log records manifest verification failures", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", adapter, "gov-v1");

    const badManifest = {
      manifest_version: "1.0" as const,
      adapter_name: "test",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@evil/bad",
      issued_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() + 86400000).toISOString(),
      issuer: "gimel-foundation" as const,
      public_key: "test-key",
      signature: "a".repeat(128),
    };

    registry.satisfyAttestation("ai_governance", badManifest);

    const log = registry.getComplianceLog();
    expect(log.some(e => e.event_type === "MANIFEST_VERIFICATION_FAILED")).toBe(true);
  });
});

describe("CT-TRUST: Pinned trust key enforcement", () => {
  it("CT-TRUST-001: rejects manifest when no pinned trust key matches issuer", () => {
    const wrongKeys = [{ public_key_hex: TEST_ED25519_PUBLIC_KEY, issuer: "other-foundation" }];
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, wrongKeys);
    const adapter = { name: "real-governance", packageNamespace: "@gimel/gov" } as unknown as import("../adapters.js").GAuthAdapter;
    registry.register("ai_governance", adapter, "real-gov-v1");

    const manifest = {
      manifest_version: "1.0" as const,
      adapter_name: "real-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/gov",
      issued_at: "2025-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: TEST_ED25519_PUBLIC_KEY,
      signature: VALID_SIG_REAL_GOV,
    };
    const result = registry.satisfyAttestation("ai_governance", manifest);
    expect(result.success).toBe(false);
    expect(result.error).toContain("pinned trust key");
  });

  it("CT-TRUST-002: rejects self-signed manifest (attacker key not in trust store)", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = { name: "real-governance", packageNamespace: "@gimel/gov" } as unknown as import("../adapters.js").GAuthAdapter;
    registry.register("ai_governance", adapter, "real-gov-v1");

    const attackerKey = "302a300506032b6570032100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const manifest = {
      manifest_version: "1.0" as const,
      adapter_name: "real-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/gov",
      issued_at: "2025-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: attackerKey,
      signature: "ff".repeat(64),
    };
    const result = registry.satisfyAttestation("ai_governance", manifest);
    expect(result.success).toBe(false);
    expect(result.error).toContain("signature");
  });

  it("CT-TRUST-003: accepts manifest verified against pinned trust key", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = { name: "real-governance", packageNamespace: "@gimel/gov" } as unknown as import("../adapters.js").GAuthAdapter;
    registry.register("ai_governance", adapter, "real-gov-v1");

    const manifest = {
      manifest_version: "1.0" as const,
      adapter_name: "real-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/gov",
      issued_at: "2025-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: TEST_ED25519_PUBLIC_KEY,
      signature: VALID_SIG_REAL_GOV,
    };
    const result = registry.satisfyAttestation("ai_governance", manifest);
    expect(result.success).toBe(true);
    expect(registry.getSlotStatus("ai_governance").status).toBe("active");
  });
});

describe("CT-BIND: Manifest-adapter identity binding", () => {
  it("CT-BIND-001: rejects manifest with mismatched adapter_name", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = { name: "my-governance", packageNamespace: "@gimel/gov" } as unknown as import("../adapters.js").GAuthAdapter;
    registry.register("ai_governance", adapter, "my-gov-v1");

    const manifest = {
      manifest_version: "1.0" as const,
      adapter_name: "different-adapter",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/gov",
      issued_at: "2025-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: TEST_ED25519_PUBLIC_KEY,
      signature: VALID_SIG_REAL_GOV,
    };
    const result = registry.satisfyAttestation("ai_governance", manifest);
    expect(result.success).toBe(false);
    expect(result.error).toContain("adapter_name");
    expect(result.error).toContain("does not match");
  });

  it("CT-BIND-002: rejects manifest with mismatched namespace", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = { name: "real-governance", packageNamespace: "@gimel/other" } as unknown as import("../adapters.js").GAuthAdapter;
    registry.register("ai_governance", adapter, "real-gov-v1");

    const manifest = {
      manifest_version: "1.0" as const,
      adapter_name: "real-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/gov",
      issued_at: "2025-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: TEST_ED25519_PUBLIC_KEY,
      signature: VALID_SIG_REAL_GOV,
    };
    const result = registry.satisfyAttestation("ai_governance", manifest);
    expect(result.success).toBe(false);
    expect(result.error).toContain("namespace");
    expect(result.error).toContain("does not match");
  });

  it("CT-BIND-003: register() rejects manifest with mismatched adapter identity", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode, GIMEL_TRUST_KEYS);
    const adapter = { name: "wrong-name", packageNamespace: "@gimel/gov" } as unknown as import("../adapters.js").GAuthAdapter;

    const manifest = {
      manifest_version: "1.0" as const,
      adapter_name: "real-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/gov",
      issued_at: "2025-01-01T00:00:00Z",
      expires_at: "2030-01-01T00:00:00Z",
      issuer: "gimel-foundation" as const,
      public_key: TEST_ED25519_PUBLIC_KEY,
      signature: VALID_SIG_REAL_GOV,
    };
    const result = registry.register("ai_governance", adapter, "wrong-v1", manifest);
    expect(result.success).toBe(false);
    expect(result.error).toContain("adapter_name");
  });
});
