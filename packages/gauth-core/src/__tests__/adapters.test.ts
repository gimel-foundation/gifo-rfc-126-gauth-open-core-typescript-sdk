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

  it("registers Type C adapter as pending without attestation", () => {
    const reg = new ConnectorSlotRegistry("M");
    const adapter = new NoOpGovernanceAdapter();
    const result = reg.register("ai_governance", adapter, "G-Agent Governance");
    expect(result.success).toBe(true);
    expect(reg.getSlotStatus("ai_governance").status).toBe("pending");
  });

  it("transitions Type C from pending to active on attestation", () => {
    const reg = new ConnectorSlotRegistry("M");
    reg.register("ai_governance", new NoOpGovernanceAdapter(), "G-Agent");
    expect(reg.getSlotStatus("ai_governance").status).toBe("pending");

    const attest = reg.satisfyAttestation("ai_governance");
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
    const registryM = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
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
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
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
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
    const goodAdapter = new NoOpGovernanceAdapter();
    const result = registry.register("ai_governance", goodAdapter, "noop-gov-v1");
    expect(result.success).toBe(true);
  });

  it("CT-REG-021: manifest verification rejects expired manifest", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
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
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
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
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
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

  it("CT-REG-024: valid manifest succeeds attestation and activates adapter", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
    const adapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", adapter, "noop-gov-v1");

    expect(registry.getSlotStatus("ai_governance").status).toBe("pending");

    const validManifest = {
      manifest_version: "1.0" as const,
      adapter_name: "noop-ai-governance",
      adapter_type: "C" as const,
      adapter_version: "1.0.0",
      slot_name: "ai_governance" as const,
      namespace: "@gimel/ai-governance",
      issued_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() + 86400000).toISOString(),
      issuer: "gimel-foundation" as const,
      public_key: "test-key",
      signature: "a".repeat(128),
    };

    const result = registry.satisfyAttestation("ai_governance", validManifest);
    expect(result.success).toBe(true);
    expect(registry.getSlotStatus("ai_governance").status).toBe("active");
  });
});

describe("CT-REG: Tariff downgrade re-evaluation", () => {
  it("CT-REG-025: setTariff downgrades and deactivates non-compliant adapters", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
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
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
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

describe("CT-REG: Non-NoOp Type C attestation requires manifest", () => {
  it("CT-REG-028: non-NoOp Type C adapter cannot satisfy attestation without manifest", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
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

  it("CT-REG-029: NoOp Type C adapter can satisfy attestation without manifest", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
    const adapter = new NoOpGovernanceAdapter();
    registry.register("ai_governance", adapter, "noop-gov-v1");
    const result = registry.satisfyAttestation("ai_governance");
    expect(result.success).toBe(true);
  });

  it("CT-REG-030: non-NoOp Type C adapter succeeds attestation with valid manifest", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
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
      issued_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() + 86400000).toISOString(),
      issuer: "gimel-foundation" as const,
      public_key: "test-key",
      signature: "a".repeat(128),
    };
    const result = registry.satisfyAttestation("ai_governance", validManifest);
    expect(result.success).toBe(true);
    expect(registry.getSlotStatus("ai_governance").status).toBe("active");
  });
});

describe("CT-LIC: License compliance checks", () => {
  it("CT-LIC-010: checkLicenseCompliance detects non-NoOp Type C at tariff O", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
    const realAdapter = {
      adapterType: "C" as const,
      name: "real-ai-governance",
      packageNamespace: "@gimel/ai-governance",
      async checkAccess() { return { allowed: true, reason: "" }; },
      async getRecommendations() { return []; },
      async healthCheck() { return { healthy: true, latencyMs: 0 }; },
    };
    registry.register("ai_governance", realAdapter, "real-gov-v1");
    registry.satisfyAttestation("ai_governance");

    registry.setTariff("O" as import("../types.js").TariffCode);

    registry.register("ai_governance", realAdapter, "real-gov-v1-force");

    const violations = registry.checkLicenseCompliance();
    expect(violations.length).toBe(0);
  });

  it("CT-LIC-011: compliance log records manifest verification failures", () => {
    const registry = new ConnectorSlotRegistry("M" as import("../types.js").TariffCode);
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
