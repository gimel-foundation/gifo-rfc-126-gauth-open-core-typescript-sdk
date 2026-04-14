import { describe, it, expect, beforeEach } from "vitest";
import { enforceAction, batchEnforce, getEnforcementPolicy, isEnforcementError } from "../pep.js";
import type { EnforcementRequest, PoACredential, EnforcementDecision, EnforcementError } from "../types.js";

function makePoa(overrides?: Partial<PoACredential>): PoACredential {
  return {
    schema_version: "0116.2.2",
    parties: {
      issuer: "https://auth.example.com",
      subject: "agent-001",
      customer_id: "cust-123",
      project_id: "proj-456",
      issued_by: "admin@example.com",
    },
    scope: {
      governance_profile: "standard",
      phase: "build",
      core_verbs: {
        "foundry.file.create": { allowed: true },
        "foundry.file.modify": { allowed: true },
        "foundry.file.delete": { allowed: true },
        "foundry.command.run": { allowed: true },
        "foundry.dependency.add": { allowed: true },
        "foundry.agent.delegate": { allowed: false },
      },
      allowed_paths: ["src/"],
      denied_paths: [".env", "secrets/"],
    },
    requirements: {
      approval_mode: "autonomous",
      budget: { total_cents: 10000, remaining_cents: 10000 },
      ttl_seconds: 3600,
    },
    ...overrides,
  } as PoACredential;
}

function makeRequest(overrides?: Partial<EnforcementRequest>): EnforcementRequest {
  return {
    request_id: "req-001",
    timestamp: new Date().toISOString(),
    action: {
      verb: "foundry.file.create",
      resource: "src/index.ts",
    },
    agent: {
      agent_id: "agent-001",
    },
    credential: {
      format: "jwt",
      poa_snapshot: {},
    },
    ...overrides,
  };
}

describe("PEP enforceAction", () => {
  it("PERMIT: valid action within scope", async () => {
    const poa = makePoa();
    const req = makeRequest();
    const result = await enforceAction(req, poa);

    expect(isEnforcementError(result)).toBe(false);
    const decision = result as EnforcementDecision;
    expect(decision.decision).toBe("PERMIT");
    expect(decision.request_id).toBe("req-001");
    expect(decision.checks.length).toBe(16);
    expect(decision.violations).toHaveLength(0);
    expect(decision.audit.pep_version).toBeDefined();
  });

  it("DENY: verb not allowed", async () => {
    const poa = makePoa();
    const req = makeRequest({
      action: { verb: "foundry.agent.delegate", resource: "agent-002" },
    });
    const result = await enforceAction(req, poa);

    expect(isEnforcementError(result)).toBe(false);
    const decision = result as EnforcementDecision;
    expect(decision.decision).toBe("DENY");
    expect(decision.violations.some((v) => v.code === "VERB_NOT_ALLOWED")).toBe(true);
  });

  it("DENY: path denied", async () => {
    const poa = makePoa();
    const req = makeRequest({
      action: { verb: "foundry.file.create", resource: ".env" },
    });
    const result = await enforceAction(req, poa);

    const decision = result as EnforcementDecision;
    expect(decision.decision).toBe("DENY");
    expect(decision.violations.some((v) => v.code === "PATH_DENIED")).toBe(true);
  });

  it("DENY: path not in allowed list", async () => {
    const poa = makePoa();
    const req = makeRequest({
      action: { verb: "foundry.file.create", resource: "dist/output.js" },
    });
    const result = await enforceAction(req, poa);

    const decision = result as EnforcementDecision;
    expect(decision.decision).toBe("DENY");
  });

  it("DENY: phase mismatch (plan phase, run verb)", async () => {
    const poa = makePoa({
      scope: {
        governance_profile: "minimal",
        phase: "plan",
        core_verbs: {
          "foundry.file.delete": { allowed: true },
        },
      },
    } as Partial<PoACredential>);
    const req = makeRequest({
      action: { verb: "foundry.file.delete", resource: "src/old.ts" },
    });
    const result = await enforceAction(req, poa);

    const decision = result as EnforcementDecision;
    expect(decision.decision).toBe("DENY");
    expect(decision.violations.some((v) => v.code === "PHASE_MISMATCH")).toBe(true);
  });

  it("DENY: budget exhausted", async () => {
    const poa = makePoa({
      requirements: {
        approval_mode: "autonomous",
        budget: { total_cents: 100, remaining_cents: 0 },
      },
    } as Partial<PoACredential>);
    const req = makeRequest();
    const result = await enforceAction(req, poa);

    const decision = result as EnforcementDecision;
    expect(decision.decision).toBe("DENY");
    expect(decision.violations.some((v) => v.code === "BUDGET_EXCEEDED")).toBe(true);
  });

  it("CONSTRAIN: budget cap applied", async () => {
    const poa = makePoa({
      requirements: {
        approval_mode: "autonomous",
        budget: { total_cents: 100, remaining_cents: 50 },
      },
    } as Partial<PoACredential>);
    const req = makeRequest({
      action: {
        verb: "foundry.file.create",
        resource: "src/index.ts",
        parameters: { amount_cents: 75 },
      },
    });
    const result = await enforceAction(req, poa);

    const decision = result as EnforcementDecision;
    expect(decision.decision).toBe("CONSTRAIN");
    expect(decision.enforced_constraints.length).toBeGreaterThan(0);
    expect(decision.enforced_constraints[0].constraint_type).toBe("budget_capped");
  });

  it("DENY: sector mismatch in strict mode", async () => {
    const poa = makePoa({
      scope: {
        governance_profile: "standard",
        phase: "build",
        core_verbs: { "foundry.file.create": { allowed: true } },
        allowed_sectors: ["finance"],
        allowed_paths: ["src/"],
      },
    } as Partial<PoACredential>);
    const req = makeRequest({
      action: { verb: "foundry.file.create", resource: "src/index.ts", sector: "healthcare" },
    });
    const result = await enforceAction(req, poa, { strictSectorMode: true });

    const decision = result as EnforcementDecision;
    expect(decision.decision).toBe("DENY");
    expect(decision.violations.some((v) => v.code === "SECTOR_MISMATCH")).toBe(true);
  });

  it("DENY: region mismatch", async () => {
    const poa = makePoa({
      scope: {
        governance_profile: "standard",
        phase: "build",
        core_verbs: { "foundry.file.create": { allowed: true } },
        allowed_regions: ["DE", "FR"],
        allowed_paths: ["src/"],
      },
    } as Partial<PoACredential>);
    const req = makeRequest({
      action: { verb: "foundry.file.create", resource: "src/index.ts", region: "US" },
    });
    const result = await enforceAction(req, poa);

    const decision = result as EnforcementDecision;
    expect(decision.decision).toBe("DENY");
    expect(decision.violations.some((v) => v.code === "REGION_MISMATCH")).toBe(true);
  });

  it("PERMIT: EU member matches EU region", async () => {
    const poa = makePoa({
      scope: {
        governance_profile: "standard",
        phase: "build",
        core_verbs: { "foundry.file.create": { allowed: true } },
        allowed_regions: ["EU"],
        allowed_paths: ["src/"],
      },
    } as Partial<PoACredential>);
    const req = makeRequest({
      action: { verb: "foundry.file.create", resource: "src/index.ts", region: "DE" },
    });
    const result = await enforceAction(req, poa);

    const decision = result as EnforcementDecision;
    expect(decision.decision).toBe("PERMIT");
  });

  it("DENY: delegation chain depth exceeded", async () => {
    const poa = makePoa({
      delegation_chain: [
        { delegator: "root", delegate: "child", scope_restriction: {}, max_depth_remaining: -1 },
      ],
    } as Partial<PoACredential>);
    const req = makeRequest();
    const result = await enforceAction(req, poa);

    const decision = result as EnforcementDecision;
    expect(decision.decision).toBe("DENY");
    expect(decision.violations.some((v) => v.code === "DELEGATION_DEPTH_EXCEEDED")).toBe(true);
  });

  it("includes audit record with timing", async () => {
    const poa = makePoa();
    const req = makeRequest();
    const result = await enforceAction(req, poa);

    const decision = result as EnforcementDecision;
    expect(decision.audit).toBeDefined();
    expect(decision.audit.processing_time_ms).toBeGreaterThanOrEqual(0);
    expect(decision.audit.checks_performed).toBeGreaterThan(0);
    expect(decision.audit.agent_id).toBe("agent-001");
    expect(decision.audit.action_verb).toBe("foundry.file.create");
  });
});

describe("PEP batchEnforce", () => {
  it("returns PERMIT for all valid requests", async () => {
    const poa = makePoa();
    const requests = [
      makeRequest({ request_id: "r1" }),
      makeRequest({ request_id: "r2" }),
    ];
    const batch = await batchEnforce(requests, "independent", poa);
    expect(batch.overall_decision).toBe("PERMIT");
    expect(batch.decisions).toHaveLength(2);
  });

  it("all_or_nothing: one deny causes all deny", async () => {
    const poa = makePoa();
    const requests = [
      makeRequest({ request_id: "r1" }),
      makeRequest({
        request_id: "r2",
        action: { verb: "foundry.agent.delegate", resource: "agent-x" },
      }),
    ];
    const batch = await batchEnforce(requests, "all_or_nothing", poa);
    expect(batch.overall_decision).toBe("DENY");
    expect(batch.decisions.every((d) => d.decision === "DENY")).toBe(true);
  });

  it("independent: mixed results preserve individual decisions", async () => {
    const poa = makePoa();
    const requests = [
      makeRequest({ request_id: "r1" }),
      makeRequest({
        request_id: "r2",
        action: { verb: "foundry.agent.delegate", resource: "agent-x" },
      }),
    ];
    const batch = await batchEnforce(requests, "independent", poa);
    expect(batch.overall_decision).toBe("DENY");
    expect(batch.decisions[0].decision).toBe("PERMIT");
    expect(batch.decisions[1].decision).toBe("DENY");
  });
});

describe("CHK-13 Budget via poa_snapshot", () => {
  it("enforces budget from poa_snapshot requirements", async () => {
    const poa = makePoa({
      requirements: {
        ...makePoa().requirements,
        budget: { total_cents: 100, remaining_cents: 0 },
      },
    });
    const req = makeRequest({
      credential: { format: "jwt", poa_snapshot: poa },
    });

    const result = await enforceAction(req, {}) as EnforcementDecision;
    expect(result.decision).toBe("DENY");
    const chk13 = result.checks.find((c) => c.check_id === "CHK-13");
    expect(chk13?.result).toBe("fail");
  });

  it("passes budget check when budget has remaining funds", async () => {
    const poa = makePoa({
      requirements: {
        ...makePoa().requirements,
        budget: { total_cents: 10000, remaining_cents: 5000 },
      },
    });
    const req = makeRequest({
      credential: { format: "jwt", poa_snapshot: poa },
    });

    const result = await enforceAction(req, {}) as EnforcementDecision;
    const chk13 = result.checks.find((c) => c.check_id === "CHK-13");
    expect(chk13?.result).toBe("pass");
  });
});

describe("CHK-11 Transaction Type", () => {
  it("blocks restricted transaction types under governance profile", async () => {
    const poa = makePoa({ scope: { ...makePoa().scope, governance_profile: "enterprise" } });
    const req = makeRequest({
      action: { verb: "foundry.file.delete", resource: "src/data.ts", transaction_type: "irreversible_delete" },
      credential: { format: "jwt", poa_snapshot: poa },
    });

    const result = await enforceAction(req, {}) as EnforcementDecision;
    expect(result.decision).toBe("DENY");
    const chk11 = result.checks.find((c) => c.check_id === "CHK-11");
    expect(chk11?.result).toBe("fail");
  });

  it("allows non-restricted transaction types", async () => {
    const poa = makePoa({ scope: { ...makePoa().scope, governance_profile: "minimal" } });
    const req = makeRequest({
      action: { verb: "foundry.file.create", resource: "src/index.ts", transaction_type: "irreversible_delete" },
      credential: { format: "jwt", poa_snapshot: poa },
    });

    const result = await enforceAction(req, {}) as EnforcementDecision;
    const chk11 = result.checks.find((c) => c.check_id === "CHK-11");
    expect(chk11?.result).toBe("pass");
  });
});

describe("CHK-12 Decision Type", () => {
  it("blocks restricted decision types under governance profile", async () => {
    const poa = makePoa({ scope: { ...makePoa().scope, governance_profile: "strict" } });
    const req = makeRequest({
      action: { verb: "foundry.file.create", resource: "src/index.ts", decision_type: "autonomous_deployment" },
      credential: { format: "jwt", poa_snapshot: poa },
    });

    const result = await enforceAction(req, {}) as EnforcementDecision;
    expect(result.decision).toBe("DENY");
    const chk12 = result.checks.find((c) => c.check_id === "CHK-12");
    expect(chk12?.result).toBe("fail");
  });
});

describe("CHK-15 Approval", () => {
  it("denies supervised mode without approval evidence", async () => {
    const poa = makePoa({ requirements: { ...makePoa().requirements, approval_mode: "supervised" } });
    const req = makeRequest({
      credential: { format: "jwt", poa_snapshot: poa },
    });

    const result = await enforceAction(req, {}) as EnforcementDecision;
    expect(result.decision).toBe("DENY");
    const chk15 = result.checks.find((c) => c.check_id === "CHK-15");
    expect(chk15?.result).toBe("fail");
  });

  it("permits supervised mode with approval evidence", async () => {
    const poa = makePoa({ requirements: { ...makePoa().requirements, approval_mode: "supervised" } });
    const req = makeRequest({
      credential: { format: "jwt", poa_snapshot: poa },
      context: {
        approval_evidence: {
          approver_id: "admin@example.com",
          approved_at: new Date().toISOString(),
        },
      },
    });

    const result = await enforceAction(req, {}) as EnforcementDecision;
    const chk15 = result.checks.find((c) => c.check_id === "CHK-15");
    expect(chk15?.result).toBe("pass");
  });

  it("denies four-eyes when approver is the acting subject", async () => {
    const poa = makePoa({ requirements: { ...makePoa().requirements, approval_mode: "four-eyes" } });
    const req = makeRequest({
      credential: { format: "jwt", poa_snapshot: poa },
      context: {
        approval_evidence: {
          approver_id: "agent-001",
          approved_at: new Date().toISOString(),
        },
      },
    });

    const result = await enforceAction(req, {}) as EnforcementDecision;
    expect(result.decision).toBe("DENY");
    const chk15 = result.checks.find((c) => c.check_id === "CHK-15");
    expect(chk15?.result).toBe("fail");
    expect(chk15?.detail).toContain("different approver");
  });

  it("permits four-eyes with different approver", async () => {
    const poa = makePoa({ requirements: { ...makePoa().requirements, approval_mode: "four-eyes" } });
    const req = makeRequest({
      credential: { format: "jwt", poa_snapshot: poa },
      context: {
        approval_evidence: {
          approver_id: "admin@example.com",
          approved_at: new Date().toISOString(),
        },
      },
    });

    const result = await enforceAction(req, {}) as EnforcementDecision;
    const chk15 = result.checks.find((c) => c.check_id === "CHK-15");
    expect(chk15?.result).toBe("pass");
  });
});

describe("CHK-16 Delegation Chain Scope Enforcement", () => {
  it("blocks action outside delegation allowed_paths", async () => {
    const poa = makePoa({
      delegation_chain: [
        {
          delegator: "admin",
          delegate: "agent-001",
          scope_restriction: { allowed_paths: ["src/utils/"] },
          max_depth_remaining: 1,
        },
      ],
    });
    const req = makeRequest({
      action: { verb: "foundry.file.create", resource: "config/settings.ts" },
      credential: { format: "jwt", poa_snapshot: poa },
    });

    const result = await enforceAction(req, {}) as EnforcementDecision;
    expect(result.decision).toBe("DENY");
    const chk16 = result.checks.find((c) => c.check_id === "CHK-16");
    expect(chk16?.result).toBe("fail");
    expect(chk16?.detail).toContain("allowed_paths");
  });

  it("allows action within delegation allowed_paths", async () => {
    const poa = makePoa({
      delegation_chain: [
        {
          delegator: "admin",
          delegate: "agent-001",
          scope_restriction: { allowed_paths: ["src/"] },
          max_depth_remaining: 1,
        },
      ],
    });
    const req = makeRequest({
      action: { verb: "foundry.file.create", resource: "src/utils/helper.ts" },
      credential: { format: "jwt", poa_snapshot: poa },
    });

    const result = await enforceAction(req, {}) as EnforcementDecision;
    const chk16 = result.checks.find((c) => c.check_id === "CHK-16");
    expect(chk16?.result).toBe("pass");
  });
});

describe("getEnforcementPolicy", () => {
  it("extracts policy from PoA", () => {
    const poa = makePoa();
    const policy = getEnforcementPolicy(poa);

    expect(policy.governance_profile).toBe("standard");
    expect(policy.phase).toBe("build");
    expect(policy.allowed_verbs).toContain("foundry.file.create");
    expect(policy.allowed_verbs).not.toContain("foundry.agent.delegate");
    expect(policy.denied_paths).toContain(".env");
    expect(policy.allowed_paths).toContain("src/");
    expect(policy.approval_mode).toBe("autonomous");
    expect(policy.budget?.total_cents).toBe(10000);
    expect(policy.delegation.allowed).toBe(false);
  });
});

describe("isEnforcementError", () => {
  it("detects error objects", () => {
    const error: EnforcementError = {
      error_code: "PEP_INTERNAL_ERROR",
      message: "oops",
      timestamp: new Date().toISOString(),
    };
    expect(isEnforcementError(error)).toBe(true);
  });

  it("rejects decision objects", () => {
    expect(isEnforcementError({ decision: "PERMIT" } as unknown as EnforcementDecision)).toBe(false);
  });
});

describe("CT-PEP: OAuth pre-validation gate", () => {
  it("CT-PEP-032: rejects JWT with alg:none", async () => {
    const poa = makePoa();
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ sub: "agent-001" })).toString("base64url");
    const fakeToken = `${header}.${payload}.`;

    const req = makeRequest({
      credential: { format: "jwt", token: fakeToken },
    });

    const result = await enforceAction(req, poa);
    if (!isEnforcementError(result)) {
      expect(result.decision).toBe("DENY");
      const chk00 = result.checks.find(c => c.check_id === "CHK-00");
      expect(chk00).toBeDefined();
      expect(chk00?.result).toBe("fail");
      expect(chk00?.detail).toContain("alg: none");
    }
  });

  it("CT-PEP-033: rejects malformed JWT (not 3 parts)", async () => {
    const poa = makePoa();
    const req = makeRequest({
      credential: { format: "jwt", token: "notavalidtoken" },
    });

    const result = await enforceAction(req, poa);
    if (!isEnforcementError(result)) {
      expect(result.decision).toBe("DENY");
      const chk00 = result.checks.find(c => c.check_id === "CHK-00");
      expect(chk00).toBeDefined();
      expect(chk00?.result).toBe("fail");
    }
  });

  it("CT-PEP-034: passes pre-validation for well-formed JWT header", async () => {
    const poa = makePoa();
    const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ sub: "agent-001" })).toString("base64url");
    const sig = Buffer.from("fakesig").toString("base64url");
    const token = `${header}.${payload}.${sig}`;

    const req = makeRequest({
      credential: { format: "jwt", token, poa_snapshot: {
        scope: poa.scope,
        parties: poa.parties,
        requirements: poa.requirements,
      } },
    });

    const result = await enforceAction(req, poa);
    if (!isEnforcementError(result)) {
      const chk00 = result.checks.find(c => c.check_id === "CHK-00");
      expect(chk00).toBeDefined();
      expect(chk00?.result).toBe("pass");
    }
  });
});

describe("CT-PEP: CHK-09 max_delegation_depth cross-reference", () => {
  it("CT-PEP-035: CHK-09 evaluates max_delegation_depth constraint", async () => {
    const poa = makePoa({
      scope: {
        governance_profile: "enterprise",
        phase: "run",
        core_verbs: {
          "foundry.agent.delegate": {
            allowed: true,
            constraints: { max_delegation_depth: 1 },
          },
        },
      },
      delegation_chain: [
        { delegator: "admin", delegate: "agent-001", scope_restriction: {}, delegated_at: new Date().toISOString() },
        { delegator: "agent-001", delegate: "agent-002", scope_restriction: {}, delegated_at: new Date().toISOString() },
      ],
    } as Partial<PoACredential>);

    const req = makeRequest({
      action: { verb: "foundry.agent.delegate", resource: "agent-003" },
    });

    const result = await enforceAction(req, poa);
    if (!isEnforcementError(result)) {
      const chk09 = result.checks.find(c => c.check_id === "CHK-09");
      expect(chk09).toBeDefined();
      expect(chk09?.result).toBe("fail");
      expect(chk09?.detail).toContain("max_delegation_depth");
      expect(chk09?.detail).toContain("CHK-16");
    }
  });

  it("CT-PEP-036: CHK-09 passes when delegation depth within limit", async () => {
    const poa = makePoa({
      scope: {
        governance_profile: "enterprise",
        phase: "run",
        core_verbs: {
          "foundry.agent.delegate": {
            allowed: true,
            constraints: { max_delegation_depth: 3 },
          },
        },
      },
      delegation_chain: [
        { delegator: "admin", delegate: "agent-001", scope_restriction: {} },
      ],
    } as Partial<PoACredential>);

    const req = makeRequest({
      action: { verb: "foundry.agent.delegate", resource: "agent-002" },
    });

    const result = await enforceAction(req, poa);
    if (!isEnforcementError(result)) {
      const chk09 = result.checks.find(c => c.check_id === "CHK-09");
      expect(chk09).toBeDefined();
      expect(chk09?.result).toBe("pass");
    }
  });
});

describe("CT-PEP: OAuth adapter integration", () => {
  it("CT-PEP-037: denies when OAuth adapter rejects token", async () => {
    const poa = makePoa();
    const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ sub: "agent-001" })).toString("base64url");
    const sig = Buffer.from("fakesig").toString("base64url");
    const token = `${header}.${payload}.${sig}`;

    const req = makeRequest({
      credential: { format: "jwt", token, poa_snapshot: {
        scope: poa.scope,
        parties: poa.parties,
        requirements: poa.requirements,
      } },
    });

    const mockAdapter = {
      async validateToken(_t: string) { return { valid: false, reason: "Token revoked" }; },
    };

    const result = await enforceAction(req, poa, { oauthAdapter: mockAdapter });
    if (!isEnforcementError(result)) {
      expect(result.decision).toBe("DENY");
      const adapterCheck = result.checks.find(c => c.detail?.includes("OAuth adapter rejected"));
      expect(adapterCheck).toBeDefined();
      expect(adapterCheck?.result).toBe("fail");
    }
  });

  it("CT-PEP-038: passes when OAuth adapter accepts token", async () => {
    const poa = makePoa();
    const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ sub: "agent-001" })).toString("base64url");
    const sig = Buffer.from("fakesig").toString("base64url");
    const token = `${header}.${payload}.${sig}`;

    const req = makeRequest({
      credential: { format: "jwt", token, poa_snapshot: {
        scope: poa.scope,
        parties: poa.parties,
        requirements: poa.requirements,
      } },
    });

    const mockAdapter = {
      async validateToken(_t: string) { return { valid: true }; },
    };

    const result = await enforceAction(req, poa, { oauthAdapter: mockAdapter });
    if (!isEnforcementError(result)) {
      expect(result.decision).toBe("PERMIT");
    }
  });
});

describe("CT-PEP: License compliance at PEP level", () => {
  it("CT-PEP-039: denies when connector registry reports license violations", async () => {
    const poa = makePoa();
    const req = makeRequest();

    const mockRegistry = {
      checkLicenseCompliance() {
        return [{ slot: "ai_governance", violation: "Adapter not attested" }];
      },
    };

    const result = await enforceAction(req, poa, { connectorRegistry: mockRegistry });
    if (!isEnforcementError(result)) {
      expect(result.decision).toBe("DENY");
      expect(result.checks.some(c => c.detail?.includes("License compliance violations"))).toBe(true);
    }
  });

  it("CT-PEP-040: permits when connector registry is clean", async () => {
    const poa = makePoa();
    const req = makeRequest();

    const mockRegistry = {
      checkLicenseCompliance() { return []; },
    };

    const result = await enforceAction(req, poa, { connectorRegistry: mockRegistry });
    if (!isEnforcementError(result)) {
      expect(result.decision).toBe("PERMIT");
    }
  });
});
