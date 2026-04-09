import { describe, it, expect } from "vitest";
import {
  PoACredential,
  GovernanceProfile,
  Phase,
  ApprovalMode,
  MandateStatus,
  TERMINAL_STATES,
  DEFAULT_GOVERNANCE_CEILINGS,
  VIOLATION_CODES,
  PEP_ERROR_CODES,
  MGMT_ERROR_CODES,
  SCHEMA_VERSION,
} from "../types.js";

describe("types and constants", () => {
  it("has correct schema version", () => {
    expect(SCHEMA_VERSION).toBe("0116.2.2");
  });

  it("defines all governance profiles", () => {
    const profiles: string[] = ["minimal", "standard", "strict", "enterprise", "behoerde"];
    for (const p of profiles) {
      expect(GovernanceProfile.safeParse(p).success).toBe(true);
    }
  });

  it("defines all phases", () => {
    for (const p of ["plan", "build", "run"]) {
      expect(Phase.safeParse(p).success).toBe(true);
    }
  });

  it("defines all approval modes", () => {
    for (const m of ["autonomous", "supervised", "four-eyes"]) {
      expect(ApprovalMode.safeParse(m).success).toBe(true);
    }
  });

  it("defines terminal states", () => {
    expect(TERMINAL_STATES).toContain("EXPIRED");
    expect(TERMINAL_STATES).toContain("REVOKED");
    expect(TERMINAL_STATES).toContain("BUDGET_EXCEEDED");
    expect(TERMINAL_STATES).toContain("SUPERSEDED");
    expect(TERMINAL_STATES).not.toContain("ACTIVE");
    expect(TERMINAL_STATES).not.toContain("SUSPENDED");
  });

  it("has ceilings for all profiles", () => {
    const profiles: GovernanceProfile[] = ["minimal", "standard", "strict", "enterprise", "behoerde"];
    for (const p of profiles) {
      const ceiling = DEFAULT_GOVERNANCE_CEILINGS[p];
      expect(ceiling).toBeDefined();
      expect(ceiling.governance_profile).toBe(p);
      expect(ceiling.max_ttl_seconds).toBeGreaterThan(0);
      expect(ceiling.max_budget_cents).toBeGreaterThan(0);
    }
  });

  it("minimal profile is the most restrictive", () => {
    const minimal = DEFAULT_GOVERNANCE_CEILINGS.minimal;
    const enterprise = DEFAULT_GOVERNANCE_CEILINGS.enterprise;
    expect(minimal.max_ttl_seconds).toBeLessThan(enterprise.max_ttl_seconds);
    expect(minimal.max_budget_cents).toBeLessThan(enterprise.max_budget_cents);
    expect(minimal.max_delegation_depth).toBeLessThan(enterprise.max_delegation_depth);
    expect(minimal.auto_deploy_allowed).toBe(false);
    expect(minimal.production_access_allowed).toBe(false);
  });

  it("behoerde requires four-eyes only", () => {
    const behoerde = DEFAULT_GOVERNANCE_CEILINGS.behoerde;
    expect(behoerde.allowed_approval_modes).toEqual(["four-eyes"]);
  });

  it("defines all violation codes", () => {
    expect(Object.keys(VIOLATION_CODES).length).toBeGreaterThanOrEqual(20);
    expect(VIOLATION_CODES.CREDENTIAL_INVALID).toBe("CREDENTIAL_INVALID");
    expect(VIOLATION_CODES.BUDGET_EXCEEDED).toBe("BUDGET_EXCEEDED");
  });

  it("defines PEP error codes", () => {
    expect(PEP_ERROR_CODES.PEP_INTERNAL_ERROR).toBe("PEP_INTERNAL_ERROR");
    expect(PEP_ERROR_CODES.INVALID_REQUEST).toBe("INVALID_REQUEST");
  });

  it("defines management error codes", () => {
    expect(MGMT_ERROR_CODES.MANDATE_NOT_FOUND).toBe("MANDATE_NOT_FOUND");
    expect(MGMT_ERROR_CODES.SCOPE_IMMUTABLE).toBe("SCOPE_IMMUTABLE");
  });
});

describe("PoACredential schema validation", () => {
  const validPoa = {
    parties: {
      issuer: "https://auth.example.com",
      subject: "agent-001",
      customer_id: "cust-123",
      project_id: "proj-456",
    },
    scope: {
      governance_profile: "standard",
      phase: "build",
      core_verbs: {
        "foundry.file.create": { allowed: true },
        "foundry.file.modify": { allowed: true },
      },
    },
    requirements: {
      approval_mode: "supervised",
    },
  };

  it("accepts valid PoA credential", () => {
    const result = PoACredential.safeParse(validPoa);
    expect(result.success).toBe(true);
  });

  it("rejects invalid governance profile", () => {
    const result = PoACredential.safeParse({
      ...validPoa,
      scope: { ...validPoa.scope, governance_profile: "invalid" },
    });
    expect(result.success).toBe(false);
  });

  it("rejects invalid phase", () => {
    const result = PoACredential.safeParse({
      ...validPoa,
      scope: { ...validPoa.scope, phase: "invalid" },
    });
    expect(result.success).toBe(false);
  });

  it("rejects missing subject", () => {
    const result = PoACredential.safeParse({
      ...validPoa,
      parties: { ...validPoa.parties, subject: undefined },
    });
    expect(result.success).toBe(false);
  });
});
