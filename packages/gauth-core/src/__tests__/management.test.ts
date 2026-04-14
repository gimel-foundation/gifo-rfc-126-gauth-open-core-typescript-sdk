import { describe, it, expect, beforeEach } from "vitest";
import { ManagementAPI, InMemoryMandateStore, isManagementError } from "../management.js";
import type { MandateCreationRequest, ManagementError, MandateDetail } from "../types.js";

function makeCreateRequest(overrides?: Partial<MandateCreationRequest>): MandateCreationRequest {
  return {
    parties: {
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
      },
    },
    requirements: {
      approval_mode: "autonomous",
      budget: { total_cents: 5000 },
      ttl_seconds: 3600,
    },
    ...overrides,
  } as MandateCreationRequest;
}

describe("ManagementAPI", () => {
  let api: ManagementAPI;
  let store: InMemoryMandateStore;

  beforeEach(() => {
    store = new InMemoryMandateStore();
    api = new ManagementAPI(store);
  });

  describe("createMandate", () => {
    it("creates a DRAFT mandate", async () => {
      const result = await api.createMandate(makeCreateRequest());

      expect(isManagementError(result)).toBe(false);
      if (!isManagementError(result)) {
        expect(result.status).toBe("DRAFT");
        expect(result.mandate_id).toMatch(/^mdt_/);
        expect(result.scope_checksum).toMatch(/^sha256:/);
        expect(result.validation.accepted).toBe(true);
      }
    });

    it("rejects missing required fields", async () => {
      const result = await api.createMandate({
        parties: {} as MandateCreationRequest["parties"],
        scope: {} as MandateCreationRequest["scope"],
        requirements: {} as MandateCreationRequest["requirements"],
      } as MandateCreationRequest);

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.error_code).toBe("VALIDATION_FAILED");
      }
    });

    it("rejects ceiling violations", async () => {
      const result = await api.createMandate(makeCreateRequest({
        requirements: {
          approval_mode: "autonomous",
          budget: { total_cents: 999999 },
          ttl_seconds: 3600,
        },
      }));

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.error_code).toBe("VALIDATION_FAILED");
      }
    });

    it("rejects four-eyes without approval chain", async () => {
      const result = await api.createMandate(makeCreateRequest({
        requirements: {
          approval_mode: "four-eyes",
          budget: { total_cents: 5000 },
          ttl_seconds: 3600,
        },
      }));

      expect(isManagementError(result)).toBe(true);
    });
  });

  describe("mandate lifecycle", () => {
    let mandateId: string;

    beforeEach(async () => {
      const result = await api.createMandate(makeCreateRequest());
      if (!isManagementError(result)) {
        mandateId = result.mandate_id;
      }
    });

    it("activates a DRAFT mandate", async () => {
      const result = await api.activateMandate({ mandate_id: mandateId, activated_by: "admin@example.com" });

      expect(isManagementError(result)).toBe(false);
      if (!isManagementError(result)) {
        expect(result.status).toBe("ACTIVE");
        expect(result.expires_at).toBeDefined();
      }
    });

    it("rejects activating non-DRAFT mandate", async () => {
      await api.activateMandate({ mandate_id: mandateId, activated_by: "admin@example.com" });
      const result = await api.activateMandate({ mandate_id: mandateId, activated_by: "admin@example.com" });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.error_code).toBe("INVALID_STATE_TRANSITION");
      }
    });

    it("suspends an ACTIVE mandate", async () => {
      await api.activateMandate({ mandate_id: mandateId, activated_by: "admin@example.com" });
      const result = await api.suspendMandate({
        mandate_id: mandateId,
        suspended_by: "admin@example.com",
        reason: "investigation",
      });

      expect(isManagementError(result)).toBe(false);
      if (!isManagementError(result)) {
        expect(result.status).toBe("SUSPENDED");
      }
    });

    it("resumes a SUSPENDED mandate", async () => {
      await api.activateMandate({ mandate_id: mandateId, activated_by: "admin@example.com" });
      await api.suspendMandate({ mandate_id: mandateId, suspended_by: "admin@example.com", reason: "test" });
      const result = await api.resumeMandate({
        mandate_id: mandateId,
        resumed_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(false);
      if (!isManagementError(result)) {
        expect(result.status).toBe("ACTIVE");
        expect(result.remaining_ttl_seconds).toBeGreaterThan(0);
      }
    });

    it("revokes an ACTIVE mandate", async () => {
      await api.activateMandate({ mandate_id: mandateId, activated_by: "admin@example.com" });
      const result = await api.revokeMandate({
        mandate_id: mandateId,
        revoked_by: "admin@example.com",
        reason: "misuse detected",
      });

      expect(isManagementError(result)).toBe(false);
      if (!isManagementError(result)) {
        expect(result.status).toBe("REVOKED");
        expect(result.reason).toBe("misuse detected");
      }
    });

    it("cannot revoke a DRAFT mandate", async () => {
      const result = await api.revokeMandate({
        mandate_id: mandateId,
        revoked_by: "admin@example.com",
        reason: "test",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.error_code).toBe("INVALID_STATE_TRANSITION");
      }
    });

    it("cannot resume a non-SUSPENDED mandate", async () => {
      await api.activateMandate({ mandate_id: mandateId, activated_by: "admin@example.com" });
      const result = await api.resumeMandate({ mandate_id: mandateId, resumed_by: "admin@example.com" });

      expect(isManagementError(result)).toBe(true);
    });

    it("supersedes existing active mandate on activation", async () => {
      await api.activateMandate({ mandate_id: mandateId, activated_by: "admin@example.com" });

      const result2 = await api.createMandate(makeCreateRequest());
      if (!isManagementError(result2)) {
        const activation = await api.activateMandate({ mandate_id: result2.mandate_id, activated_by: "admin@example.com" });
        if (!isManagementError(activation)) {
          expect(activation.superseded_mandate_id).toBe(mandateId);
        }
      }
    });
  });

  describe("budget operations", () => {
    let mandateId: string;

    beforeEach(async () => {
      const result = await api.createMandate(makeCreateRequest());
      if (!isManagementError(result)) {
        mandateId = result.mandate_id;
        await api.activateMandate({ mandate_id: mandateId, activated_by: "admin@example.com" });
      }
    });

    it("tops up budget", async () => {
      const result = await api.topUpBudget({
        mandate_id: mandateId,
        additional_cents: 2000,
        performed_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(false);
      if (!isManagementError(result)) {
        expect(result.previous_total_cents).toBe(5000);
        expect(result.new_total_cents).toBe(7000);
        expect(result.remaining_cents).toBe(7000);
      }
    });

    it("rejects budget top-up exceeding governance ceiling", async () => {
      const result = await api.topUpBudget({
        mandate_id: mandateId,
        additional_cents: 999999,
        performed_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.error_code).toBe("CEILING_VIOLATION");
      }
    });

    it("rejects negative top-up", async () => {
      const result = await api.topUpBudget({
        mandate_id: mandateId,
        additional_cents: -100,
        performed_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.error_code).toBe("BUDGET_DECREASE_DENIED");
      }
    });

    it("tracks budget consumption", async () => {
      await api.reportConsumption({
        mandate_id: mandateId,
        amount_cents: 4500,
        action_verb: "foundry.command.run",
        action_resource: "npm test",
        timestamp: new Date().toISOString(),
      });

      const mandate = await api.getMandate(mandateId);
      if (!isManagementError(mandate)) {
        expect(mandate.budget_consumed_cents).toBe(4500);
        expect(mandate.requirements.budget?.remaining_cents).toBe(500);
      }
    });

    it("transitions to BUDGET_EXCEEDED when budget exhausted", async () => {
      await api.reportConsumption({
        mandate_id: mandateId,
        amount_cents: 5001,
        action_verb: "foundry.command.run",
        action_resource: "npm test",
        timestamp: new Date().toISOString(),
      });

      const mandate = await api.getMandate(mandateId);
      if (!isManagementError(mandate)) {
        expect(mandate.status).toBe("BUDGET_EXCEEDED");
      }
    });
  });

  describe("TTL extension", () => {
    let mandateId: string;

    beforeEach(async () => {
      const result = await api.createMandate(makeCreateRequest());
      if (!isManagementError(result)) {
        mandateId = result.mandate_id;
        await api.activateMandate({ mandate_id: mandateId, activated_by: "admin@example.com" });
      }
    });

    it("extends TTL", async () => {
      const result = await api.extendTTL({
        mandate_id: mandateId,
        additional_seconds: 1800,
        performed_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(false);
      if (!isManagementError(result)) {
        expect(result.new_ttl_seconds).toBe(5400);
      }
    });

    it("rejects TTL extension exceeding governance ceiling", async () => {
      const result = await api.extendTTL({
        mandate_id: mandateId,
        additional_seconds: 999999,
        performed_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.error_code).toBe("CEILING_VIOLATION");
      }
    });

    it("rejects negative TTL extension", async () => {
      const result = await api.extendTTL({
        mandate_id: mandateId,
        additional_seconds: -600,
        performed_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.error_code).toBe("TTL_DECREASE_DENIED");
      }
    });
  });

  describe("delegation", () => {
    let parentId: string;

    beforeEach(async () => {
      const result = await api.createMandate(makeCreateRequest({
        scope: {
          governance_profile: "enterprise",
          phase: "build",
          core_verbs: {
            "foundry.file.create": { allowed: true },
            "foundry.agent.delegate": {
              allowed: true,
              constraints: { max_delegation_depth: 2 },
            },
          },
        },
        requirements: {
          approval_mode: "autonomous",
          budget: { total_cents: 50000 },
          ttl_seconds: 3600,
        },
      }));
      if (!isManagementError(result)) {
        parentId = result.mandate_id;
        await api.activateMandate({ mandate_id: parentId, activated_by: "admin@example.com" });
      }
    });

    it("creates child mandate via delegation", async () => {
      const result = await api.createDelegation({
        parent_mandate_id: parentId,
        delegate_agent_id: "agent-002",
        scope_restriction: {},
        delegated_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(false);
      if (!isManagementError(result)) {
        expect(result.status).toBe("DRAFT");
        expect(result.delegation_depth).toBe(1);
        expect(result.parent_mandate_id).toBe(parentId);
      }
    });

    it("rejects delegation scope escalation (adding verbs not in parent)", async () => {
      const result = await api.createDelegation({
        parent_mandate_id: parentId,
        delegate_agent_id: "agent-002",
        scope_restriction: {
          core_verbs: {
            "foundry.file.delete": { allowed: true },
          },
        },
        delegated_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.error_code).toBe("VALIDATION_FAILED");
        expect(result.message).toContain("escalation");
      }
    });

    it("rejects delegation by unauthorized user", async () => {
      const result = await api.createDelegation({
        parent_mandate_id: parentId,
        delegate_agent_id: "agent-002",
        scope_restriction: {},
        delegated_by: "random-user@example.com",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.error_code).toBe("INSUFFICIENT_AUTHORITY");
      }
    });

    it("rejects delegation with less restrictive governance_profile", async () => {
      const result = await api.createDelegation({
        parent_mandate_id: parentId,
        delegate_agent_id: "agent-002",
        scope_restriction: {
          governance_profile: "minimal",
        },
        delegated_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.error_code).toBe("VALIDATION_FAILED");
        expect(result.message).toContain("governance_profile");
        expect(result.message).toContain("less restrictive");
      }
    });

    it("rejects delegation with broader phase", async () => {
      const result = await api.createDelegation({
        parent_mandate_id: parentId,
        delegate_agent_id: "agent-002",
        scope_restriction: {
          phase: "run",
        },
        delegated_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.error_code).toBe("VALIDATION_FAILED");
        expect(result.message).toContain("phase");
        expect(result.message).toContain("broader");
      }
    });

    it("allows delegation with more restrictive governance_profile", async () => {
      const result = await api.createDelegation({
        parent_mandate_id: parentId,
        delegate_agent_id: "agent-002",
        scope_restriction: {
          governance_profile: "behoerde",
        },
        delegated_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(false);
    });

    it("allows delegation with narrower phase", async () => {
      const result = await api.createDelegation({
        parent_mandate_id: parentId,
        delegate_agent_id: "agent-002",
        scope_restriction: {
          phase: "plan",
        },
        delegated_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(false);
    });

    it("rejects delegation with platform_permission escalation (boolean false→true)", async () => {
      const parentResult = await api.createMandate(makeCreateRequest({
        scope: {
          governance_profile: "enterprise",
          phase: "build",
          core_verbs: {
            "foundry.file.create": { allowed: true },
            "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
          },
          platform_permissions: { "database": { write: false, read: true } },
        },
        requirements: { approval_mode: "autonomous", budget: { total_cents: 50000 }, ttl_seconds: 3600 },
      }));
      if (isManagementError(parentResult)) return;
      await api.activateMandate({ mandate_id: parentResult.mandate_id, activated_by: "admin@example.com" });

      const result = await api.createDelegation({
        parent_mandate_id: parentResult.mandate_id,
        delegate_agent_id: "agent-002",
        scope_restriction: {
          platform_permissions: { "database": { write: true, read: true } },
        },
        delegated_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.message).toContain("escalates from false to true");
      }
    });

    it("rejects delegation with platform_permission escalation (array superset)", async () => {
      const parentResult = await api.createMandate(makeCreateRequest({
        scope: {
          governance_profile: "enterprise",
          phase: "build",
          core_verbs: {
            "foundry.file.create": { allowed: true },
            "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
          },
          platform_permissions: { "deploy": { targets: ["dev", "staging"] } },
        },
        requirements: { approval_mode: "autonomous", budget: { total_cents: 50000 }, ttl_seconds: 3600 },
      }));
      if (isManagementError(parentResult)) return;
      await api.activateMandate({ mandate_id: parentResult.mandate_id, activated_by: "admin@example.com" });

      const result = await api.createDelegation({
        parent_mandate_id: parentResult.mandate_id,
        delegate_agent_id: "agent-002",
        scope_restriction: {
          platform_permissions: { "deploy": { targets: ["dev", "staging", "prod"] } },
        },
        delegated_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.message).toContain("not in parent");
      }
    });

    it("rejects delegation with platform_permission type mismatch (fail-closed)", async () => {
      const parentResult = await api.createMandate(makeCreateRequest({
        scope: {
          governance_profile: "enterprise",
          phase: "build",
          core_verbs: {
            "foundry.file.create": { allowed: true },
            "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
          },
          platform_permissions: { "database": { write: false } },
        },
        requirements: { approval_mode: "autonomous", budget: { total_cents: 50000 }, ttl_seconds: 3600 },
      }));
      if (isManagementError(parentResult)) return;
      await api.activateMandate({ mandate_id: parentResult.mandate_id, activated_by: "admin@example.com" });

      const result = await api.createDelegation({
        parent_mandate_id: parentResult.mandate_id,
        delegate_agent_id: "agent-002",
        scope_restriction: {
          platform_permissions: { "database": { write: "yes" } } as any,
        },
        delegated_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.message).toContain("type mismatch");
      }
    });

    it("rejects delegation with loosened verb constraints", async () => {
      const result = await api.createDelegation({
        parent_mandate_id: parentId,
        delegate_agent_id: "agent-002",
        scope_restriction: {
          core_verbs: {
            "foundry.agent.delegate": {
              allowed: true,
              constraints: { max_delegation_depth: 5 },
            },
          },
        },
        delegated_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.message).toContain("constraint");
        expect(result.message).toContain("exceeds parent");
      }
    });

    it("allows delegation with tighter platform_permissions", async () => {
      const parentResult = await api.createMandate(makeCreateRequest({
        scope: {
          governance_profile: "enterprise",
          phase: "build",
          core_verbs: {
            "foundry.file.create": { allowed: true },
            "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
          },
          platform_permissions: { "database": { write: true, read: true } },
        },
        requirements: { approval_mode: "autonomous", budget: { total_cents: 50000 }, ttl_seconds: 3600 },
      }));
      if (isManagementError(parentResult)) return;
      await api.activateMandate({ mandate_id: parentResult.mandate_id, activated_by: "admin@example.com" });

      const result = await api.createDelegation({
        parent_mandate_id: parentResult.mandate_id,
        delegate_agent_id: "agent-002",
        scope_restriction: {
          platform_permissions: { "database": { write: false, read: true } },
        },
        delegated_by: "admin@example.com",
      });

      expect(isManagementError(result)).toBe(false);
    });

    it("rejects delegation when not allowed", async () => {
      const noDelegateResult = await api.createMandate(makeCreateRequest());
      if (!isManagementError(noDelegateResult)) {
        await api.activateMandate({ mandate_id: noDelegateResult.mandate_id, activated_by: "admin@example.com" });
        const result = await api.createDelegation({
          parent_mandate_id: noDelegateResult.mandate_id,
          delegate_agent_id: "agent-002",
          scope_restriction: {},
          delegated_by: "admin@example.com",
        });
        expect(isManagementError(result)).toBe(true);
      }
    });
  });

  describe("governance profile", () => {
    it("updates governance profile on DRAFT mandate (tightening)", async () => {
      const createResult = await api.createMandate(makeCreateRequest({
        scope: { governance_profile: "standard", phase: "build", core_verbs: { "foundry.file.create": { allowed: true } } },
        requirements: { approval_mode: "autonomous", budget: { total_cents: 5000 }, ttl_seconds: 3600 },
      }));
      if (isManagementError(createResult)) return;

      const result = await api.updateGovernanceProfile(createResult.mandate_id, "enterprise", "admin@example.com");
      expect(isManagementError(result)).toBe(false);
      if (!isManagementError(result)) {
        expect(result.previous_profile).toBe("standard");
        expect(result.new_profile).toBe("enterprise");
      }
    });

    it("rejects governance profile relaxation", async () => {
      const createResult = await api.createMandate(makeCreateRequest({
        scope: { governance_profile: "enterprise", phase: "build", core_verbs: { "foundry.file.create": { allowed: true } } },
        requirements: { approval_mode: "autonomous", budget: { total_cents: 5000 }, ttl_seconds: 3600 },
      }));
      if (isManagementError(createResult)) return;

      const result = await api.updateGovernanceProfile(createResult.mandate_id, "minimal", "admin@example.com");
      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.message).toContain("relax");
      }
    });

    it("rejects governance profile update on non-DRAFT mandate", async () => {
      const createResult = await api.createMandate(makeCreateRequest());
      if (isManagementError(createResult)) return;
      await api.activateMandate({ mandate_id: createResult.mandate_id, activated_by: "admin@example.com" });

      const result = await api.updateGovernanceProfile(createResult.mandate_id, "enterprise", "admin@example.com");
      expect(isManagementError(result)).toBe(true);
      if (isManagementError(result)) {
        expect(result.message).toContain("DRAFT");
      }
    });
  });

  describe("query", () => {
    it("queries mandates by customer_id", async () => {
      await api.createMandate(makeCreateRequest());
      await api.createMandate(makeCreateRequest({ parties: { subject: "agent-002", customer_id: "cust-123", project_id: "proj-789", issued_by: "admin@example.com" } }));

      const result = await api.queryMandates({ customer_id: "cust-123" });
      expect(result.mandates.length).toBe(2);
      expect(result.total).toBe(2);
    });

    it("queries mandates by status", async () => {
      const r = await api.createMandate(makeCreateRequest());
      if (!isManagementError(r)) {
        await api.activateMandate({ mandate_id: r.mandate_id, activated_by: "admin@example.com" });
      }
      await api.createMandate(makeCreateRequest({ parties: { subject: "agent-002", customer_id: "cust-123", project_id: "proj-789", issued_by: "admin@example.com" } }));

      const active = await api.queryMandates({ status: ["ACTIVE"] });
      expect(active.mandates.length).toBe(1);

      const draft = await api.queryMandates({ status: ["DRAFT"] });
      expect(draft.mandates.length).toBe(1);
    });
  });
});

describe("isManagementError", () => {
  it("detects error objects", () => {
    expect(isManagementError({ error_code: "MANDATE_NOT_FOUND", message: "x", timestamp: "y" })).toBe(true);
  });

  it("rejects non-error objects", () => {
    expect(isManagementError({ mandate_id: "mdt_abc" })).toBe(false);
  });
});

describe("CT-MGMT: Delegation approval gate", () => {
  let api: ManagementAPI;
  let store: InMemoryMandateStore;

  beforeEach(() => {
    store = new InMemoryMandateStore();
    api = new ManagementAPI(store);
  });

  it("CT-MGMT-027: supervised parent → child starts as PENDING_APPROVAL", async () => {
    const parent = await api.createMandate(makeCreateRequest({
      scope: {
        governance_profile: "enterprise",
        phase: "build",
        core_verbs: {
          "foundry.file.create": { allowed: true },
          "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
        },
      },
      requirements: {
        approval_mode: "supervised",
        budget: { total_cents: 50000 },
        ttl_seconds: 3600,
      },
    }));
    if (isManagementError(parent)) return;
    await api.activateMandate({ mandate_id: parent.mandate_id, activated_by: "admin@example.com" });

    const result = await api.createDelegation({
      parent_mandate_id: parent.mandate_id,
      delegate_agent_id: "agent-002",
      scope_restriction: {},
      delegated_by: "admin@example.com",
    });

    expect(isManagementError(result)).toBe(false);
    if (!isManagementError(result)) {
      expect(result.status).toBe("PENDING_APPROVAL");
    }
  });

  it("CT-MGMT-028: autonomous parent → child starts as DRAFT (no gate)", async () => {
    const parent = await api.createMandate(makeCreateRequest({
      scope: {
        governance_profile: "enterprise",
        phase: "build",
        core_verbs: {
          "foundry.file.create": { allowed: true },
          "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
        },
      },
      requirements: {
        approval_mode: "autonomous",
        budget: { total_cents: 50000 },
        ttl_seconds: 3600,
      },
    }));
    if (isManagementError(parent)) return;
    await api.activateMandate({ mandate_id: parent.mandate_id, activated_by: "admin@example.com" });

    const result = await api.createDelegation({
      parent_mandate_id: parent.mandate_id,
      delegate_agent_id: "agent-002",
      scope_restriction: {},
      delegated_by: "admin@example.com",
    });

    expect(isManagementError(result)).toBe(false);
    if (!isManagementError(result)) {
      expect(result.status).toBe("DRAFT");
    }
  });

  it("CT-MGMT-029: approveDelegation transitions PENDING_APPROVAL → DRAFT", async () => {
    const parent = await api.createMandate(makeCreateRequest({
      scope: {
        governance_profile: "enterprise",
        phase: "build",
        core_verbs: {
          "foundry.file.create": { allowed: true },
          "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
        },
      },
      requirements: {
        approval_mode: "supervised",
        budget: { total_cents: 50000 },
        ttl_seconds: 3600,
      },
    }));
    if (isManagementError(parent)) return;
    await api.activateMandate({ mandate_id: parent.mandate_id, activated_by: "admin@example.com" });

    const delegation = await api.createDelegation({
      parent_mandate_id: parent.mandate_id,
      delegate_agent_id: "agent-002",
      scope_restriction: {},
      delegated_by: "admin@example.com",
    });
    if (isManagementError(delegation)) return;

    const approval = await api.approveDelegation(delegation.child_mandate_id, "admin@example.com");
    expect(isManagementError(approval)).toBe(false);
    if (!isManagementError(approval)) {
      expect(approval.status).toBe("DRAFT");
      expect(approval.remaining_approvals).toBe(0);
      expect(approval.approved_by).toContain("admin@example.com");
    }
  });

  it("CT-MGMT-030: four-eyes delegation requires two distinct approvers", async () => {
    const parent = await api.createMandate(makeCreateRequest({
      parties: {
        subject: "agent-001",
        customer_id: "cust-123",
        project_id: "proj-456",
        issued_by: "admin@example.com",
        approval_chain: ["admin@example.com", "reviewer@example.com", "auditor@example.com"],
      },
      scope: {
        governance_profile: "enterprise",
        phase: "build",
        core_verbs: {
          "foundry.file.create": { allowed: true },
          "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
        },
      },
      requirements: {
        approval_mode: "four-eyes",
        budget: { total_cents: 50000 },
        ttl_seconds: 3600,
      },
    }));
    if (isManagementError(parent)) return;
    await api.activateMandate({ mandate_id: parent.mandate_id, activated_by: "admin@example.com" });

    const delegation = await api.createDelegation({
      parent_mandate_id: parent.mandate_id,
      delegate_agent_id: "agent-002",
      scope_restriction: {},
      delegated_by: "admin@example.com",
    });
    if (isManagementError(delegation)) return;

    const samePersonApproval = await api.approveDelegation(delegation.child_mandate_id, "admin@example.com");
    expect(isManagementError(samePersonApproval)).toBe(true);
    if (isManagementError(samePersonApproval)) {
      expect(samePersonApproval.error_code).toBe("INSUFFICIENT_AUTHORITY");
      expect(samePersonApproval.message).toContain("Four-eyes");
    }

    const firstApproval = await api.approveDelegation(delegation.child_mandate_id, "reviewer@example.com");
    expect(isManagementError(firstApproval)).toBe(false);
    if (!isManagementError(firstApproval)) {
      expect(firstApproval.status).toBe("PENDING_APPROVAL");
      expect(firstApproval.remaining_approvals).toBe(1);
      expect(firstApproval.approved_by).toContain("reviewer@example.com");
    }

    const duplicateApproval = await api.approveDelegation(delegation.child_mandate_id, "reviewer@example.com");
    expect(isManagementError(duplicateApproval)).toBe(true);
    if (isManagementError(duplicateApproval)) {
      expect(duplicateApproval.message).toContain("already approved");
    }

    const secondApproval = await api.approveDelegation(delegation.child_mandate_id, "auditor@example.com");
    expect(isManagementError(secondApproval)).toBe(false);
    if (!isManagementError(secondApproval)) {
      expect(secondApproval.status).toBe("DRAFT");
      expect(secondApproval.remaining_approvals).toBe(0);
      expect(secondApproval.approved_by).toHaveLength(2);
    }
  });
});

describe("CT-MGMT: generatePoaMap", () => {
  let api: ManagementAPI;
  let store: InMemoryMandateStore;

  beforeEach(() => {
    store = new InMemoryMandateStore();
    api = new ManagementAPI(store);
  });

  it("CT-MGMT-031: generates PoA map summary for mandate", async () => {
    const result = await api.createMandate(makeCreateRequest({
      scope: {
        governance_profile: "enterprise",
        phase: "build",
        core_verbs: {
          "foundry.file.create": { allowed: true },
          "foundry.file.delete": { allowed: false },
          "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
        },
        platform_permissions: {
          database: { read: true, write: false },
        },
      },
    }));
    if (isManagementError(result)) return;

    const map = await api.generatePoaMap(result.mandate_id);
    expect(isManagementError(map)).toBe(false);
    if (!isManagementError(map)) {
      expect(map.mandate_id).toBe(result.mandate_id);
      expect(map.governance_profile).toBe("enterprise");
      expect(map.phase).toBe("build");
      expect(map.allowed_verbs).toContain("foundry.file.create");
      expect(map.denied_verbs).toContain("foundry.file.delete");
      expect(map.max_delegation_depth).toBe(2);
      expect(map.platform_permissions_summary["database.read"]).toBe(true);
      expect(map.platform_permissions_summary["database.write"]).toBe(false);
      expect(map.generated_at).toBeDefined();
    }
  });

  it("CT-MGMT-032: generatePoaMap returns NOT_FOUND for missing mandate", async () => {
    const result = await api.generatePoaMap("mdt_nonexistent");
    expect(isManagementError(result)).toBe(true);
    if (isManagementError(result)) {
      expect(result.error_code).toBe("MANDATE_NOT_FOUND");
    }
  });

  it("CT-MGMT-033: delegation narrowing computes numeric min for constraints", async () => {
    const issuer = "admin@example.com";
    const parentReq = makeCreateRequest({
      scope: {
        governance_profile: "standard",
        phase: "build",
        core_verbs: {
          "foundry.file.create": {
            allowed: true,
            constraints: { max_file_size_bytes: 10000, max_delegation_depth: 3 },
          },
          "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 3 } },
        },
      },
    });
    const parent = await api.createMandate(parentReq);
    expect(isManagementError(parent)).toBe(false);
    if (isManagementError(parent)) return;
    await api.activateMandate({ mandate_id: parent.mandate_id, activated_by: issuer });

    const delegResult = await api.createDelegation({
      parent_mandate_id: parent.mandate_id,
      delegate_agent_id: "child-agent",
      delegated_by: issuer,
      scope_restriction: {
        core_verbs: {
          "foundry.file.create": {
            allowed: true,
            constraints: { max_file_size_bytes: 5000 },
          },
          "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
        },
      },
    });
    expect(isManagementError(delegResult)).toBe(false);
    if (isManagementError(delegResult)) return;
    const child = await api.getMandate(delegResult.child_mandate_id);
    expect(isManagementError(child)).toBe(false);
    if (isManagementError(child)) return;
    const fileCreate = child.scope.core_verbs["foundry.file.create"];
    expect(fileCreate.constraints?.max_file_size_bytes).toBe(5000);
    expect(fileCreate.constraints?.max_delegation_depth).toBe(3);
  });

  it("CT-MGMT-034: delegation narrowing intersects allowed lists", async () => {
    const issuer = "admin@example.com";
    const parentReq = makeCreateRequest({
      scope: {
        governance_profile: "standard",
        phase: "build",
        core_verbs: {
          "foundry.file.create": { allowed: true },
          "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
        },
        active_modules: ["mod-a", "mod-b", "mod-c"],
        allowed_regions: ["EU", "US"],
        allowed_sectors: ["finance", "health"],
      },
    });
    const parent = await api.createMandate(parentReq);
    expect(isManagementError(parent)).toBe(false);
    if (isManagementError(parent)) return;
    await api.activateMandate({ mandate_id: parent.mandate_id, activated_by: issuer });

    const delegResult = await api.createDelegation({
      parent_mandate_id: parent.mandate_id,
      delegate_agent_id: "child-agent",
      delegated_by: issuer,
      scope_restriction: {
        active_modules: ["mod-b", "mod-c"],
        allowed_regions: ["EU"],
        allowed_sectors: ["finance"],
      },
    });
    expect(isManagementError(delegResult)).toBe(false);
    if (isManagementError(delegResult)) return;
    const child = await api.getMandate(delegResult.child_mandate_id);
    expect(isManagementError(child)).toBe(false);
    if (isManagementError(child)) return;
    expect(child.scope.active_modules).toEqual(["mod-b", "mod-c"]);
    expect(child.scope.allowed_regions).toEqual(["EU"]);
    expect(child.scope.allowed_sectors).toEqual(["finance"]);
  });

  it("CT-MGMT-035: delegation rejects disjoint active_modules escalation", async () => {
    const issuer = "admin@example.com";
    const parentReq = makeCreateRequest({
      scope: {
        governance_profile: "standard",
        phase: "build",
        core_verbs: {
          "foundry.file.create": { allowed: true },
          "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
        },
        active_modules: ["mod-a"],
      },
    });
    const parent = await api.createMandate(parentReq);
    expect(isManagementError(parent)).toBe(false);
    if (isManagementError(parent)) return;
    await api.activateMandate({ mandate_id: parent.mandate_id, activated_by: issuer });

    const delegResult = await api.createDelegation({
      parent_mandate_id: parent.mandate_id,
      delegate_agent_id: "child-agent",
      delegated_by: issuer,
      scope_restriction: {
        active_modules: ["mod-x"],
      },
    });
    expect(isManagementError(delegResult)).toBe(true);
    if (isManagementError(delegResult)) {
      expect(delegResult.message).toContain("active_module");
      expect(delegResult.message).toContain("escalation");
    }
  });

  it("CT-MGMT-036: disjoint sector intersection yields rejection", async () => {
    const issuer = "admin@example.com";
    const parentReq = makeCreateRequest({
      scope: {
        governance_profile: "standard",
        phase: "build",
        core_verbs: {
          "foundry.file.create": { allowed: true },
          "foundry.agent.delegate": { allowed: true, constraints: { max_delegation_depth: 2 } },
        },
        allowed_regions: ["EU"],
        allowed_sectors: ["finance"],
      },
    });
    const parent = await api.createMandate(parentReq);
    expect(isManagementError(parent)).toBe(false);
    if (isManagementError(parent)) return;
    await api.activateMandate({ mandate_id: parent.mandate_id, activated_by: issuer });

    const delegResult = await api.createDelegation({
      parent_mandate_id: parent.mandate_id,
      delegate_agent_id: "child-agent",
      delegated_by: issuer,
      scope_restriction: {
        allowed_regions: ["EU"],
        allowed_sectors: ["health"],
      },
    });
    expect(isManagementError(delegResult)).toBe(true);
    if (isManagementError(delegResult)) {
      expect(delegResult.message).toContain("sector");
    }
  });
});
