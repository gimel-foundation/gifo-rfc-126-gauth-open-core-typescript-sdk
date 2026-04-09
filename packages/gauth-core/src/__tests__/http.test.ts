import { describe, it, expect, beforeEach } from "vitest";
import { handlePEPRequest, handleMgmtRequest } from "../http.js";
import { ManagementAPI, InMemoryMandateStore } from "../management.js";
import type { PoACredential, EnforcementRequest } from "../types.js";

function makePoa(): PoACredential {
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
      },
      allowed_paths: ["src/"],
      denied_paths: [".env"],
    },
    requirements: {
      approval_mode: "autonomous",
      budget: { total_cents: 10000, remaining_cents: 10000 },
    },
  } as PoACredential;
}

describe("PEP HTTP handler", () => {
  it("returns health check", async () => {
    const res = await handlePEPRequest({
      method: "GET",
      path: "/gauth/pep/v1/health",
      body: null,
      headers: {},
    });
    expect(res.status).toBe(200);
    expect((res.body as Record<string, unknown>).status).toBe("ok");
  });

  it("enforces single action", async () => {
    const poa = makePoa();
    const req: EnforcementRequest = {
      request_id: "req-http-1",
      timestamp: new Date().toISOString(),
      action: { verb: "foundry.file.create", resource: "src/test.ts" },
      agent: { agent_id: "agent-001" },
      credential: { format: "jwt", poa_snapshot: {} },
    };
    const res = await handlePEPRequest(
      { method: "POST", path: "/gauth/pep/v1/enforce", body: req, headers: {} },
      {},
      poa,
    );
    expect(res.status).toBe(200);
    expect((res.body as Record<string, unknown>).decision).toBe("PERMIT");
  });

  it("returns 400 for invalid enforce request", async () => {
    const res = await handlePEPRequest(
      { method: "POST", path: "/gauth/pep/v1/enforce", body: {}, headers: {} },
    );
    expect(res.status).toBe(400);
  });

  it("enforces batch", async () => {
    const poa = makePoa();
    const requests = [
      {
        request_id: "r1",
        timestamp: new Date().toISOString(),
        action: { verb: "foundry.file.create", resource: "src/a.ts" },
        agent: { agent_id: "agent-001" },
        credential: { format: "jwt", poa_snapshot: {} },
      },
    ];
    const res = await handlePEPRequest(
      { method: "POST", path: "/gauth/pep/v1/enforce/batch", body: { requests, mode: "independent" }, headers: {} },
      {},
      poa,
    );
    expect(res.status).toBe(200);
  });

  it("returns policy", async () => {
    const poa = makePoa();
    const res = await handlePEPRequest(
      { method: "POST", path: "/gauth/pep/v1/policy", body: {}, headers: {} },
      {},
      poa,
    );
    expect(res.status).toBe(200);
    expect((res.body as Record<string, unknown>).governance_profile).toBe("standard");
  });

  it("returns 404 for unknown path", async () => {
    const res = await handlePEPRequest(
      { method: "GET", path: "/gauth/pep/v1/unknown", body: null, headers: {} },
    );
    expect(res.status).toBe(404);
  });
});

describe("Management HTTP handler", () => {
  let api: ManagementAPI;

  beforeEach(() => {
    api = new ManagementAPI(new InMemoryMandateStore());
  });

  it("creates a mandate", async () => {
    const res = await handleMgmtRequest(
      {
        method: "POST",
        path: "/gauth/mgmt/v1/mandates",
        body: {
          parties: { subject: "agent-001", customer_id: "cust-123", project_id: "proj-456", issued_by: "admin@example.com" },
          scope: { governance_profile: "standard", phase: "build", core_verbs: { "foundry.file.create": { allowed: true } } },
          requirements: { approval_mode: "autonomous", budget: { total_cents: 5000 }, ttl_seconds: 3600 },
        },
        headers: {},
      },
      api,
    );
    expect(res.status).toBe(201);
    expect((res.body as Record<string, unknown>).mandate_id).toBeDefined();
  });

  it("gets a mandate", async () => {
    const createRes = await handleMgmtRequest(
      {
        method: "POST",
        path: "/gauth/mgmt/v1/mandates",
        body: {
          parties: { subject: "agent-001", customer_id: "cust-123", project_id: "proj-456", issued_by: "admin@example.com" },
          scope: { governance_profile: "standard", phase: "build", core_verbs: { "foundry.file.create": { allowed: true } } },
          requirements: { approval_mode: "autonomous", budget: { total_cents: 5000 }, ttl_seconds: 3600 },
        },
        headers: {},
      },
      api,
    );
    const mandateId = (createRes.body as Record<string, unknown>).mandate_id as string;

    const getRes = await handleMgmtRequest(
      { method: "GET", path: `/gauth/mgmt/v1/mandates/${mandateId}`, body: null, headers: {} },
      api,
    );
    expect(getRes.status).toBe(200);
    expect((getRes.body as Record<string, unknown>).mandate_id).toBe(mandateId);
  });

  it("returns 404 for unknown mandate", async () => {
    const res = await handleMgmtRequest(
      { method: "GET", path: "/gauth/mgmt/v1/mandates/mdt_nonexistent", body: null, headers: {} },
      api,
    );
    expect(res.status).toBe(404);
  });

  it("activates a mandate", async () => {
    const createRes = await handleMgmtRequest(
      {
        method: "POST",
        path: "/gauth/mgmt/v1/mandates",
        body: {
          parties: { subject: "agent-001", customer_id: "cust-123", project_id: "proj-456", issued_by: "admin@example.com" },
          scope: { governance_profile: "standard", phase: "build", core_verbs: { "foundry.file.create": { allowed: true } } },
          requirements: { approval_mode: "autonomous", budget: { total_cents: 5000 }, ttl_seconds: 3600 },
        },
        headers: {},
      },
      api,
    );
    const mandateId = (createRes.body as Record<string, unknown>).mandate_id as string;

    const res = await handleMgmtRequest(
      {
        method: "POST",
        path: `/gauth/mgmt/v1/mandates/${mandateId}/activate`,
        body: { activated_by: "admin@example.com" },
        headers: {},
      },
      api,
    );
    expect(res.status).toBe(200);
    expect((res.body as Record<string, unknown>).status).toBe("ACTIVE");
  });

  it("returns 404 for unknown management path", async () => {
    const res = await handleMgmtRequest(
      { method: "GET", path: "/gauth/mgmt/v1/unknown", body: null, headers: {} },
      api,
    );
    expect(res.status).toBe(404);
  });
});
