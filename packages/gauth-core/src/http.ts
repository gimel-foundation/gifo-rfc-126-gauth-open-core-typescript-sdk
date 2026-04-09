import type {
  EnforcementRequest,
  EnforcementDecision,
  EnforcementError,
  PoACredential,
} from "./types.js";
import { PEP_INTERFACE_VERSION } from "./types.js";
import { enforceAction, batchEnforce, getEnforcementPolicy, isEnforcementError } from "./pep.js";
import type { PEPOptions } from "./pep.js";
import type { ManagementAPI } from "./management.js";

const SDK_VERSION = "0.1.0";

export interface PEPHttpRequest {
  method: string;
  path: string;
  body: unknown;
  headers: Record<string, string | undefined>;
}

export interface PEPHttpResponse {
  status: number;
  body: unknown;
  headers: Record<string, string>;
}

const PEP_RESPONSE_HEADERS: Record<string, string> = {
  "Content-Type": "application/json; charset=utf-8",
  "X-PEP-Version": SDK_VERSION,
  "X-PEP-Interface-Version": PEP_INTERFACE_VERSION,
};

export async function handlePEPRequest(
  req: PEPHttpRequest,
  pepOptions?: PEPOptions,
  poa?: PoACredential,
): Promise<PEPHttpResponse> {
  const path = req.path.replace(/\/+$/, "");

  if (path === "/gauth/pep/v1/health" && req.method === "GET") {
    return {
      status: 200,
      body: { status: "ok", pep_version: SDK_VERSION, interface_version: PEP_INTERFACE_VERSION },
      headers: PEP_RESPONSE_HEADERS,
    };
  }

  if (path === "/gauth/pep/v1/enforce" && req.method === "POST") {
    const request = req.body as EnforcementRequest;
    if (!request?.action || !request?.agent || !request?.credential) {
      return {
        status: 400,
        body: {
          error_code: "INVALID_REQUEST",
          message: "Missing required fields: action, agent, credential.",
          timestamp: new Date().toISOString(),
        },
        headers: PEP_RESPONSE_HEADERS,
      };
    }

    const result = await enforceAction(request, poa, pepOptions);

    if (isEnforcementError(result)) {
      const statusMap: Record<string, number> = {
        INVALID_REQUEST: 400,
        CREDENTIAL_PARSE_ERROR: 400,
        ISSUER_UNREACHABLE: 502,
        EVALUATION_TIMEOUT: 504,
        PEP_INTERNAL_ERROR: 500,
      };
      return {
        status: statusMap[result.error_code] ?? 500,
        body: result,
        headers: PEP_RESPONSE_HEADERS,
      };
    }

    const headers = { ...PEP_RESPONSE_HEADERS };
    if (result.audit?.processing_time_ms !== undefined) {
      headers["X-PEP-Processing-Time-Ms"] = String(result.audit.processing_time_ms);
    }

    return { status: 200, body: result, headers };
  }

  if (path === "/gauth/pep/v1/enforce/batch" && req.method === "POST") {
    const body = req.body as { requests: EnforcementRequest[]; mode: "all_or_nothing" | "independent" };
    if (!body?.requests || !Array.isArray(body.requests)) {
      return {
        status: 400,
        body: {
          error_code: "INVALID_REQUEST",
          message: "Missing required field: requests (array).",
          timestamp: new Date().toISOString(),
        },
        headers: PEP_RESPONSE_HEADERS,
      };
    }

    const result = await batchEnforce(body.requests, body.mode ?? "independent", poa, pepOptions);
    return { status: 200, body: result, headers: PEP_RESPONSE_HEADERS };
  }

  if (path === "/gauth/pep/v1/policy" && req.method === "POST") {
    if (!poa) {
      return {
        status: 400,
        body: {
          error_code: "INVALID_REQUEST",
          message: "PoA credential required for policy inspection.",
          timestamp: new Date().toISOString(),
        },
        headers: PEP_RESPONSE_HEADERS,
      };
    }
    const policy = getEnforcementPolicy(poa);
    return { status: 200, body: policy, headers: PEP_RESPONSE_HEADERS };
  }

  return {
    status: 404,
    body: { error: "Not found", path: req.path },
    headers: PEP_RESPONSE_HEADERS,
  };
}

export interface MgmtHttpRequest {
  method: string;
  path: string;
  body: unknown;
  headers: Record<string, string | undefined>;
  params?: Record<string, string>;
}

export interface MgmtHttpResponse {
  status: number;
  body: unknown;
  headers: Record<string, string>;
}

const MGMT_RESPONSE_HEADERS: Record<string, string> = {
  "Content-Type": "application/json; charset=utf-8",
  "X-GAuth-API-Version": "1.1",
};

export async function handleMgmtRequest(
  req: MgmtHttpRequest,
  api: ManagementAPI,
): Promise<MgmtHttpResponse> {
  const path = req.path.replace(/\/+$/, "");

  if (path === "/gauth/mgmt/v1/mandates" && req.method === "POST") {
    const result = await api.createMandate(req.body as Parameters<ManagementAPI["createMandate"]>[0]);
    if ("error_code" in result) {
      return { status: 422, body: result, headers: MGMT_RESPONSE_HEADERS };
    }
    return { status: 201, body: result, headers: MGMT_RESPONSE_HEADERS };
  }

  if (path.match(/^\/gauth\/mgmt\/v1\/mandates\/[^/]+$/) && req.method === "GET") {
    const mandateId = path.split("/").pop()!;
    const result = await api.getMandate(mandateId);
    if ("error_code" in result) {
      return { status: 404, body: result, headers: MGMT_RESPONSE_HEADERS };
    }
    return { status: 200, body: result, headers: MGMT_RESPONSE_HEADERS };
  }

  if (path === "/gauth/mgmt/v1/mandates" && req.method === "GET") {
    const result = await api.queryMandates(req.body as Parameters<ManagementAPI["queryMandates"]>[0] ?? {});
    return { status: 200, body: result, headers: MGMT_RESPONSE_HEADERS };
  }

  if (path.match(/^\/gauth\/mgmt\/v1\/mandates\/[^/]+\/activate$/) && req.method === "POST") {
    const mandateId = path.split("/").slice(-2)[0];
    const body = req.body as Record<string, string>;
    const result = await api.activateMandate({ mandate_id: mandateId, activated_by: body.activated_by });
    if ("error_code" in result) {
      return { status: 409, body: result, headers: MGMT_RESPONSE_HEADERS };
    }
    return { status: 200, body: result, headers: MGMT_RESPONSE_HEADERS };
  }

  if (path.match(/^\/gauth\/mgmt\/v1\/mandates\/[^/]+\/revoke$/) && req.method === "POST") {
    const mandateId = path.split("/").slice(-2)[0];
    const body = req.body as Record<string, string>;
    const result = await api.revokeMandate({ mandate_id: mandateId, revoked_by: body.revoked_by, reason: body.reason });
    if ("error_code" in result) {
      const status = (result as { error_code: string }).error_code === "MANDATE_NOT_FOUND" ? 404 : 409;
      return { status, body: result, headers: MGMT_RESPONSE_HEADERS };
    }
    return { status: 200, body: result, headers: MGMT_RESPONSE_HEADERS };
  }

  if (path.match(/^\/gauth\/mgmt\/v1\/mandates\/[^/]+\/suspend$/) && req.method === "POST") {
    const mandateId = path.split("/").slice(-2)[0];
    const body = req.body as Record<string, string>;
    const result = await api.suspendMandate({ mandate_id: mandateId, suspended_by: body.suspended_by, reason: body.reason });
    if ("error_code" in result) {
      const status = (result as { error_code: string }).error_code === "MANDATE_NOT_FOUND" ? 404 : 409;
      return { status, body: result, headers: MGMT_RESPONSE_HEADERS };
    }
    return { status: 200, body: result, headers: MGMT_RESPONSE_HEADERS };
  }

  if (path.match(/^\/gauth\/mgmt\/v1\/mandates\/[^/]+\/resume$/) && req.method === "POST") {
    const mandateId = path.split("/").slice(-2)[0];
    const body = req.body as Record<string, string>;
    const result = await api.resumeMandate({ mandate_id: mandateId, resumed_by: body.resumed_by, reason: body.reason });
    if ("error_code" in result) {
      const status = (result as { error_code: string }).error_code === "MANDATE_NOT_FOUND" ? 404 : 409;
      return { status, body: result, headers: MGMT_RESPONSE_HEADERS };
    }
    return { status: 200, body: result, headers: MGMT_RESPONSE_HEADERS };
  }

  if (path.match(/^\/gauth\/mgmt\/v1\/mandates\/[^/]+\/budget\/top-up$/) && req.method === "POST") {
    const mandateId = path.split("/").slice(-3)[0];
    const body = req.body as Record<string, unknown>;
    const result = await api.topUpBudget({
      mandate_id: mandateId,
      additional_cents: body.additional_cents as number,
      performed_by: body.performed_by as string,
    });
    if ("error_code" in result) {
      return { status: 409, body: result, headers: MGMT_RESPONSE_HEADERS };
    }
    return { status: 200, body: result, headers: MGMT_RESPONSE_HEADERS };
  }

  if (path.match(/^\/gauth\/mgmt\/v1\/mandates\/[^/]+\/ttl\/extend$/) && req.method === "POST") {
    const mandateId = path.split("/").slice(-3)[0];
    const body = req.body as Record<string, unknown>;
    const result = await api.extendTTL({
      mandate_id: mandateId,
      additional_seconds: body.additional_seconds as number,
      performed_by: body.performed_by as string,
    });
    if ("error_code" in result) {
      return { status: 409, body: result, headers: MGMT_RESPONSE_HEADERS };
    }
    return { status: 200, body: result, headers: MGMT_RESPONSE_HEADERS };
  }

  if (path.match(/^\/gauth\/mgmt\/v1\/mandates\/[^/]+\/delegate$/) && req.method === "POST") {
    const mandateId = path.split("/").slice(-2)[0];
    const body = req.body as Record<string, unknown>;
    const result = await api.createDelegation({
      parent_mandate_id: mandateId,
      delegate_agent_id: body.delegate_agent_id as string,
      scope_restriction: (body.scope_restriction ?? {}) as Parameters<ManagementAPI["createDelegation"]>[0]["scope_restriction"],
      delegated_by: body.delegated_by as string,
      max_depth: body.max_depth as number | undefined,
    });
    if ("error_code" in result) {
      return { status: 422, body: result, headers: MGMT_RESPONSE_HEADERS };
    }
    return { status: 201, body: result, headers: MGMT_RESPONSE_HEADERS };
  }

  if (path.match(/^\/gauth\/mgmt\/v1\/mandates\/[^/]+\/governance-profile$/) && req.method === "PUT") {
    const mandateId = path.split("/").slice(-2)[0];
    const body = req.body as Record<string, string>;
    const result = await api.updateGovernanceProfile(mandateId, body.governance_profile as Parameters<ManagementAPI["updateGovernanceProfile"]>[1], body.updated_by);
    if ("error_code" in result) {
      const status = (result as { error_code: string }).error_code === "MANDATE_NOT_FOUND" ? 404 : 409;
      return { status, body: result, headers: MGMT_RESPONSE_HEADERS };
    }
    return { status: 200, body: result, headers: MGMT_RESPONSE_HEADERS };
  }

  return {
    status: 404,
    body: { error: "Not found", path: req.path },
    headers: MGMT_RESPONSE_HEADERS,
  };
}
