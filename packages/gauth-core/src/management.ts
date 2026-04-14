import type {
  MandateCreationRequest,
  MandateCreationResponse,
  MandateActivationRequest,
  MandateActivationResponse,
  MandateRevocationRequest,
  MandateRevocationResponse,
  MandateSuspensionRequest,
  MandateSuspensionResponse,
  MandateResumptionRequest,
  MandateResumptionResponse,
  MandateDetail,
  MandateQueryRequest,
  MandateQueryResponse,
  BudgetTopUpRequest,
  BudgetTopUpResponse,
  BudgetConsumptionReport,
  TTLExtensionRequest,
  TTLExtensionResponse,
  DelegationRequest,
  DelegationResponse,
  ManagementError,
  MandateAuditEntry,
  MandateStore,
  GovernanceProfile,
  GovernanceProfileCeiling,
  PoAScope,
  PoaMapSummary,
} from "./types.js";
import {
  MGMT_ERROR_CODES,
  TERMINAL_STATES,
  DEFAULT_GOVERNANCE_CEILINGS,
  PoACredential,
} from "./types.js";
import {
  computeScopeChecksum,
  computeToolPermissionsHash,
  computePlatformPermissionsHash,
} from "./crypto.js";

export class ManagementAPI {
  private store: MandateStore;
  private ceilings: Record<GovernanceProfile, GovernanceProfileCeiling>;

  constructor(store: MandateStore, ceilings?: Record<GovernanceProfile, GovernanceProfileCeiling>) {
    this.store = store;
    this.ceilings = ceilings ?? DEFAULT_GOVERNANCE_CEILINGS;
  }

  async createMandate(request: MandateCreationRequest): Promise<MandateCreationResponse | ManagementError> {
    const validation = this.validateMandateRequest(request);
    if (!validation.accepted) {
      return {
        error_code: MGMT_ERROR_CODES.VALIDATION_FAILED,
        message: "Mandate validation failed.",
        timestamp: new Date().toISOString(),
        detail: {
          schema_errors: validation.schema_errors,
          ceiling_violations: validation.ceiling_violations,
          consistency_errors: validation.consistency_errors,
        },
      };
    }

    const mandateId = `mdt_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
    const now = new Date().toISOString();

    const toolPermissionsHash = await computeToolPermissionsHash(request.scope.core_verbs);
    const platformPermissionsHash = await computePlatformPermissionsHash(
      request.scope.platform_permissions as Record<string, unknown> | undefined,
    );
    const scopeChecksum = await computeScopeChecksum({
      governance_profile: request.scope.governance_profile,
      phase: request.scope.phase,
      allowed_paths: request.scope.allowed_paths,
      denied_paths: request.scope.denied_paths,
      allowed_regions: request.scope.allowed_regions,
      allowed_sectors: request.scope.allowed_sectors,
      active_modules: request.scope.active_modules,
      tool_permissions_hash: toolPermissionsHash,
      platform_permissions_hash: platformPermissionsHash,
    });

    const auditEntry: MandateAuditEntry = {
      operation: "CREATE",
      performed_by: request.parties.issued_by,
      timestamp: now,
      mandate_id: mandateId,
    };

    const mandate: MandateDetail = {
      mandate_id: mandateId,
      status: "DRAFT",
      parties: {
        issuer: "https://gimelfoundation.com/gauth",
        subject: request.parties.subject,
        customer_id: request.parties.customer_id,
        project_id: request.parties.project_id,
        issued_by: request.parties.issued_by,
        approval_chain: request.parties.approval_chain,
      },
      scope: request.scope,
      requirements: {
        approval_mode: request.requirements.approval_mode,
        budget: { total_cents: request.requirements.budget.total_cents, remaining_cents: request.requirements.budget.total_cents },
        ttl_seconds: request.requirements.ttl_seconds,
        session_limits: request.requirements.session_limits,
      },
      scope_checksum: scopeChecksum,
      tool_permissions_hash: toolPermissionsHash,
      platform_permissions_hash: platformPermissionsHash,
      delegation_chain: [],
      created_at: now,
      budget_consumed_cents: 0,
      audit_trail: [auditEntry],
    };

    await this.store.create(mandate);

    return {
      mandate_id: mandateId,
      status: "DRAFT",
      scope_checksum: scopeChecksum,
      tool_permissions_hash: toolPermissionsHash,
      platform_permissions_hash: platformPermissionsHash,
      created_at: now,
      validation: {
        accepted: true,
        schema_errors: [],
        ceiling_violations: [],
        consistency_errors: [],
      },
      audit: auditEntry,
    };
  }

  async activateMandate(request: MandateActivationRequest): Promise<MandateActivationResponse | ManagementError> {
    const mandate = await this.store.get(request.mandate_id);
    if (!mandate) {
      return this.notFound(request.mandate_id);
    }

    if (mandate.status !== "DRAFT") {
      return this.invalidTransition(request.mandate_id, mandate.status, "ACTIVE");
    }

    const existing = await this.store.findActive(mandate.parties.subject, mandate.parties.project_id);
    let supersededId: string | null = null;
    if (existing && existing.mandate_id !== mandate.mandate_id) {
      existing.status = "SUPERSEDED";
      existing.audit_trail.push({
        operation: "SUPERSEDE",
        performed_by: request.activated_by,
        timestamp: new Date().toISOString(),
        mandate_id: existing.mandate_id,
      });
      await this.store.update(existing);
      supersededId = existing.mandate_id;
    }

    const now = new Date().toISOString();
    const ttlSeconds = mandate.requirements.ttl_seconds ?? 3600;
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();

    mandate.status = "ACTIVE";
    mandate.activated_at = now;
    mandate.expires_at = expiresAt;

    const auditEntry: MandateAuditEntry = {
      operation: "ACTIVATE",
      performed_by: request.activated_by,
      timestamp: now,
      mandate_id: mandate.mandate_id,
    };
    mandate.audit_trail.push(auditEntry);
    await this.store.update(mandate);

    return {
      mandate_id: mandate.mandate_id,
      status: "ACTIVE",
      activated_at: now,
      expires_at: expiresAt,
      superseded_mandate_id: supersededId,
      audit: auditEntry,
    };
  }

  async revokeMandate(request: MandateRevocationRequest): Promise<MandateRevocationResponse | ManagementError> {
    const mandate = await this.store.get(request.mandate_id);
    if (!mandate) return this.notFound(request.mandate_id);

    if (mandate.status !== "ACTIVE" && mandate.status !== "SUSPENDED") {
      return this.invalidTransition(request.mandate_id, mandate.status, "REVOKED");
    }

    if (!this.hasAuthority(request.revoked_by, mandate)) {
      return {
        error_code: MGMT_ERROR_CODES.INSUFFICIENT_AUTHORITY,
        message: `User '${request.revoked_by}' does not have revocation authority.`,
        timestamp: new Date().toISOString(),
        mandate_id: request.mandate_id,
      };
    }

    const now = new Date().toISOString();
    mandate.status = "REVOKED";
    mandate.revoked_at = now;

    const auditEntry: MandateAuditEntry = {
      operation: "REVOKE",
      performed_by: request.revoked_by,
      timestamp: now,
      mandate_id: mandate.mandate_id,
      reason: request.reason,
    };
    mandate.audit_trail.push(auditEntry);
    await this.store.update(mandate);

    return {
      mandate_id: mandate.mandate_id,
      status: "REVOKED",
      revoked_at: now,
      revoked_by: request.revoked_by,
      reason: request.reason,
      cascaded_revocations: [],
      audit: auditEntry,
    };
  }

  async suspendMandate(request: MandateSuspensionRequest): Promise<MandateSuspensionResponse | ManagementError> {
    const mandate = await this.store.get(request.mandate_id);
    if (!mandate) return this.notFound(request.mandate_id);

    if (mandate.status !== "ACTIVE") {
      return this.invalidTransition(request.mandate_id, mandate.status, "SUSPENDED");
    }

    if (!this.hasAuthority(request.suspended_by, mandate)) {
      return {
        error_code: MGMT_ERROR_CODES.INSUFFICIENT_AUTHORITY,
        message: `User '${request.suspended_by}' does not have suspension authority.`,
        timestamp: new Date().toISOString(),
        mandate_id: request.mandate_id,
      };
    }

    const now = new Date().toISOString();
    mandate.status = "SUSPENDED";
    mandate.suspended_at = now;

    const auditEntry: MandateAuditEntry = {
      operation: "SUSPEND",
      performed_by: request.suspended_by,
      timestamp: now,
      mandate_id: mandate.mandate_id,
      reason: request.reason,
    };
    mandate.audit_trail.push(auditEntry);
    await this.store.update(mandate);

    return {
      mandate_id: mandate.mandate_id,
      status: "SUSPENDED",
      suspended_at: now,
      suspended_by: request.suspended_by,
      reason: request.reason,
      cascaded_suspensions: [],
      audit: auditEntry,
    };
  }

  async resumeMandate(request: MandateResumptionRequest): Promise<MandateResumptionResponse | ManagementError> {
    const mandate = await this.store.get(request.mandate_id);
    if (!mandate) return this.notFound(request.mandate_id);

    if (mandate.status !== "SUSPENDED") {
      return this.invalidTransition(request.mandate_id, mandate.status, "ACTIVE");
    }

    if (mandate.expires_at && new Date(mandate.expires_at) < new Date()) {
      mandate.status = "EXPIRED";
      await this.store.update(mandate);
      return {
        error_code: MGMT_ERROR_CODES.MANDATE_EXPIRED,
        message: "Mandate has expired during suspension.",
        timestamp: new Date().toISOString(),
        mandate_id: request.mandate_id,
      };
    }

    if (!this.hasAuthority(request.resumed_by, mandate)) {
      return {
        error_code: MGMT_ERROR_CODES.INSUFFICIENT_AUTHORITY,
        message: `User '${request.resumed_by}' does not have resumption authority.`,
        timestamp: new Date().toISOString(),
        mandate_id: request.mandate_id,
      };
    }

    const now = new Date().toISOString();
    mandate.status = "ACTIVE";

    const remainingTtl = mandate.expires_at
      ? Math.max(0, Math.floor((new Date(mandate.expires_at).getTime() - Date.now()) / 1000))
      : 0;

    const auditEntry: MandateAuditEntry = {
      operation: "RESUME",
      performed_by: request.resumed_by,
      timestamp: now,
      mandate_id: mandate.mandate_id,
      reason: request.reason,
    };
    mandate.audit_trail.push(auditEntry);
    await this.store.update(mandate);

    return {
      mandate_id: mandate.mandate_id,
      status: "ACTIVE",
      resumed_at: now,
      resumed_by: request.resumed_by,
      remaining_ttl_seconds: remainingTtl,
      audit: auditEntry,
    };
  }

  async getMandate(mandateId: string): Promise<MandateDetail | ManagementError> {
    const mandate = await this.store.get(mandateId);
    if (!mandate) return this.notFound(mandateId);
    return mandate;
  }

  async queryMandates(query: MandateQueryRequest): Promise<MandateQueryResponse> {
    return this.store.query(query);
  }

  async topUpBudget(request: BudgetTopUpRequest): Promise<BudgetTopUpResponse | ManagementError> {
    const mandate = await this.store.get(request.mandate_id);
    if (!mandate) return this.notFound(request.mandate_id);

    if (mandate.status !== "ACTIVE" && mandate.status !== "SUSPENDED") {
      return {
        error_code: MGMT_ERROR_CODES.INVALID_STATE_TRANSITION,
        message: "Budget can only be increased on ACTIVE or SUSPENDED mandates.",
        timestamp: new Date().toISOString(),
        mandate_id: request.mandate_id,
      };
    }

    if (request.additional_cents <= 0) {
      return {
        error_code: MGMT_ERROR_CODES.BUDGET_DECREASE_DENIED,
        message: "Budget top-up must be positive (additive-only).",
        timestamp: new Date().toISOString(),
        mandate_id: request.mandate_id,
      };
    }

    const prevTotal = mandate.requirements.budget?.total_cents ?? 0;
    const prevRemaining = mandate.requirements.budget?.remaining_cents ?? 0;
    const newTotal = prevTotal + request.additional_cents;
    const newRemaining = prevRemaining + request.additional_cents;

    const ceiling = this.ceilings[mandate.scope.governance_profile];
    if (ceiling && newTotal > ceiling.max_budget_cents) {
      return {
        error_code: MGMT_ERROR_CODES.CEILING_VIOLATION,
        message: `Budget top-up would exceed governance ceiling (${ceiling.max_budget_cents} cents) for profile '${mandate.scope.governance_profile}'.`,
        timestamp: new Date().toISOString(),
        mandate_id: request.mandate_id,
      };
    }

    mandate.requirements.budget = { total_cents: newTotal, remaining_cents: newRemaining };

    const auditEntry: MandateAuditEntry = {
      operation: "BUDGET_TOP_UP",
      performed_by: request.performed_by,
      timestamp: new Date().toISOString(),
      mandate_id: mandate.mandate_id,
    };
    mandate.audit_trail.push(auditEntry);
    await this.store.update(mandate);

    return {
      mandate_id: mandate.mandate_id,
      previous_total_cents: prevTotal,
      new_total_cents: newTotal,
      remaining_cents: newRemaining,
      audit: auditEntry,
    };
  }

  async reportConsumption(report: BudgetConsumptionReport): Promise<void> {
    const mandate = await this.store.get(report.mandate_id);
    if (!mandate || mandate.status !== "ACTIVE") return;

    const remaining = (mandate.requirements.budget?.remaining_cents ?? 0) - report.amount_cents;
    if (mandate.requirements.budget) {
      mandate.requirements.budget.remaining_cents = Math.max(0, remaining);
    }
    mandate.budget_consumed_cents += report.amount_cents;

    if (remaining <= 0) {
      mandate.status = "BUDGET_EXCEEDED";
      mandate.audit_trail.push({
        operation: "BUDGET_EXHAUSTED",
        performed_by: "system",
        timestamp: new Date().toISOString(),
        mandate_id: mandate.mandate_id,
      });
    }

    await this.store.update(mandate);
  }

  async extendTTL(request: TTLExtensionRequest): Promise<TTLExtensionResponse | ManagementError> {
    const mandate = await this.store.get(request.mandate_id);
    if (!mandate) return this.notFound(request.mandate_id);

    if (mandate.status !== "ACTIVE" && mandate.status !== "SUSPENDED") {
      return {
        error_code: MGMT_ERROR_CODES.INVALID_STATE_TRANSITION,
        message: "TTL can only be extended on ACTIVE or SUSPENDED mandates.",
        timestamp: new Date().toISOString(),
        mandate_id: request.mandate_id,
      };
    }

    if (request.additional_seconds <= 0) {
      return {
        error_code: MGMT_ERROR_CODES.TTL_DECREASE_DENIED,
        message: "TTL extension must be positive (additive-only).",
        timestamp: new Date().toISOString(),
        mandate_id: request.mandate_id,
      };
    }

    const prevTtl = mandate.requirements.ttl_seconds ?? 0;
    const newTtl = prevTtl + request.additional_seconds;

    const ceiling = this.ceilings[mandate.scope.governance_profile];
    if (ceiling && newTtl > ceiling.max_ttl_seconds) {
      return {
        error_code: MGMT_ERROR_CODES.CEILING_VIOLATION,
        message: `TTL extension would exceed governance ceiling (${ceiling.max_ttl_seconds}s) for profile '${mandate.scope.governance_profile}'.`,
        timestamp: new Date().toISOString(),
        mandate_id: request.mandate_id,
      };
    }

    mandate.requirements.ttl_seconds = newTtl;

    if (mandate.expires_at) {
      const newExpires = new Date(new Date(mandate.expires_at).getTime() + request.additional_seconds * 1000);
      mandate.expires_at = newExpires.toISOString();
    }

    const auditEntry: MandateAuditEntry = {
      operation: "TTL_EXTEND",
      performed_by: request.performed_by,
      timestamp: new Date().toISOString(),
      mandate_id: mandate.mandate_id,
    };
    mandate.audit_trail.push(auditEntry);
    await this.store.update(mandate);

    return {
      mandate_id: mandate.mandate_id,
      previous_ttl_seconds: prevTtl,
      new_ttl_seconds: newTtl,
      new_expires_at: mandate.expires_at ?? "",
      audit: auditEntry,
    };
  }

  private checkConstraintSubset(
    parentConstraints: Record<string, unknown>,
    childConstraints: Record<string, unknown>,
    verb: string,
  ): string | null {
    for (const [key, childVal] of Object.entries(childConstraints)) {
      const parentVal = parentConstraints[key];
      if (parentVal === undefined) continue;

      if (typeof childVal === "number" && typeof parentVal === "number") {
        if (childVal > parentVal) {
          return `verb '${verb}' constraint '${key}' exceeds parent (${childVal} > ${parentVal}).`;
        }
      } else if (typeof childVal === "boolean" && typeof parentVal === "boolean") {
        if (childVal === true && parentVal === false) {
          return `verb '${verb}' constraint '${key}' escalates from false to true.`;
        }
      } else if (Array.isArray(childVal) && Array.isArray(parentVal)) {
        for (const item of childVal) {
          if (!parentVal.includes(item)) {
            return `verb '${verb}' constraint '${key}' contains '${item}' not in parent.`;
          }
        }
      }
    }
    return null;
  }

  private checkPlatformPermSubset(
    parentPerms: Record<string, unknown>,
    childPerms: Record<string, unknown>,
    path: string,
  ): string | null {
    for (const [key, childVal] of Object.entries(childPerms)) {
      const fullKey = path ? `${path}.${key}` : key;
      if (!(key in parentPerms)) {
        return `platform_permission '${fullKey}' is not present in parent.`;
      }
      const parentVal = parentPerms[key];

      if (typeof childVal !== typeof parentVal || Array.isArray(childVal) !== Array.isArray(parentVal)) {
        return `platform_permission '${fullKey}' type mismatch with parent (fail-closed).`;
      }

      if (typeof childVal === "boolean" && typeof parentVal === "boolean") {
        if (childVal === true && parentVal === false) {
          return `platform_permission '${fullKey}' escalates from false to true.`;
        }
      } else if (typeof childVal === "number" && typeof parentVal === "number") {
        if (childVal > parentVal) {
          return `platform_permission '${fullKey}' exceeds parent value (${childVal} > ${parentVal}).`;
        }
      } else if (Array.isArray(childVal) && Array.isArray(parentVal)) {
        for (const item of childVal) {
          if (!parentVal.includes(item)) {
            return `platform_permission '${fullKey}' contains '${item}' not in parent.`;
          }
        }
      } else if (
        typeof childVal === "object" && childVal !== null && !Array.isArray(childVal) &&
        typeof parentVal === "object" && parentVal !== null && !Array.isArray(parentVal)
      ) {
        const nested = this.checkPlatformPermSubset(
          parentVal as Record<string, unknown>,
          childVal as Record<string, unknown>,
          fullKey,
        );
        if (nested) return nested;
      }
    }
    return null;
  }

  private validateDelegationSubset(
    parent: MandateDetail,
    request: DelegationRequest,
  ): ManagementError | null {
    const restriction = request.scope_restriction;
    const makeError = (msg: string): ManagementError => ({
      error_code: MGMT_ERROR_CODES.VALIDATION_FAILED,
      message: `Delegation scope escalation: ${msg}`,
      timestamp: new Date().toISOString(),
      mandate_id: request.parent_mandate_id,
    });

    const GOVERNANCE_STRICTNESS: Record<string, number> = {
      minimal: 0,
      standard: 1,
      strict: 2,
      enterprise: 3,
      behoerde: 4,
    };

    if (restriction.governance_profile) {
      const parentLevel = GOVERNANCE_STRICTNESS[parent.scope.governance_profile] ?? 0;
      const childLevel = GOVERNANCE_STRICTNESS[restriction.governance_profile] ?? 0;
      if (childLevel < parentLevel) {
        return makeError(
          `governance_profile '${restriction.governance_profile}' is less restrictive than parent '${parent.scope.governance_profile}'.`,
        );
      }
    }

    const PHASE_BREADTH: Record<string, number> = { plan: 0, build: 1, run: 2 };
    if (restriction.phase) {
      const parentBreadth = PHASE_BREADTH[parent.scope.phase] ?? 0;
      const childBreadth = PHASE_BREADTH[restriction.phase] ?? 0;
      if (childBreadth > parentBreadth) {
        return makeError(
          `phase '${restriction.phase}' is broader than parent phase '${parent.scope.phase}'.`,
        );
      }
    }

    if (restriction.core_verbs) {
      for (const [verb, policy] of Object.entries(restriction.core_verbs)) {
        const parentPolicy = parent.scope.core_verbs[verb];
        if (!parentPolicy || !parentPolicy.allowed) {
          return makeError(`verb '${verb}' is not allowed in parent mandate.`);
        }
        if (policy.allowed && !parentPolicy.allowed) {
          return makeError(`verb '${verb}' cannot be enabled when disabled in parent.`);
        }
        if (policy.constraints && parentPolicy.constraints) {
          const constraintCheck = this.checkConstraintSubset(
            parentPolicy.constraints as Record<string, unknown>,
            policy.constraints as Record<string, unknown>,
            verb,
          );
          if (constraintCheck) return makeError(constraintCheck);
        }
      }
    }

    if (restriction.allowed_paths && parent.scope.allowed_paths) {
      for (const childPath of restriction.allowed_paths) {
        const isSubset = parent.scope.allowed_paths.some(
          (pp) => childPath === pp || childPath.startsWith(pp.endsWith("/") ? pp : pp + "/"),
        );
        if (!isSubset) {
          return makeError(`allowed_path '${childPath}' is not a subset of parent allowed_paths.`);
        }
      }
    }

    if (restriction.allowed_regions && parent.scope.allowed_regions) {
      for (const region of restriction.allowed_regions) {
        if (!parent.scope.allowed_regions.includes(region)) {
          return makeError(`region '${region}' is not in parent allowed_regions.`);
        }
      }
    }

    if (restriction.allowed_sectors && parent.scope.allowed_sectors) {
      for (const sector of restriction.allowed_sectors) {
        if (!parent.scope.allowed_sectors.includes(sector)) {
          return makeError(`sector '${sector}' is not in parent allowed_sectors.`);
        }
      }
    }

    if (restriction.platform_permissions && parent.scope.platform_permissions) {
      const escalation = this.checkPlatformPermSubset(
        parent.scope.platform_permissions as Record<string, unknown>,
        restriction.platform_permissions as Record<string, unknown>,
        "",
      );
      if (escalation) {
        return makeError(escalation);
      }
    }

    return null;
  }

  async createDelegation(request: DelegationRequest): Promise<DelegationResponse | ManagementError> {
    const parent = await this.store.get(request.parent_mandate_id);
    if (!parent) return this.notFound(request.parent_mandate_id);

    if (parent.status !== "ACTIVE") {
      return {
        error_code: MGMT_ERROR_CODES.INVALID_STATE_TRANSITION,
        message: "Delegation can only be created from an ACTIVE mandate.",
        timestamp: new Date().toISOString(),
        mandate_id: request.parent_mandate_id,
      };
    }

    const delegateVerb = parent.scope.core_verbs["foundry.agent.delegate"];
    if (!delegateVerb || !delegateVerb.allowed) {
      return {
        error_code: MGMT_ERROR_CODES.INSUFFICIENT_AUTHORITY,
        message: "Parent mandate does not allow delegation.",
        timestamp: new Date().toISOString(),
        mandate_id: request.parent_mandate_id,
      };
    }

    const maxDepth = delegateVerb.constraints?.max_delegation_depth ?? 0;
    const currentDepth = parent.delegation_chain.length;
    if (currentDepth >= maxDepth) {
      return {
        error_code: MGMT_ERROR_CODES.VALIDATION_FAILED,
        message: `Delegation depth ${currentDepth + 1} exceeds maximum ${maxDepth}.`,
        timestamp: new Date().toISOString(),
        mandate_id: request.parent_mandate_id,
      };
    }

    if (!this.hasAuthority(request.delegated_by, parent)) {
      return {
        error_code: MGMT_ERROR_CODES.INSUFFICIENT_AUTHORITY,
        message: `User '${request.delegated_by}' does not have delegation authority.`,
        timestamp: new Date().toISOString(),
        mandate_id: request.parent_mandate_id,
      };
    }

    const childId = `mdt_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
    const now = new Date().toISOString();

    const escalationError = this.validateDelegationSubset(parent, request);
    if (escalationError) return escalationError;

    const approvalMode = parent.requirements.approval_mode;
    let childStatus: "DRAFT" | "PENDING_APPROVAL" = "DRAFT";
    if (approvalMode === "supervised" || approvalMode === "four-eyes") {
      childStatus = "PENDING_APPROVAL";
    }

    const childVerbs: Record<string, import("./types.js").ToolPolicy> = {};
    const restrictionVerbs = request.scope_restriction.core_verbs;
    if (restrictionVerbs) {
      for (const [verb, policy] of Object.entries(restrictionVerbs)) {
        childVerbs[verb] = policy;
      }
    } else {
      Object.assign(childVerbs, parent.scope.core_verbs);
    }

    const childScope: PoAScope = {
      governance_profile: request.scope_restriction.governance_profile ?? parent.scope.governance_profile,
      phase: request.scope_restriction.phase ?? parent.scope.phase,
      core_verbs: childVerbs,
      active_modules: request.scope_restriction.active_modules ?? parent.scope.active_modules,
      allowed_paths: request.scope_restriction.allowed_paths ?? parent.scope.allowed_paths,
      denied_paths: [
        ...(parent.scope.denied_paths ?? []),
        ...(request.scope_restriction.denied_paths ?? []),
      ],
      allowed_sectors: request.scope_restriction.allowed_sectors ?? parent.scope.allowed_sectors,
      allowed_regions: request.scope_restriction.allowed_regions ?? parent.scope.allowed_regions,
      platform_permissions: request.scope_restriction.platform_permissions ?? parent.scope.platform_permissions,
    };

    const scopeChecksum = await computeScopeChecksum({
      governance_profile: childScope.governance_profile,
      phase: childScope.phase,
      allowed_paths: childScope.allowed_paths,
      denied_paths: childScope.denied_paths,
      allowed_regions: childScope.allowed_regions,
      allowed_sectors: childScope.allowed_sectors,
      active_modules: childScope.active_modules,
      tool_permissions_hash: await computeToolPermissionsHash(childScope.core_verbs),
      platform_permissions_hash: await computePlatformPermissionsHash(
        childScope.platform_permissions as Record<string, unknown> | undefined,
      ),
    });

    const auditEntry: MandateAuditEntry = {
      operation: "DELEGATE",
      performed_by: request.delegated_by,
      timestamp: now,
      mandate_id: childId,
    };

    const childMandate: MandateDetail = {
      mandate_id: childId,
      status: childStatus,
      parties: {
        ...parent.parties,
        subject: request.delegate_agent_id,
      },
      scope: childScope,
      requirements: parent.requirements,
      scope_checksum: scopeChecksum,
      tool_permissions_hash: await computeToolPermissionsHash(childScope.core_verbs),
      platform_permissions_hash: await computePlatformPermissionsHash(
        childScope.platform_permissions as Record<string, unknown> | undefined,
      ),
      delegation_chain: [
        ...parent.delegation_chain,
        {
          delegator: parent.parties.subject,
          delegate: request.delegate_agent_id,
          scope_restriction: request.scope_restriction as Record<string, unknown>,
          delegated_at: now,
          max_depth_remaining: maxDepth - currentDepth - 1,
        },
      ],
      created_at: now,
      budget_consumed_cents: 0,
      audit_trail: [auditEntry],
    };

    await this.store.create(childMandate);

    return {
      child_mandate_id: childId,
      parent_mandate_id: request.parent_mandate_id,
      status: childStatus,
      delegation_depth: currentDepth + 1,
      scope_checksum: scopeChecksum,
      audit: auditEntry,
    };
  }

  async approveDelegation(
    mandateId: string,
    approvedBy: string,
  ): Promise<{ mandate_id: string; status: "DRAFT"; audit: MandateAuditEntry } | ManagementError> {
    const mandate = await this.store.get(mandateId);
    if (!mandate) return this.notFound(mandateId);

    if (mandate.status !== "PENDING_APPROVAL") {
      return this.invalidTransition(mandateId, mandate.status, "DRAFT");
    }

    if (!this.hasAuthority(approvedBy, mandate)) {
      return {
        error_code: MGMT_ERROR_CODES.INSUFFICIENT_AUTHORITY,
        message: `User '${approvedBy}' does not have approval authority.`,
        timestamp: new Date().toISOString(),
        mandate_id: mandateId,
      };
    }

    if (mandate.requirements.approval_mode === "four-eyes") {
      const delegateEntry = mandate.audit_trail.find((e) => e.operation === "DELEGATE");
      if (delegateEntry && delegateEntry.performed_by === approvedBy) {
        return {
          error_code: MGMT_ERROR_CODES.INSUFFICIENT_AUTHORITY,
          message: "Four-eyes mode: approver must differ from the delegator.",
          timestamp: new Date().toISOString(),
          mandate_id: mandateId,
        };
      }
    }

    mandate.status = "DRAFT";
    const auditEntry: MandateAuditEntry = {
      operation: "APPROVE_DELEGATION",
      performed_by: approvedBy,
      timestamp: new Date().toISOString(),
      mandate_id: mandateId,
    };
    mandate.audit_trail.push(auditEntry);
    await this.store.update(mandate);

    return { mandate_id: mandateId, status: "DRAFT", audit: auditEntry };
  }

  async generatePoaMap(mandateId: string): Promise<PoaMapSummary | ManagementError> {
    const mandate = await this.store.get(mandateId);
    if (!mandate) return this.notFound(mandateId);

    const allowedVerbs: string[] = [];
    const deniedVerbs: string[] = [];
    const effectiveConstraints: Record<string, Record<string, unknown>> = {};

    for (const [verb, policy] of Object.entries(mandate.scope.core_verbs)) {
      if (policy.allowed) {
        allowedVerbs.push(verb);
        if (policy.constraints) {
          effectiveConstraints[verb] = policy.constraints as Record<string, unknown>;
        }
      } else {
        deniedVerbs.push(verb);
      }
    }

    const delegatePolicy = mandate.scope.core_verbs["foundry.agent.delegate"];
    const maxDelegationDepth = delegatePolicy?.constraints?.max_delegation_depth ?? 0;

    const platformPermsSummary: Record<string, boolean> = {};
    if (mandate.scope.platform_permissions) {
      const pp = mandate.scope.platform_permissions;
      if (pp.deployment) {
        platformPermsSummary["deployment.auto_deploy"] = pp.deployment.auto_deploy ?? false;
      }
      if (pp.database) {
        platformPermsSummary["database.read"] = pp.database.read ?? false;
        platformPermsSummary["database.write"] = pp.database.write ?? false;
        platformPermsSummary["database.migrate"] = pp.database.migrate ?? false;
        platformPermsSummary["database.production_access"] = pp.database.production_access ?? false;
      }
      if (pp.secrets) {
        platformPermsSummary["secrets.read"] = pp.secrets.read ?? false;
        platformPermsSummary["secrets.create"] = pp.secrets.create ?? false;
      }
    }

    return {
      mandate_id: mandate.mandate_id,
      subject: mandate.parties.subject,
      governance_profile: mandate.scope.governance_profile,
      phase: mandate.scope.phase,
      allowed_verbs: allowedVerbs,
      denied_verbs: deniedVerbs,
      allowed_paths: mandate.scope.allowed_paths ?? [],
      denied_paths: mandate.scope.denied_paths ?? [],
      allowed_regions: mandate.scope.allowed_regions ?? [],
      allowed_sectors: mandate.scope.allowed_sectors ?? [],
      budget: mandate.requirements.budget
        ? { total_cents: mandate.requirements.budget.total_cents, remaining_cents: mandate.requirements.budget.remaining_cents ?? mandate.requirements.budget.total_cents }
        : null,
      ttl_seconds: mandate.requirements.ttl_seconds ?? null,
      delegation_depth: mandate.delegation_chain.length,
      max_delegation_depth: maxDelegationDepth,
      approval_mode: mandate.requirements.approval_mode,
      platform_permissions_summary: platformPermsSummary,
      effective_constraints: effectiveConstraints,
      generated_at: new Date().toISOString(),
    };
  }

  private validateMandateRequest(request: MandateCreationRequest): {
    accepted: boolean;
    schema_errors: Array<{ path: string; message: string }>;
    ceiling_violations: Array<{ field: string; ceiling: unknown; requested: unknown }>;
    consistency_errors: Array<{ rule: string; message: string }>;
  } {
    const schemaErrors: Array<{ path: string; message: string }> = [];
    const ceilingViolations: Array<{ field: string; ceiling: unknown; requested: unknown }> = [];
    const consistencyErrors: Array<{ rule: string; message: string }> = [];

    if (!request.parties?.subject) schemaErrors.push({ path: "parties.subject", message: "Subject is required." });
    if (!request.parties?.customer_id) schemaErrors.push({ path: "parties.customer_id", message: "Customer ID is required." });
    if (!request.parties?.project_id) schemaErrors.push({ path: "parties.project_id", message: "Project ID is required." });
    if (!request.parties?.issued_by) schemaErrors.push({ path: "parties.issued_by", message: "Issued by is required." });

    if (!request.scope?.governance_profile) schemaErrors.push({ path: "scope.governance_profile", message: "Governance profile is required." });
    if (!request.scope?.phase) schemaErrors.push({ path: "scope.phase", message: "Phase is required." });
    if (!request.scope?.core_verbs || Object.keys(request.scope.core_verbs).length === 0) {
      schemaErrors.push({ path: "scope.core_verbs", message: "At least one core verb is required." });
    }

    if (!request.requirements?.approval_mode) schemaErrors.push({ path: "requirements.approval_mode", message: "Approval mode is required." });
    if (!request.requirements?.budget || request.requirements.budget.total_cents === undefined) {
      schemaErrors.push({ path: "requirements.budget.total_cents", message: "Budget total_cents is required." });
    }
    if (!request.requirements?.ttl_seconds || request.requirements.ttl_seconds < 60) {
      schemaErrors.push({ path: "requirements.ttl_seconds", message: "TTL must be at least 60 seconds." });
    }

    if (schemaErrors.length > 0) {
      return { accepted: false, schema_errors: schemaErrors, ceiling_violations: [], consistency_errors: [] };
    }

    const ceiling = this.ceilings[request.scope.governance_profile];
    if (ceiling) {
      if (request.requirements.ttl_seconds > ceiling.max_ttl_seconds) {
        ceilingViolations.push({ field: "ttl_seconds", ceiling: ceiling.max_ttl_seconds, requested: request.requirements.ttl_seconds });
      }
      if (request.requirements.budget.total_cents > ceiling.max_budget_cents) {
        ceilingViolations.push({ field: "budget.total_cents", ceiling: ceiling.max_budget_cents, requested: request.requirements.budget.total_cents });
      }
      if (!ceiling.allowed_phases.includes(request.scope.phase)) {
        ceilingViolations.push({ field: "phase", ceiling: ceiling.allowed_phases, requested: request.scope.phase });
      }
      if (!ceiling.allowed_approval_modes.includes(request.requirements.approval_mode)) {
        ceilingViolations.push({ field: "approval_mode", ceiling: ceiling.allowed_approval_modes, requested: request.requirements.approval_mode });
      }
    }

    if (request.requirements.approval_mode === "four-eyes" && (!request.parties.approval_chain || request.parties.approval_chain.length < 2)) {
      consistencyErrors.push({ rule: "FOUR_EYES_REQUIRES_CHAIN", message: "Four-eyes approval mode requires at least 2 members in approval_chain." });
    }

    const accepted = ceilingViolations.length === 0 && consistencyErrors.length === 0;
    return { accepted, schema_errors: schemaErrors, ceiling_violations: ceilingViolations, consistency_errors: consistencyErrors };
  }

  private hasAuthority(userId: string, mandate: MandateDetail): boolean {
    if (mandate.parties.issued_by === userId) return true;
    if (mandate.parties.approval_chain?.includes(userId)) return true;
    return false;
  }

  private notFound(mandateId: string): ManagementError {
    return {
      error_code: MGMT_ERROR_CODES.MANDATE_NOT_FOUND,
      message: `Mandate '${mandateId}' not found.`,
      timestamp: new Date().toISOString(),
      mandate_id: mandateId,
    };
  }

  async updateGovernanceProfile(
    mandateId: string,
    newProfile: GovernanceProfile,
    updatedBy: string,
  ): Promise<{ mandate_id: string; previous_profile: GovernanceProfile; new_profile: GovernanceProfile; audit: MandateAuditEntry } | ManagementError> {
    const mandate = await this.store.get(mandateId);
    if (!mandate) return this.notFound(mandateId);

    if (mandate.status !== "DRAFT") {
      return {
        error_code: MGMT_ERROR_CODES.INVALID_STATE_TRANSITION,
        message: "Governance profile can only be changed on DRAFT mandates (scope is immutable once ACTIVE).",
        timestamp: new Date().toISOString(),
        mandate_id: mandateId,
      };
    }

    const GOVERNANCE_STRICTNESS: Record<string, number> = {
      minimal: 0, standard: 1, strict: 2, enterprise: 3, behoerde: 4,
    };
    const currentLevel = GOVERNANCE_STRICTNESS[mandate.scope.governance_profile] ?? 0;
    const newLevel = GOVERNANCE_STRICTNESS[newProfile] ?? 0;
    if (newLevel < currentLevel) {
      return {
        error_code: MGMT_ERROR_CODES.VALIDATION_FAILED,
        message: `Cannot relax governance profile from '${mandate.scope.governance_profile}' to '${newProfile}'. Only tightening is allowed.`,
        timestamp: new Date().toISOString(),
        mandate_id: mandateId,
      };
    }

    const previousProfile = mandate.scope.governance_profile;
    mandate.scope.governance_profile = newProfile;

    const ceiling = this.ceilings[newProfile];
    if (ceiling) {
      if (mandate.requirements.budget && mandate.requirements.budget.total_cents > ceiling.max_budget_cents) {
        mandate.requirements.budget.total_cents = ceiling.max_budget_cents;
        if (mandate.requirements.budget.remaining_cents !== undefined) {
          mandate.requirements.budget.remaining_cents = Math.min(
            mandate.requirements.budget.remaining_cents,
            ceiling.max_budget_cents,
          );
        }
      }
    }

    const toolPermissionsHash = await computeToolPermissionsHash(mandate.scope.core_verbs);
    const platformPermissionsHash = await computePlatformPermissionsHash(
      mandate.scope.platform_permissions as Record<string, unknown> | undefined,
    );
    mandate.scope_checksum = await computeScopeChecksum({
      governance_profile: mandate.scope.governance_profile,
      phase: mandate.scope.phase,
      allowed_paths: mandate.scope.allowed_paths,
      denied_paths: mandate.scope.denied_paths,
      allowed_regions: mandate.scope.allowed_regions,
      allowed_sectors: mandate.scope.allowed_sectors,
      active_modules: mandate.scope.active_modules,
      tool_permissions_hash: toolPermissionsHash,
      platform_permissions_hash: platformPermissionsHash,
    });
    mandate.tool_permissions_hash = toolPermissionsHash;
    mandate.platform_permissions_hash = platformPermissionsHash;

    const auditEntry: MandateAuditEntry = {
      operation: "UPDATE_GOVERNANCE_PROFILE",
      performed_by: updatedBy,
      timestamp: new Date().toISOString(),
      mandate_id: mandateId,
    };
    mandate.audit_trail.push(auditEntry);
    await this.store.update(mandate);

    return {
      mandate_id: mandateId,
      previous_profile: previousProfile,
      new_profile: newProfile,
      audit: auditEntry,
    };
  }

  private invalidTransition(mandateId: string, from: string, to: string): ManagementError {
    return {
      error_code: MGMT_ERROR_CODES.INVALID_STATE_TRANSITION,
      message: `Cannot transition mandate from '${from}' to '${to}'.`,
      timestamp: new Date().toISOString(),
      mandate_id: mandateId,
    };
  }
}

export function isManagementError(result: unknown): result is ManagementError {
  return typeof result === "object" && result !== null && "error_code" in result;
}

export class InMemoryMandateStore implements MandateStore {
  private mandates = new Map<string, MandateDetail>();

  async create(mandate: MandateDetail): Promise<void> {
    this.mandates.set(mandate.mandate_id, structuredClone(mandate));
  }

  async get(mandateId: string): Promise<MandateDetail | null> {
    const m = this.mandates.get(mandateId);
    return m ? structuredClone(m) : null;
  }

  async update(mandate: MandateDetail): Promise<void> {
    this.mandates.set(mandate.mandate_id, structuredClone(mandate));
  }

  async query(query: MandateQueryRequest): Promise<MandateQueryResponse> {
    let results = Array.from(this.mandates.values());

    if (query.customer_id) results = results.filter((m) => m.parties.customer_id === query.customer_id);
    if (query.project_id) results = results.filter((m) => m.parties.project_id === query.project_id);
    if (query.subject) results = results.filter((m) => m.parties.subject === query.subject);
    if (query.status && query.status.length > 0) results = results.filter((m) => query.status!.includes(m.status));

    const total = results.length;
    const offset = query.offset ?? 0;
    const limit = query.limit ?? 50;
    results = results.slice(offset, offset + limit);

    return { mandates: results, total, limit, offset };
  }

  async findActive(agentId: string, projectId: string): Promise<MandateDetail | null> {
    for (const m of this.mandates.values()) {
      if (m.parties.subject === agentId && m.parties.project_id === projectId && m.status === "ACTIVE") {
        return structuredClone(m);
      }
    }
    return null;
  }
}
