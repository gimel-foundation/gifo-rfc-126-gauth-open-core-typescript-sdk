import type {
  EnforcementRequest,
  EnforcementDecision,
  EnforcementError,
  BatchDecision,
  EnforcementPolicy,
  CredentialReference,
  CheckResult,
  EnforcedConstraint,
  Violation,
  AuditRecord,
  PoACredential,
  GAuthJWTClaims,
  PoAScope,
  ToolPolicy,
  ViolationCode,
} from "./types.js";
import {
  VIOLATION_CODES,
  PEP_ERROR_CODES,
  PEP_INTERFACE_VERSION,
  PHASE_VERB_MAP,
  DEFAULT_GOVERNANCE_CEILINGS,
} from "./types.js";
import { matchGlob } from "./crypto.js";
import { validateExtendedToken, type TokenValidationOptions, GAuthTokenError } from "./token.js";

const SDK_VERSION = "0.1.0";

export interface PEPOptions {
  tokenValidation?: TokenValidationOptions;
  serviceUri?: string;
  strictSectorMode?: boolean;
  strictRegionMode?: boolean;
}

interface ParsedCredential {
  poa: PoAScope;
  subject: string;
  jti?: string;
  mandateId?: string;
  mandateStatus?: string;
  budget?: { total_cents: number; remaining_cents: number };
  session?: {
    session_id?: string;
    remaining_tool_calls?: number;
    max_lines_per_commit?: number;
    started_at?: string;
  };
  approvalMode: string;
  delegationChain?: Array<{ delegator: string; delegate: string; scope_restriction: Record<string, unknown>; max_depth_remaining?: number }>;
  exp?: number;
  nbf?: number;
  aud?: string[];
}

async function parseCredential(
  credRef: CredentialReference,
  opts: PEPOptions,
): Promise<ParsedCredential> {
  if (credRef.poa_snapshot) {
    const snap = credRef.poa_snapshot as Record<string, unknown>;
    const scope = (snap.scope ?? snap) as PoAScope;
    return {
      poa: scope,
      subject: (snap.subject as string) ?? "",
      mandateId: snap.mandate_id as string | undefined,
      mandateStatus: snap.mandate_status as string | undefined,
      approvalMode: (snap.approval_mode as string) ?? "supervised",
      delegationChain: snap.delegation_chain as ParsedCredential["delegationChain"],
    };
  }

  if (credRef.format === "jwt" && credRef.token && opts.tokenValidation) {
    const validated = await validateExtendedToken(credRef.token, opts.tokenValidation);
    const claims = validated.claims;
    return {
      poa: {
        governance_profile: claims.gauth.scope.governance_profile,
        phase: claims.gauth.scope.phase,
        core_verbs: {} as Record<string, ToolPolicy>,
        active_modules: claims.gauth.scope.active_modules,
        allowed_paths: claims.gauth.scope.allowed_paths,
        denied_paths: claims.gauth.scope.denied_paths,
      },
      subject: claims.sub,
      jti: claims.jti,
      mandateId: claims.gauth_mandate?.mandate_id,
      mandateStatus: claims.gauth_mandate?.mandate_status,
      budget: claims.gauth_mandate?.budget,
      session: claims.gauth_mandate?.session,
      approvalMode: claims.gauth.approval_mode,
      exp: claims.exp,
      nbf: claims.nbf,
      aud: claims.aud,
    };
  }

  if (credRef.poa_snapshot) {
    return parseCredential({ ...credRef, poa_snapshot: credRef.poa_snapshot }, opts);
  }

  throw new GAuthTokenError("Cannot parse credential: no token or poa_snapshot provided", "CREDENTIAL_PARSE_ERROR");
}

function makeCheckResult(id: string, name: string, result: "pass" | "fail" | "skip" | "constrain", detail?: string): CheckResult {
  return { check_id: id, check_name: name, result, detail };
}

export async function enforceAction(
  request: EnforcementRequest,
  poaOrOptions?: PoACredential | PEPOptions,
  pepOptions?: PEPOptions,
): Promise<EnforcementDecision | EnforcementError> {
  const startTime = performance.now();
  const opts: PEPOptions = pepOptions ?? (poaOrOptions && !("parties" in poaOrOptions) ? poaOrOptions as PEPOptions : {});
  let directPoa: PoACredential | undefined;
  if (poaOrOptions && "parties" in poaOrOptions) {
    directPoa = poaOrOptions as PoACredential;
  }

  try {
    let parsed: ParsedCredential;
    if (directPoa) {
      parsed = {
        poa: directPoa.scope,
        subject: directPoa.parties.subject,
        approvalMode: directPoa.requirements.approval_mode,
        budget: directPoa.requirements.budget
          ? { total_cents: directPoa.requirements.budget.total_cents, remaining_cents: directPoa.requirements.budget.remaining_cents ?? directPoa.requirements.budget.total_cents }
          : undefined,
        session: directPoa.requirements.session_limits
          ? {
              session_id: directPoa.requirements.session_limits.session_id,
              remaining_tool_calls: directPoa.requirements.session_limits.remaining_tool_calls,
              max_lines_per_commit: directPoa.requirements.session_limits.max_lines_per_commit,
              started_at: directPoa.requirements.session_limits.started_at,
            }
          : undefined,
        delegationChain: directPoa.delegation_chain as ParsedCredential["delegationChain"],
      };
    } else {
      parsed = await parseCredential(request.credential, opts);
    }

    const checks: CheckResult[] = [];
    const violations: Violation[] = [];
    const constraints: EnforcedConstraint[] = [];
    const isStateful = !!request.context?.live_mandate_state;

    checks.push(runCHK01(parsed));
    checks.push(runCHK02(parsed, request, opts, isStateful));
    checks.push(runCHK03(parsed, request));
    checks.push(runCHK04(parsed, request));
    checks.push(runCHK05(parsed, request, opts));
    checks.push(runCHK06(parsed, request, opts));
    const chk07 = runCHK07(parsed, request);
    checks.push(chk07.check);
    if (chk07.constraint) constraints.push(chk07.constraint);
    checks.push(runCHK08(parsed, request));
    const chk09 = runCHK09(parsed, request);
    checks.push(chk09.check);
    if (chk09.constraint) constraints.push(chk09.constraint);
    checks.push(runCHK10(parsed, request));
    checks.push(runCHK11(parsed, request));
    checks.push(runCHK12(parsed, request));
    const chk13 = runCHK13(parsed, request);
    checks.push(chk13.check);
    if (chk13.constraint) constraints.push(chk13.constraint);
    checks.push(runCHK14(parsed, request));
    checks.push(runCHK15(parsed, request));
    checks.push(runCHK16(parsed));

    for (const check of checks) {
      if (check.result === "fail") {
        const code = checkIdToViolationCode(check.check_id);
        violations.push({
          code,
          message: check.detail ?? `Check ${check.check_id} failed`,
          check_id: check.check_id,
          severity: "error",
        });
      }
    }

    const hasError = violations.some((v) => v.severity === "error");
    const hasConstrain = checks.some((c) => c.result === "constrain");

    let decision: "PERMIT" | "DENY" | "CONSTRAIN";
    if (hasError) {
      decision = "DENY";
    } else if (hasConstrain) {
      decision = "CONSTRAIN";
    } else {
      decision = "PERMIT";
    }

    const processingTime = performance.now() - startTime;

    const audit: AuditRecord = {
      processing_time_ms: Math.round(processingTime * 100) / 100,
      pep_version: SDK_VERSION,
      pep_interface_version: PEP_INTERFACE_VERSION,
      credential_jti: parsed.jti,
      mandate_id: parsed.mandateId,
      agent_id: request.agent.agent_id,
      action_verb: request.action.verb,
      action_resource: request.action.resource,
      checks_performed: checks.filter((c) => c.result !== "skip").length,
      checks_passed: checks.filter((c) => c.result === "pass" || c.result === "constrain").length,
      checks_failed: checks.filter((c) => c.result === "fail").length,
    };

    return {
      request_id: request.request_id,
      decision,
      timestamp: new Date().toISOString(),
      enforcement_mode: isStateful ? "stateful" : "stateless",
      checks,
      enforced_constraints: decision === "CONSTRAIN" ? constraints : [],
      violations,
      audit,
    };
  } catch (err) {
    if (err instanceof GAuthTokenError) {
      const errorCode = err.violationCode === "CREDENTIAL_EXPIRED"
        ? PEP_ERROR_CODES.CREDENTIAL_PARSE_ERROR
        : err.violationCode === "CREDENTIAL_PARSE_ERROR"
          ? PEP_ERROR_CODES.CREDENTIAL_PARSE_ERROR
          : PEP_ERROR_CODES.CREDENTIAL_PARSE_ERROR;
      return {
        error_code: errorCode,
        message: err.message,
        timestamp: new Date().toISOString(),
        request_id: request.request_id,
      };
    }
    return {
      error_code: PEP_ERROR_CODES.PEP_INTERNAL_ERROR,
      message: err instanceof Error ? err.message : "Unexpected PEP error",
      timestamp: new Date().toISOString(),
      request_id: request.request_id,
    };
  }
}

export async function batchEnforce(
  requests: EnforcementRequest[],
  mode: "all_or_nothing" | "independent",
  poaOrOptions?: PoACredential | PEPOptions,
  pepOptions?: PEPOptions,
): Promise<BatchDecision> {
  const decisions: EnforcementDecision[] = [];
  for (const req of requests) {
    const result = await enforceAction(req, poaOrOptions, pepOptions);
    if ("error_code" in result) {
      decisions.push({
        request_id: req.request_id,
        decision: "DENY",
        timestamp: new Date().toISOString(),
        enforcement_mode: "stateless",
        checks: [],
        enforced_constraints: [],
        violations: [{ code: VIOLATION_CODES.CREDENTIAL_INVALID, message: result.message, check_id: "ERROR", severity: "error" }],
        audit: { processing_time_ms: 0, pep_version: SDK_VERSION, pep_interface_version: PEP_INTERFACE_VERSION, checks_performed: 0, checks_passed: 0, checks_failed: 1 },
      });
    } else {
      decisions.push(result);
    }
  }

  let overallDecision: "PERMIT" | "DENY" | "CONSTRAIN";
  if (mode === "all_or_nothing") {
    const anyDeny = decisions.some((d) => d.decision === "DENY");
    if (anyDeny) {
      overallDecision = "DENY";
      for (const d of decisions) d.decision = "DENY";
    } else {
      const anyConstrain = decisions.some((d) => d.decision === "CONSTRAIN");
      overallDecision = anyConstrain ? "CONSTRAIN" : "PERMIT";
    }
  } else {
    const anyDeny = decisions.some((d) => d.decision === "DENY");
    const anyConstrain = decisions.some((d) => d.decision === "CONSTRAIN");
    overallDecision = anyDeny ? "DENY" : anyConstrain ? "CONSTRAIN" : "PERMIT";
  }

  return { overall_decision: overallDecision, decisions };
}

export function getEnforcementPolicy(
  poa: PoACredential,
): EnforcementPolicy {
  const allowedVerbs = Object.entries(poa.scope.core_verbs)
    .filter(([, policy]) => policy.allowed)
    .map(([verb]) => verb);

  const delegatePolicy = poa.scope.core_verbs["foundry.agent.delegate"];
  const maxDepth = delegatePolicy?.constraints?.max_delegation_depth ?? 0;

  return {
    governance_profile: poa.scope.governance_profile,
    phase: poa.scope.phase,
    allowed_verbs: allowedVerbs,
    denied_paths: poa.scope.denied_paths ?? [],
    allowed_paths: poa.scope.allowed_paths ?? [],
    permissions: (poa.scope.platform_permissions ?? {}) as Record<string, unknown>,
    budget: poa.requirements.budget
      ? { total_cents: poa.requirements.budget.total_cents, remaining_cents: poa.requirements.budget.remaining_cents ?? poa.requirements.budget.total_cents }
      : null,
    session_limits: poa.requirements.session_limits ? { ...poa.requirements.session_limits } : null,
    approval_mode: poa.requirements.approval_mode,
    delegation: { allowed: delegatePolicy?.allowed ?? false, max_depth: maxDepth },
  };
}

function runCHK01(parsed: ParsedCredential): CheckResult {
  if (parsed.poa.governance_profile && parsed.poa.phase) {
    return makeCheckResult("CHK-01", "Credential Integrity", "pass", "Credential structure valid.");
  }
  return makeCheckResult("CHK-01", "Credential Integrity", "fail", "Missing required credential fields.");
}

function runCHK02(parsed: ParsedCredential, request: EnforcementRequest, opts: PEPOptions, isStateful: boolean): CheckResult {
  if (parsed.exp !== undefined) {
    const now = Math.floor(Date.now() / 1000);
    if (parsed.exp < now) {
      return makeCheckResult("CHK-02", "Temporal & Status", "fail", "Credential has expired.");
    }
    if (parsed.nbf !== undefined && parsed.nbf > now) {
      return makeCheckResult("CHK-02", "Temporal & Status", "fail", "Credential is not yet valid.");
    }
  }

  if (parsed.subject && request.agent.agent_id !== parsed.subject) {
    return makeCheckResult("CHK-02", "Temporal & Status", "fail", `Agent mismatch: expected '${parsed.subject}', got '${request.agent.agent_id}'.`);
  }

  if (isStateful && request.context?.live_mandate_state) {
    const liveStatus = request.context.live_mandate_state.status;
    if (liveStatus !== "active") {
      const codeMap: Record<string, string> = {
        revoked: "CREDENTIAL_REVOKED",
        expired: "CREDENTIAL_EXPIRED",
        superseded: "CREDENTIAL_SUPERSEDED",
        budget_exceeded: "BUDGET_EXHAUSTED",
      };
      return makeCheckResult("CHK-02", "Temporal & Status", "fail", `Mandate status is ${liveStatus}.`);
    }
  }

  if (parsed.mandateStatus && parsed.mandateStatus !== "active") {
    return makeCheckResult("CHK-02", "Temporal & Status", "fail", `Mandate status is ${parsed.mandateStatus}.`);
  }

  return makeCheckResult("CHK-02", "Temporal & Status", "pass", "Temporal and status checks passed.");
}

function runCHK03(parsed: ParsedCredential, request: EnforcementRequest): CheckResult {
  const profile = parsed.poa.governance_profile;
  const ceiling = DEFAULT_GOVERNANCE_CEILINGS[profile];
  if (!ceiling) {
    return makeCheckResult("CHK-03", "Governance Profile", "fail", `Unknown governance profile: ${profile}.`);
  }
  return makeCheckResult("CHK-03", "Governance Profile", "pass", `Profile '${profile}' ceiling validated.`);
}

function runCHK04(parsed: ParsedCredential, request: EnforcementRequest): CheckResult {
  const phase = parsed.poa.phase;
  const verbShort = extractVerbShort(request.action.verb);
  const phaseVerbs = PHASE_VERB_MAP[phase];

  if (!phaseVerbs) {
    return makeCheckResult("CHK-04", "Phase", "fail", `Unknown phase: ${phase}.`);
  }

  if (verbShort && !phaseVerbs.has(verbShort)) {
    return makeCheckResult("CHK-04", "Phase", "fail", `Verb '${request.action.verb}' not permitted in phase '${phase}'.`);
  }

  return makeCheckResult("CHK-04", "Phase", "pass", `Action permitted in phase '${phase}'.`);
}

function runCHK05(parsed: ParsedCredential, request: EnforcementRequest, opts: PEPOptions): CheckResult {
  const allowedSectors = parsed.poa.allowed_sectors;
  if (!allowedSectors || allowedSectors.length === 0) {
    return makeCheckResult("CHK-05", "Sector", "skip", "No sector restrictions defined.");
  }

  if (!request.action.sector) {
    if (opts.strictSectorMode) {
      return makeCheckResult("CHK-05", "Sector", "fail", "Sector-restricted PoA requires sector context on action.");
    }
    return makeCheckResult("CHK-05", "Sector", "pass", "No sector in action; permissive mode.");
  }

  if (!allowedSectors.includes(request.action.sector)) {
    return makeCheckResult("CHK-05", "Sector", "fail", `Sector '${request.action.sector}' not in allowed sectors.`);
  }

  return makeCheckResult("CHK-05", "Sector", "pass", `Sector '${request.action.sector}' allowed.`);
}

function runCHK06(parsed: ParsedCredential, request: EnforcementRequest, opts: PEPOptions): CheckResult {
  const allowedRegions = parsed.poa.allowed_regions;
  if (!allowedRegions || allowedRegions.length === 0) {
    return makeCheckResult("CHK-06", "Region", "skip", "No region restrictions defined.");
  }

  if (!request.action.region) {
    if (opts.strictRegionMode) {
      return makeCheckResult("CHK-06", "Region", "fail", "Region-restricted PoA requires region context on action.");
    }
    return makeCheckResult("CHK-06", "Region", "pass", "No region in action; permissive mode.");
  }

  const region = request.action.region;
  const matches = allowedRegions.some((r) => {
    if (r === region) return true;
    if (r === "EU" && EU_MEMBERS.has(region)) return true;
    return false;
  });

  if (!matches) {
    return makeCheckResult("CHK-06", "Region", "fail", `Region '${region}' not in allowed regions.`);
  }

  return makeCheckResult("CHK-06", "Region", "pass", `Region '${region}' allowed.`);
}

function runCHK07(parsed: ParsedCredential, request: EnforcementRequest): { check: CheckResult; constraint?: EnforcedConstraint } {
  const resourceType = request.action.resource_type;
  if (resourceType && !["file", "directory"].includes(resourceType)) {
    return { check: makeCheckResult("CHK-07", "Path", "skip", `Resource type '${resourceType}' is not path-based.`) };
  }

  const resource = normalizePath(request.action.resource);
  const deniedPaths = parsed.poa.denied_paths ?? [];
  const allowedPaths = parsed.poa.allowed_paths ?? [];

  for (const denied of deniedPaths) {
    if (matchGlob(denied, resource)) {
      return { check: makeCheckResult("CHK-07", "Path", "fail", `Path '${resource}' is explicitly denied by pattern '${denied}'.`) };
    }
  }

  if (allowedPaths.length === 0) {
    return { check: makeCheckResult("CHK-07", "Path", "pass", "No path restrictions.") };
  }

  const allowed = allowedPaths.some((p) => matchGlob(p, resource));
  if (!allowed) {
    return { check: makeCheckResult("CHK-07", "Path", "fail", `Path '${resource}' not in allowed paths.`) };
  }

  return { check: makeCheckResult("CHK-07", "Path", "pass", `Path '${resource}' allowed.`) };
}

function runCHK08(parsed: ParsedCredential, request: EnforcementRequest): CheckResult {
  const verbShort = extractVerbShort(request.action.verb);
  if (!verbShort) {
    return makeCheckResult("CHK-08", "Verb Permission", "pass", "Non-standard verb; skipping verb check.");
  }

  const policy = parsed.poa.core_verbs[verbShort] ?? parsed.poa.core_verbs[request.action.verb];
  if (!policy) {
    return makeCheckResult("CHK-08", "Verb Permission", "fail", `Verb '${request.action.verb}' not registered in PoA core_verbs.`);
  }

  if (!policy.allowed) {
    return makeCheckResult("CHK-08", "Verb Permission", "fail", `Verb '${request.action.verb}' is explicitly denied.`);
  }

  return makeCheckResult("CHK-08", "Verb Permission", "pass", `Verb '${request.action.verb}' permitted.`);
}

function runCHK09(parsed: ParsedCredential, request: EnforcementRequest): { check: CheckResult; constraint?: EnforcedConstraint } {
  const verbShort = extractVerbShort(request.action.verb);
  const policy = verbShort
    ? (parsed.poa.core_verbs[verbShort] ?? parsed.poa.core_verbs[request.action.verb])
    : parsed.poa.core_verbs[request.action.verb];

  if (!policy?.constraints) {
    return { check: makeCheckResult("CHK-09", "Verb Constraints", "skip", "No verb constraints defined.") };
  }

  const c = policy.constraints;

  if (c.path_patterns && c.path_patterns.length > 0) {
    const resource = normalizePath(request.action.resource);
    const matchesPattern = c.path_patterns.some((p) => matchGlob(p, resource));
    if (!matchesPattern) {
      return {
        check: makeCheckResult("CHK-09", "Verb Constraints", "fail", `Resource '${resource}' does not match verb path patterns.`),
      };
    }
  }

  if (c.denied_commands && c.denied_commands.length > 0 && request.action.parameters?.command) {
    const cmd = String(request.action.parameters.command);
    if (c.denied_commands.some((d) => cmd.includes(d))) {
      return {
        check: makeCheckResult("CHK-09", "Verb Constraints", "fail", `Command '${cmd}' is in denied commands list.`),
      };
    }
  }

  if (c.allowed_commands && c.allowed_commands.length > 0 && request.action.parameters?.command) {
    const cmd = String(request.action.parameters.command);
    if (!c.allowed_commands.some((a) => cmd.includes(a))) {
      return {
        check: makeCheckResult("CHK-09", "Verb Constraints", "fail", `Command '${cmd}' is not in allowed commands list.`),
      };
    }
  }

  if (c.max_file_size_bytes !== undefined && request.action.parameters?.file_size_bytes !== undefined) {
    const fileSize = Number(request.action.parameters.file_size_bytes);
    if (fileSize > c.max_file_size_bytes) {
      return {
        check: makeCheckResult("CHK-09", "Verb Constraints", "constrain", `File size ${fileSize} exceeds max ${c.max_file_size_bytes}.`),
        constraint: { constraint_type: "file_size_capped", check_id: "CHK-09", requested: fileSize, enforced: c.max_file_size_bytes },
      };
    }
  }

  return { check: makeCheckResult("CHK-09", "Verb Constraints", "pass", "All verb constraints satisfied.") };
}

function runCHK10(parsed: ParsedCredential, request: EnforcementRequest): CheckResult {
  const pp = parsed.poa.platform_permissions;
  if (!pp) {
    return makeCheckResult("CHK-10", "Platform Permissions", "skip", "No platform permissions defined.");
  }

  const rt = request.action.resource_type;

  if (rt === "deployment" && pp.deployment) {
    const target = request.action.resource;
    if (pp.deployment.targets && !pp.deployment.targets.includes(target as "dev" | "staging" | "prod")) {
      return makeCheckResult("CHK-10", "Platform Permissions", "fail", `Deployment target '${target}' not permitted.`);
    }
  }

  if (rt === "database" && pp.database) {
    const verb = extractVerbShort(request.action.verb);
    if (verb?.includes("write") && !pp.database.write) {
      return makeCheckResult("CHK-10", "Platform Permissions", "fail", "Database write not permitted.");
    }
    if (verb?.includes("migrate") && !pp.database.migrate) {
      return makeCheckResult("CHK-10", "Platform Permissions", "fail", "Database migration not permitted.");
    }
    if (request.action.parameters?.production && !pp.database.production_access) {
      return makeCheckResult("CHK-10", "Platform Permissions", "fail", "Database production access not permitted.");
    }
  }

  if (rt === "secret" && pp.secrets) {
    const verb = extractVerbShort(request.action.verb);
    if (verb?.includes("create") && !pp.secrets.create) {
      return makeCheckResult("CHK-10", "Platform Permissions", "fail", "Secret creation not permitted.");
    }
    if (verb?.includes("read") && !pp.secrets.read) {
      return makeCheckResult("CHK-10", "Platform Permissions", "fail", "Secret read not permitted.");
    }
  }

  return makeCheckResult("CHK-10", "Platform Permissions", "pass", "Platform permissions satisfied.");
}

function runCHK11(parsed: ParsedCredential, request: EnforcementRequest): CheckResult {
  if (!request.action.transaction_type) {
    return makeCheckResult("CHK-11", "Transaction Type", "skip", "No transaction type in action.");
  }
  return makeCheckResult("CHK-11", "Transaction Type", "pass", "Transaction type check passed.");
}

function runCHK12(parsed: ParsedCredential, request: EnforcementRequest): CheckResult {
  if (!request.action.decision_type) {
    return makeCheckResult("CHK-12", "Decision Type", "skip", "No decision type in action.");
  }
  return makeCheckResult("CHK-12", "Decision Type", "pass", "Decision type check passed.");
}

function runCHK13(parsed: ParsedCredential, request: EnforcementRequest): { check: CheckResult; constraint?: EnforcedConstraint } {
  const budget = parsed.budget;
  if (!budget) {
    return { check: makeCheckResult("CHK-13", "Budget", "skip", "No budget defined.") };
  }

  if (budget.remaining_cents <= 0) {
    return { check: makeCheckResult("CHK-13", "Budget", "fail", "Budget fully exhausted.") };
  }

  const amountCents = request.action.parameters?.amount_cents as number | undefined;
  if (amountCents !== undefined && amountCents > budget.remaining_cents) {
    return {
      check: makeCheckResult("CHK-13", "Budget", "constrain", `Action cost ${amountCents} exceeds remaining budget ${budget.remaining_cents}.`),
      constraint: { constraint_type: "budget_capped", check_id: "CHK-13", requested: amountCents, enforced: budget.remaining_cents },
    };
  }

  return { check: makeCheckResult("CHK-13", "Budget", "pass", `Budget available: ${budget.remaining_cents} cents remaining.`) };
}

function runCHK14(parsed: ParsedCredential, request: EnforcementRequest): CheckResult {
  const session = parsed.session;
  const ctxSession = request.context?.session_state;

  if (!session && !ctxSession) {
    return makeCheckResult("CHK-14", "Session Limits", "skip", "No session limits defined.");
  }

  if (session?.remaining_tool_calls !== undefined && session.remaining_tool_calls <= 0) {
    return makeCheckResult("CHK-14", "Session Limits", "fail", "Tool call limit reached.");
  }

  if (ctxSession?.tool_calls_used !== undefined && session?.remaining_tool_calls !== undefined) {
    if (ctxSession.tool_calls_used >= (session.remaining_tool_calls + ctxSession.tool_calls_used)) {
      return makeCheckResult("CHK-14", "Session Limits", "fail", "Tool call limit reached.");
    }
  }

  return makeCheckResult("CHK-14", "Session Limits", "pass", "Session limits satisfied.");
}

function runCHK15(parsed: ParsedCredential, request: EnforcementRequest): CheckResult {
  if (parsed.approvalMode === "autonomous") {
    return makeCheckResult("CHK-15", "Approval", "pass", "Autonomous mode — no approval required.");
  }

  if (parsed.approvalMode === "four-eyes") {
    return makeCheckResult("CHK-15", "Approval", "pass", "Four-eyes mode — approval assumed granted for enforcement context.");
  }

  if (parsed.approvalMode === "supervised") {
    return makeCheckResult("CHK-15", "Approval", "pass", "Supervised mode — approval assumed granted for enforcement context.");
  }

  return makeCheckResult("CHK-15", "Approval", "pass", "Approval check passed.");
}

function runCHK16(parsed: ParsedCredential): CheckResult {
  const chain = parsed.delegationChain;
  if (!chain || chain.length === 0) {
    return makeCheckResult("CHK-16", "Delegation Chain", "skip", "No delegation chain present.");
  }

  for (let i = 0; i < chain.length; i++) {
    const entry = chain[i];
    if (entry.max_depth_remaining !== undefined && entry.max_depth_remaining < 0) {
      return makeCheckResult("CHK-16", "Delegation Chain", "fail", `Delegation depth exceeded at chain position ${i}.`);
    }
  }

  return makeCheckResult("CHK-16", "Delegation Chain", "pass", `Delegation chain valid (depth: ${chain.length}).`);
}

function extractVerbShort(verb: string): string | undefined {
  if (verb.startsWith("urn:gauth:verb:")) {
    const parts = verb.replace("urn:gauth:verb:", "").split(":");
    if (parts.length >= 3) {
      return `${parts[0]}.${parts[1]}.${parts[2]}`;
    }
  }
  if (verb.includes(".")) return verb;
  return undefined;
}

function normalizePath(path: string): string {
  return path.replace(/\/+$/, "").replace(/^\.\//, "");
}

function checkIdToViolationCode(checkId: string): ViolationCode {
  const map: Record<string, ViolationCode> = {
    "CHK-01": VIOLATION_CODES.CREDENTIAL_INVALID,
    "CHK-02": VIOLATION_CODES.CREDENTIAL_EXPIRED,
    "CHK-03": VIOLATION_CODES.PROFILE_CEILING_EXCEEDED,
    "CHK-04": VIOLATION_CODES.PHASE_MISMATCH,
    "CHK-05": VIOLATION_CODES.SECTOR_MISMATCH,
    "CHK-06": VIOLATION_CODES.REGION_MISMATCH,
    "CHK-07": VIOLATION_CODES.PATH_DENIED,
    "CHK-08": VIOLATION_CODES.VERB_NOT_ALLOWED,
    "CHK-09": VIOLATION_CODES.CONSTRAINT_VIOLATED,
    "CHK-10": VIOLATION_CODES.PLATFORM_PERMISSION_DENIED,
    "CHK-11": VIOLATION_CODES.TRANSACTION_NOT_ALLOWED,
    "CHK-12": VIOLATION_CODES.DECISION_NOT_ALLOWED,
    "CHK-13": VIOLATION_CODES.BUDGET_EXCEEDED,
    "CHK-14": VIOLATION_CODES.SESSION_LIMIT_EXCEEDED,
    "CHK-15": VIOLATION_CODES.APPROVAL_REQUIRED,
    "CHK-16": VIOLATION_CODES.DELEGATION_DEPTH_EXCEEDED,
  };
  return map[checkId] ?? VIOLATION_CODES.CREDENTIAL_INVALID;
}

const EU_MEMBERS = new Set([
  "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
  "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
  "PL", "PT", "RO", "SK", "SI", "ES", "SE",
]);

export function isEnforcementError(result: EnforcementDecision | EnforcementError): result is EnforcementError {
  return "error_code" in result;
}
