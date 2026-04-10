import { z } from "zod";

export const SCHEMA_VERSION = "0116.2.2" as const;
export const PEP_INTERFACE_VERSION = "1.2" as const;
export const MGMT_API_VERSION = "1.1" as const;

export const GovernanceProfile = z.enum([
  "minimal",
  "standard",
  "strict",
  "enterprise",
  "behoerde",
]);
export type GovernanceProfile = z.infer<typeof GovernanceProfile>;

export const Phase = z.enum(["plan", "build", "run"]);
export type Phase = z.infer<typeof Phase>;

export const ApprovalMode = z.enum(["autonomous", "supervised", "four-eyes"]);
export type ApprovalMode = z.infer<typeof ApprovalMode>;

export const DeploymentTarget = z.enum(["dev", "staging", "prod"]);
export type DeploymentTarget = z.infer<typeof DeploymentTarget>;

export const ShellMode = z.enum(["any", "denylist", "allowlist"]);
export type ShellMode = z.infer<typeof ShellMode>;

export const MandateStatus = z.enum([
  "DRAFT",
  "ACTIVE",
  "SUSPENDED",
  "EXPIRED",
  "REVOKED",
  "BUDGET_EXCEEDED",
  "SUPERSEDED",
]);
export type MandateStatus = z.infer<typeof MandateStatus>;

export const TERMINAL_STATES: readonly MandateStatus[] = [
  "EXPIRED",
  "REVOKED",
  "BUDGET_EXCEEDED",
  "SUPERSEDED",
] as const;

export const ToolPolicyConstraints = z.object({
  path_patterns: z.array(z.string()).optional(),
  allowed_commands: z.array(z.string()).optional(),
  denied_commands: z.array(z.string()).optional(),
  max_delegation_depth: z.number().int().min(0).optional(),
  max_file_size_bytes: z.number().int().min(0).optional(),
});
export type ToolPolicyConstraints = z.infer<typeof ToolPolicyConstraints>;

export const ToolPolicy = z.object({
  allowed: z.boolean(),
  cost_cents_base: z.number().min(0).optional(),
  constraints: ToolPolicyConstraints.optional(),
});
export type ToolPolicy = z.infer<typeof ToolPolicy>;

export const DeploymentPermissions = z.object({
  targets: z.array(DeploymentTarget).optional(),
  auto_deploy: z.boolean().optional(),
});
export type DeploymentPermissions = z.infer<typeof DeploymentPermissions>;

export const DatabasePermissions = z.object({
  read: z.boolean().optional(),
  write: z.boolean().optional(),
  migrate: z.boolean().optional(),
  production_access: z.boolean().optional(),
});
export type DatabasePermissions = z.infer<typeof DatabasePermissions>;

export const ShellPermissions = z.object({
  mode: ShellMode.optional(),
  allowlist: z.array(z.string()).optional(),
  denylist: z.array(z.string()).optional(),
});
export type ShellPermissions = z.infer<typeof ShellPermissions>;

export const PackagePermissions = z.object({
  verified_only: z.boolean().optional(),
});
export type PackagePermissions = z.infer<typeof PackagePermissions>;

export const ExternalApiPermissions = z.object({
  allowed_domains: z.array(z.string()).optional(),
});
export type ExternalApiPermissions = z.infer<typeof ExternalApiPermissions>;

export const SecretPermissions = z.object({
  read: z.boolean().optional(),
  create: z.boolean().optional(),
});
export type SecretPermissions = z.infer<typeof SecretPermissions>;

export const PlatformPermissions = z.object({
  deployment: DeploymentPermissions.optional(),
  database: DatabasePermissions.optional(),
  shell: ShellPermissions.optional(),
  packages: PackagePermissions.optional(),
  external_apis: ExternalApiPermissions.optional(),
  secrets: SecretPermissions.optional(),
});
export type PlatformPermissions = z.infer<typeof PlatformPermissions>;

export const Budget = z.object({
  total_cents: z.number().int().min(0),
  remaining_cents: z.number().int().min(0).optional(),
});
export type Budget = z.infer<typeof Budget>;

export const SessionLimits = z.object({
  max_tool_calls: z.number().int().min(1).optional(),
  remaining_tool_calls: z.number().int().min(0).optional(),
  max_lines_per_commit: z.number().int().min(1).optional(),
  max_session_duration_minutes: z.number().int().min(1).optional(),
  session_id: z.string().optional(),
  started_at: z.string().datetime().optional(),
});
export type SessionLimits = z.infer<typeof SessionLimits>;

export const DelegationChainEntry = z.object({
  delegator: z.string(),
  delegate: z.string(),
  scope_restriction: z.record(z.unknown()),
  delegated_at: z.string().datetime().optional(),
  max_depth_remaining: z.number().int().min(0).optional(),
});
export type DelegationChainEntry = z.infer<typeof DelegationChainEntry>;

export const PoAParties = z.object({
  issuer: z.string().url(),
  subject: z.string(),
  customer_id: z.string(),
  project_id: z.string(),
  issued_by: z.string().optional(),
  approval_chain: z.array(z.string()).optional(),
});
export type PoAParties = z.infer<typeof PoAParties>;

export const PoAScope = z.object({
  governance_profile: GovernanceProfile,
  phase: Phase,
  core_verbs: z.record(z.string(), ToolPolicy),
  active_modules: z.array(z.string()).optional(),
  allowed_paths: z.array(z.string()).optional(),
  denied_paths: z.array(z.string()).optional(),
  allowed_sectors: z.array(z.string()).optional(),
  allowed_regions: z.array(z.string()).optional(),
  platform_permissions: PlatformPermissions.optional(),
});
export type PoAScope = z.infer<typeof PoAScope>;

export const PoARequirements = z.object({
  approval_mode: ApprovalMode,
  budget: Budget.optional(),
  session_limits: SessionLimits.optional(),
  ttl_seconds: z.number().int().min(60).optional(),
});
export type PoARequirements = z.infer<typeof PoARequirements>;

export const PoACredential = z.object({
  schema_version: z.literal(SCHEMA_VERSION).default(SCHEMA_VERSION),
  parties: PoAParties,
  delegation_chain: z.array(DelegationChainEntry).optional(),
  scope: PoAScope,
  requirements: PoARequirements,
});
export type PoACredential = z.infer<typeof PoACredential>;

export const CredentialFormat = z.enum(["jwt", "w3c_vc", "sd-jwt"]);
export type CredentialFormat = z.infer<typeof CredentialFormat>;

export const ActionDescriptor = z.object({
  verb: z.string(),
  resource: z.string(),
  resource_type: z.string().optional(),
  parameters: z.record(z.unknown()).optional(),
  sector: z.string().optional(),
  region: z.string().optional(),
  transaction_type: z.string().optional(),
  decision_type: z.string().optional(),
});
export type ActionDescriptor = z.infer<typeof ActionDescriptor>;

export const AgentIdentity = z.object({
  agent_id: z.string(),
  service: z.string().optional(),
  session_id: z.string().optional(),
  did: z.string().optional(),
});
export type AgentIdentity = z.infer<typeof AgentIdentity>;

export const CredentialReference = z.object({
  format: CredentialFormat,
  token: z.string().optional(),
  mandate_id: z.string().optional(),
  poa_snapshot: z.record(z.unknown()).optional(),
});
export type CredentialReference = z.infer<typeof CredentialReference>;

export const SessionState = z.object({
  tool_calls_used: z.number().int().min(0).optional(),
  lines_committed: z.number().int().min(0).optional(),
  session_started_at: z.string().datetime().optional(),
  session_cost_cents: z.number().int().min(0).optional(),
});
export type SessionState = z.infer<typeof SessionState>;

export const LiveMandateState = z.object({
  status: z.enum(["active", "expired", "revoked", "budget_exceeded", "superseded"]),
  budget_remaining_cents: z.number().int().min(0).optional(),
  tool_permissions: z.record(z.unknown()).optional(),
  platform_permissions: z.record(z.unknown()).optional(),
});
export type LiveMandateState = z.infer<typeof LiveMandateState>;

export const ApprovalEvidence = z.object({
  approver_id: z.string(),
  approved_at: z.string().datetime(),
  method: z.enum(["manual", "automated", "four-eyes"]).optional(),
  reference: z.string().optional(),
});
export type ApprovalEvidence = z.infer<typeof ApprovalEvidence>;

export const EnforcementContext = z.object({
  session_state: SessionState.optional(),
  live_mandate_state: LiveMandateState.optional(),
  approval_evidence: ApprovalEvidence.optional(),
});
export type EnforcementContext = z.infer<typeof EnforcementContext>;

export const EnforcementRequest = z.object({
  request_id: z.string(),
  timestamp: z.string().datetime(),
  action: ActionDescriptor,
  agent: AgentIdentity,
  credential: CredentialReference,
  context: EnforcementContext.optional(),
});
export type EnforcementRequest = z.infer<typeof EnforcementRequest>;

export const EnforcementDecisionType = z.enum(["PERMIT", "DENY", "CONSTRAIN"]);
export type EnforcementDecisionType = z.infer<typeof EnforcementDecisionType>;

export const EnforcementMode = z.enum(["stateless", "stateful"]);
export type EnforcementMode = z.infer<typeof EnforcementMode>;

export const CheckResultOutcome = z.enum(["pass", "fail", "skip", "constrain"]);
export type CheckResultOutcome = z.infer<typeof CheckResultOutcome>;

export const ViolationSeverity = z.enum(["error", "warning"]);
export type ViolationSeverity = z.infer<typeof ViolationSeverity>;

export interface CheckResult {
  check_id: string;
  check_name: string;
  result: CheckResultOutcome;
  detail?: string;
}

export interface EnforcedConstraint {
  constraint_type: string;
  check_id: string;
  requested: unknown;
  enforced: unknown;
}

export interface Violation {
  code: ViolationCode;
  message: string;
  check_id: string;
  severity: ViolationSeverity;
}

export interface AuditRecord {
  processing_time_ms: number;
  pep_version: string;
  pep_interface_version: string;
  credential_jti?: string;
  mandate_id?: string;
  agent_id?: string;
  action_verb?: string;
  action_resource?: string;
  checks_performed: number;
  checks_passed: number;
  checks_failed: number;
}

export interface EnforcementDecision {
  request_id: string;
  decision: EnforcementDecisionType;
  timestamp: string;
  enforcement_mode: EnforcementMode;
  checks: CheckResult[];
  enforced_constraints: EnforcedConstraint[];
  violations: Violation[];
  audit: AuditRecord;
}

export interface BatchDecision {
  overall_decision: EnforcementDecisionType;
  decisions: EnforcementDecision[];
}

export interface EnforcementPolicy {
  governance_profile: GovernanceProfile;
  phase: Phase;
  allowed_verbs: string[];
  denied_paths: string[];
  allowed_paths: string[];
  permissions: Record<string, unknown>;
  budget: { total_cents: number; remaining_cents: number } | null;
  session_limits: Record<string, unknown> | null;
  approval_mode: ApprovalMode;
  delegation: { allowed: boolean; max_depth: number };
}

export const VIOLATION_CODES = {
  CREDENTIAL_INVALID: "CREDENTIAL_INVALID",
  CREDENTIAL_EXPIRED: "CREDENTIAL_EXPIRED",
  CREDENTIAL_REVOKED: "CREDENTIAL_REVOKED",
  CREDENTIAL_SUPERSEDED: "CREDENTIAL_SUPERSEDED",
  AGENT_MISMATCH: "AGENT_MISMATCH",
  PROFILE_CEILING_EXCEEDED: "PROFILE_CEILING_EXCEEDED",
  PHASE_MISMATCH: "PHASE_MISMATCH",
  SECTOR_MISMATCH: "SECTOR_MISMATCH",
  REGION_MISMATCH: "REGION_MISMATCH",
  PATH_DENIED: "PATH_DENIED",
  PATH_NOT_ALLOWED: "PATH_NOT_ALLOWED",
  VERB_NOT_ALLOWED: "VERB_NOT_ALLOWED",
  CONSTRAINT_VIOLATED: "CONSTRAINT_VIOLATED",
  PLATFORM_PERMISSION_DENIED: "PLATFORM_PERMISSION_DENIED",
  TRANSACTION_NOT_ALLOWED: "TRANSACTION_NOT_ALLOWED",
  DECISION_NOT_ALLOWED: "DECISION_NOT_ALLOWED",
  BUDGET_EXCEEDED: "BUDGET_EXCEEDED",
  BUDGET_EXHAUSTED: "BUDGET_EXHAUSTED",
  SESSION_LIMIT_EXCEEDED: "SESSION_LIMIT_EXCEEDED",
  APPROVAL_REQUIRED: "APPROVAL_REQUIRED",
  DELEGATION_DEPTH_EXCEEDED: "DELEGATION_DEPTH_EXCEEDED",
  DELEGATION_SCOPE_EXCEEDED: "DELEGATION_SCOPE_EXCEEDED",
} as const;
export type ViolationCode = (typeof VIOLATION_CODES)[keyof typeof VIOLATION_CODES];

export const PEP_ERROR_CODES = {
  PEP_INTERNAL_ERROR: "PEP_INTERNAL_ERROR",
  INVALID_REQUEST: "INVALID_REQUEST",
  CREDENTIAL_PARSE_ERROR: "CREDENTIAL_PARSE_ERROR",
  CREDENTIAL_EXPIRED: "CREDENTIAL_EXPIRED",
  CREDENTIAL_INVALID: "CREDENTIAL_INVALID",
  ISSUER_UNREACHABLE: "ISSUER_UNREACHABLE",
  EVALUATION_TIMEOUT: "EVALUATION_TIMEOUT",
} as const;
export type PepErrorCode = (typeof PEP_ERROR_CODES)[keyof typeof PEP_ERROR_CODES];

export interface EnforcementError {
  error_code: PepErrorCode;
  message: string;
  timestamp: string;
  request_id?: string;
  detail?: {
    failed_field?: string;
    issuer_url?: string;
    timeout_ms?: number;
  };
}

export const MGMT_ERROR_CODES = {
  MANDATE_NOT_FOUND: "MANDATE_NOT_FOUND",
  INVALID_STATE_TRANSITION: "INVALID_STATE_TRANSITION",
  VALIDATION_FAILED: "VALIDATION_FAILED",
  CEILING_VIOLATION: "CEILING_VIOLATION",
  CONSISTENCY_ERROR: "CONSISTENCY_ERROR",
  INSUFFICIENT_AUTHORITY: "INSUFFICIENT_AUTHORITY",
  SCOPE_IMMUTABLE: "SCOPE_IMMUTABLE",
  BUDGET_DECREASE_DENIED: "BUDGET_DECREASE_DENIED",
  TTL_DECREASE_DENIED: "TTL_DECREASE_DENIED",
  MANDATE_EXPIRED: "MANDATE_EXPIRED",
  INTERNAL_ERROR: "INTERNAL_ERROR",
} as const;
export type MgmtErrorCode = (typeof MGMT_ERROR_CODES)[keyof typeof MGMT_ERROR_CODES];

export interface ManagementError {
  error_code: MgmtErrorCode;
  message: string;
  timestamp: string;
  mandate_id?: string;
  detail?: {
    schema_errors?: Array<{ path: string; message: string }>;
    ceiling_violations?: Array<{ field: string; ceiling: unknown; requested: unknown }>;
    consistency_errors?: Array<{ rule: string; message: string }>;
  };
}

export interface MandateAuditEntry {
  operation: string;
  performed_by: string;
  timestamp: string;
  mandate_id: string;
  reason?: string;
}

export interface MandateCreationRequest {
  parties: {
    subject: string;
    customer_id: string;
    project_id: string;
    issued_by: string;
    approval_chain?: string[];
  };
  scope: PoAScope;
  requirements: {
    approval_mode: ApprovalMode;
    budget: { total_cents: number };
    ttl_seconds: number;
    session_limits?: {
      max_tool_calls?: number;
      max_session_duration_minutes?: number;
      max_lines_per_commit?: number;
    };
  };
}

export interface MandateCreationResponse {
  mandate_id: string;
  status: "DRAFT";
  scope_checksum: string;
  tool_permissions_hash: string;
  platform_permissions_hash: string;
  created_at: string;
  validation: {
    accepted: boolean;
    schema_errors: Array<{ path: string; message: string }>;
    ceiling_violations: Array<{ field: string; ceiling: unknown; requested: unknown }>;
    consistency_errors: Array<{ rule: string; message: string }>;
  };
  audit: MandateAuditEntry;
}

export interface MandateActivationRequest {
  mandate_id: string;
  activated_by: string;
}

export interface MandateActivationResponse {
  mandate_id: string;
  status: "ACTIVE";
  activated_at: string;
  expires_at: string;
  superseded_mandate_id: string | null;
  audit: MandateAuditEntry;
}

export interface MandateRevocationRequest {
  mandate_id: string;
  revoked_by: string;
  reason: string;
}

export interface MandateRevocationResponse {
  mandate_id: string;
  status: "REVOKED";
  revoked_at: string;
  revoked_by: string;
  reason: string;
  cascaded_revocations: string[];
  audit: MandateAuditEntry;
}

export interface MandateSuspensionRequest {
  mandate_id: string;
  suspended_by: string;
  reason: string;
}

export interface MandateSuspensionResponse {
  mandate_id: string;
  status: "SUSPENDED";
  suspended_at: string;
  suspended_by: string;
  reason: string;
  cascaded_suspensions: string[];
  audit: MandateAuditEntry;
}

export interface MandateResumptionRequest {
  mandate_id: string;
  resumed_by: string;
  reason?: string;
}

export interface MandateResumptionResponse {
  mandate_id: string;
  status: "ACTIVE";
  resumed_at: string;
  resumed_by: string;
  remaining_ttl_seconds: number;
  audit: MandateAuditEntry;
}

export interface MandateDetail {
  mandate_id: string;
  status: MandateStatus;
  parties: PoAParties;
  scope: PoAScope;
  requirements: PoARequirements;
  scope_checksum: string;
  tool_permissions_hash: string;
  platform_permissions_hash: string;
  delegation_chain: DelegationChainEntry[];
  created_at: string;
  activated_at?: string;
  expires_at?: string;
  suspended_at?: string;
  revoked_at?: string;
  budget_consumed_cents: number;
  audit_trail: MandateAuditEntry[];
}

export interface MandateQueryRequest {
  customer_id?: string;
  project_id?: string;
  subject?: string;
  status?: MandateStatus[];
  limit?: number;
  offset?: number;
}

export interface MandateQueryResponse {
  mandates: MandateDetail[];
  total: number;
  limit: number;
  offset: number;
}

export interface BudgetTopUpRequest {
  mandate_id: string;
  additional_cents: number;
  performed_by: string;
}

export interface BudgetTopUpResponse {
  mandate_id: string;
  previous_total_cents: number;
  new_total_cents: number;
  remaining_cents: number;
  audit: MandateAuditEntry;
}

export interface BudgetConsumptionReport {
  mandate_id: string;
  amount_cents: number;
  action_verb: string;
  action_resource: string;
  timestamp: string;
}

export interface TTLExtensionRequest {
  mandate_id: string;
  additional_seconds: number;
  performed_by: string;
}

export interface TTLExtensionResponse {
  mandate_id: string;
  previous_ttl_seconds: number;
  new_ttl_seconds: number;
  new_expires_at: string;
  audit: MandateAuditEntry;
}

export interface DelegationRequest {
  parent_mandate_id: string;
  delegate_agent_id: string;
  scope_restriction: Partial<PoAScope>;
  delegated_by: string;
  max_depth?: number;
}

export interface DelegationResponse {
  child_mandate_id: string;
  parent_mandate_id: string;
  status: "DRAFT";
  delegation_depth: number;
  scope_checksum: string;
  audit: MandateAuditEntry;
}

export interface GovernanceProfileCeiling {
  governance_profile: GovernanceProfile;
  max_ttl_seconds: number;
  max_budget_cents: number;
  max_delegation_depth: number;
  allowed_phases: Phase[];
  allowed_approval_modes: ApprovalMode[];
  max_tool_calls: number;
  auto_deploy_allowed: boolean;
  production_access_allowed: boolean;
  deployment_targets: DeploymentTarget[];
}

export const DEFAULT_GOVERNANCE_CEILINGS: Record<GovernanceProfile, GovernanceProfileCeiling> = {
  minimal: {
    governance_profile: "minimal",
    max_ttl_seconds: 3600,
    max_budget_cents: 1000,
    max_delegation_depth: 0,
    allowed_phases: ["plan"],
    allowed_approval_modes: ["supervised", "four-eyes"],
    max_tool_calls: 50,
    auto_deploy_allowed: false,
    production_access_allowed: false,
    deployment_targets: [],
  },
  standard: {
    governance_profile: "standard",
    max_ttl_seconds: 43200,
    max_budget_cents: 10000,
    max_delegation_depth: 1,
    allowed_phases: ["plan", "build"],
    allowed_approval_modes: ["autonomous", "supervised", "four-eyes"],
    max_tool_calls: 500,
    auto_deploy_allowed: false,
    production_access_allowed: false,
    deployment_targets: ["dev", "staging"],
  },
  strict: {
    governance_profile: "strict",
    max_ttl_seconds: 86400,
    max_budget_cents: 50000,
    max_delegation_depth: 2,
    allowed_phases: ["plan", "build", "run"],
    allowed_approval_modes: ["supervised", "four-eyes"],
    max_tool_calls: 1000,
    auto_deploy_allowed: false,
    production_access_allowed: false,
    deployment_targets: ["dev", "staging"],
  },
  enterprise: {
    governance_profile: "enterprise",
    max_ttl_seconds: 604800,
    max_budget_cents: 500000,
    max_delegation_depth: 3,
    allowed_phases: ["plan", "build", "run"],
    allowed_approval_modes: ["autonomous", "supervised", "four-eyes"],
    max_tool_calls: 10000,
    auto_deploy_allowed: true,
    production_access_allowed: true,
    deployment_targets: ["dev", "staging", "prod"],
  },
  behoerde: {
    governance_profile: "behoerde",
    max_ttl_seconds: 86400,
    max_budget_cents: 100000,
    max_delegation_depth: 2,
    allowed_phases: ["plan", "build", "run"],
    allowed_approval_modes: ["four-eyes"],
    max_tool_calls: 2000,
    auto_deploy_allowed: false,
    production_access_allowed: false,
    deployment_targets: ["dev", "staging"],
  },
};

export const CORE_VERBS = {
  "foundry.file.create": "urn:gauth:verb:foundry:file:create",
  "foundry.file.modify": "urn:gauth:verb:foundry:file:modify",
  "foundry.file.delete": "urn:gauth:verb:foundry:file:delete",
  "foundry.dependency.add": "urn:gauth:verb:foundry:dependency:add",
  "foundry.command.run": "urn:gauth:verb:foundry:command:run",
  "foundry.agent.delegate": "urn:gauth:verb:foundry:agent:delegate",
} as const;

export const GOVERNANCE_RESTRICTED_TRANSACTIONS: Record<GovernanceProfile, Set<string>> = {
  minimal: new Set(),
  standard: new Set(["irreversible_delete"]),
  strict: new Set(["irreversible_delete", "external_transfer"]),
  enterprise: new Set(["irreversible_delete", "external_transfer", "privilege_escalation"]),
  behoerde: new Set(["irreversible_delete", "external_transfer", "privilege_escalation", "cross_boundary"]),
};

export const GOVERNANCE_RESTRICTED_DECISIONS: Record<GovernanceProfile, Set<string>> = {
  minimal: new Set(),
  standard: new Set(),
  strict: new Set(["autonomous_deployment"]),
  enterprise: new Set(["autonomous_deployment", "autonomous_data_access"]),
  behoerde: new Set(["autonomous_deployment", "autonomous_data_access", "autonomous_external_comms"]),
};

export const PHASE_VERB_MAP: Record<Phase, Set<string>> = {
  plan: new Set([
    "foundry.file.create",
    "foundry.file.modify",
  ]),
  build: new Set([
    "foundry.file.create",
    "foundry.file.modify",
    "foundry.file.delete",
    "foundry.dependency.add",
    "foundry.command.run",
  ]),
  run: new Set([
    "foundry.file.create",
    "foundry.file.modify",
    "foundry.file.delete",
    "foundry.dependency.add",
    "foundry.command.run",
    "foundry.agent.delegate",
  ]),
};

export interface GAuthJWTClaims {
  iss: string;
  sub: string;
  aud: string[];
  exp: number;
  iat: number;
  nbf: number;
  jti: string;
  gauth: {
    version: typeof SCHEMA_VERSION;
    credential_id: string;
    customer_id: string;
    project_id: string;
    scope: {
      governance_profile: GovernanceProfile;
      active_modules?: string[];
      phase: Phase;
      allowed_paths?: string[];
      denied_paths?: string[];
      allowed_regions?: string[];
      allowed_sectors?: string[];
      core_verbs: Record<string, { allowed: boolean; cost_cents_base?: number; constraints?: Record<string, unknown> }>;
      platform_permissions?: Record<string, unknown>;
    };
    scope_checksum: string;
    tool_permissions_hash: string;
    platform_permissions_hash: string;
    issued_by?: string;
    approval_mode: ApprovalMode;
  };
  gauth_mandate?: {
    mandate_id: string;
    mandate_status: string;
    budget?: {
      total_cents: number;
      remaining_cents: number;
    };
    session?: {
      session_id: string;
      remaining_tool_calls?: number;
      max_lines_per_commit?: number;
      started_at?: string;
    };
    agent_capability_hash?: string;
  };
}

export interface MandateStore {
  create(mandate: MandateDetail): Promise<void>;
  get(mandateId: string): Promise<MandateDetail | null>;
  update(mandate: MandateDetail): Promise<void>;
  query(query: MandateQueryRequest): Promise<MandateQueryResponse>;
  findActive(agentId: string, projectId: string): Promise<MandateDetail | null>;
}

export const TariffCode = z.enum(["O", "S", "M", "L"]);
export type TariffCode = z.infer<typeof TariffCode>;

export const LicenseType = z.enum(["mpl_2_0", "gimel_tos"]);
export type LicenseType = z.infer<typeof LicenseType>;

export const AdapterType = z.enum(["Internal", "A", "B", "C", "D"]);
export type AdapterType = z.infer<typeof AdapterType>;

export const ConnectorSlotName = z.enum([
  "pdp",
  "oauth_engine",
  "foundry",
  "wallet",
  "ai_governance",
  "web3_identity",
  "dna_identity",
]);
export type ConnectorSlotName = z.infer<typeof ConnectorSlotName>;

export const ConnectorSlotStatus = z.enum(["null", "pending", "active", "error"]);
export type ConnectorSlotStatus = z.infer<typeof ConnectorSlotStatus>;

export const AvailabilityCode = z.enum([
  "active_always",
  "gimel_or_user",
  "user_provided_required",
  "null_or_user",
  "attested_gimel",
  "null_or_attested_gimel",
  "null",
]);
export type AvailabilityCode = z.infer<typeof AvailabilityCode>;

export interface AdapterHealthResult {
  healthy: boolean;
  latencyMs: number;
  details?: string;
}

export interface ConnectorSlotConfig {
  slotName: ConnectorSlotName;
  slotNumber: number;
  adapterType: AdapterType;
  attestationRequired: boolean;
  mandatory: boolean;
  nullBehavior: string;
  timeoutMs: number;
  maxRetries: number;
}

export const CONNECTOR_SLOT_CONFIGS: Record<ConnectorSlotName, ConnectorSlotConfig> = {
  pdp: { slotName: "pdp", slotNumber: 1, adapterType: "Internal", attestationRequired: false, mandatory: true, nullBehavior: "Not allowed — mandatory", timeoutMs: 5000, maxRetries: 0 },
  oauth_engine: { slotName: "oauth_engine", slotNumber: 2, adapterType: "A", attestationRequired: false, mandatory: true, nullBehavior: "Not allowed — mandatory", timeoutMs: 10000, maxRetries: 1 },
  foundry: { slotName: "foundry", slotNumber: 3, adapterType: "B", attestationRequired: false, mandatory: false, nullBehavior: "Features unavailable; no agent execution", timeoutMs: 30000, maxRetries: 1 },
  wallet: { slotName: "wallet", slotNumber: 4, adapterType: "B", attestationRequired: false, mandatory: false, nullBehavior: "W3C VC unavailable; JWT-only", timeoutMs: 10000, maxRetries: 1 },
  ai_governance: { slotName: "ai_governance", slotNumber: 5, adapterType: "C", attestationRequired: true, mandatory: false, nullBehavior: "AI second-pass skipped; rule-based only", timeoutMs: 60000, maxRetries: 0 },
  web3_identity: { slotName: "web3_identity", slotNumber: 6, adapterType: "C", attestationRequired: true, mandatory: false, nullBehavior: "Web3 features unavailable; standard identity", timeoutMs: 30000, maxRetries: 0 },
  dna_identity: { slotName: "dna_identity", slotNumber: 7, adapterType: "C", attestationRequired: true, mandatory: false, nullBehavior: "DNA features unavailable; standard identity", timeoutMs: 30000, maxRetries: 0 },
};

export type DeploymentPolicyMatrix = Record<ConnectorSlotName, Record<TariffCode, AvailabilityCode>>;

export const DEPLOYMENT_POLICY_MATRIX: DeploymentPolicyMatrix = {
  pdp:            { O: "active_always", S: "active_always", M: "active_always", L: "active_always" },
  oauth_engine:   { O: "user_provided_required", S: "gimel_or_user", M: "gimel_or_user", L: "gimel_or_user" },
  foundry:        { O: "null_or_user", S: "gimel_or_user", M: "gimel_or_user", L: "gimel_or_user" },
  wallet:         { O: "null_or_user", S: "gimel_or_user", M: "gimel_or_user", L: "gimel_or_user" },
  ai_governance:  { O: "null", S: "null", M: "attested_gimel", L: "attested_gimel" },
  web3_identity:  { O: "null", S: "null", M: "null_or_attested_gimel", L: "attested_gimel" },
  dna_identity:   { O: "null", S: "null", M: "null", L: "attested_gimel" },
};

export interface TariffGateResult {
  allowed: boolean;
  reason?: string;
  provenance?: string;
  availability: AvailabilityCode;
}

export interface SealedAdapterManifest {
  manifest_version: "1.0";
  adapter_name: string;
  adapter_type: "C";
  adapter_version: string;
  slot_name: "ai_governance" | "web3_identity" | "dna_identity";
  namespace: string;
  issued_at: string;
  expires_at: string;
  issuer: "gimel-foundation";
  public_key: string;
  capabilities?: string[];
  checksum?: string;
  signature: string;
}

export interface CustomerLicenseState {
  license_type: LicenseType;
  license_accepted_at: string | null;
  license_version: string | null;
  service_tos: Record<string, {
    accepted: boolean;
    version: string | null;
    accepted_at: string | null;
  }>;
}

export const DEFAULT_CUSTOMER_LICENSE_STATE: CustomerLicenseState = {
  license_type: "mpl_2_0",
  license_accepted_at: null,
  license_version: null,
  service_tos: {},
};

export interface S2SAuthHeaders {
  "X-GAuth-Platform-Key": string;
  "X-GAuth-HMAC-Signature": string;
}
