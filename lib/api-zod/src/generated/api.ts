import * as zod from "zod";

export const HealthCheckResponse = zod.object({
  status: zod.string(),
});

export const MandateStatusEnum = zod.enum([
  "DRAFT", "ACTIVE", "SUSPENDED", "REVOKED", "EXPIRED", "PENDING_APPROVAL",
]);

export const PhaseEnum = zod.enum(["exploration", "supervised", "autonomous"]);

export const ApprovalModeEnum = zod.enum(["auto", "supervised", "four_eyes"]);

export const CreateMandateRequest = zod.object({
  issuer: zod.string().min(1),
  subject_agent_id: zod.string().min(1),
  governance_profile: zod.string().min(1),
  phase: PhaseEnum,
  scope: zod.record(zod.unknown()).optional(),
  constraints: zod.record(zod.unknown()).optional(),
  budget_cents: zod.number().int().nonnegative().optional(),
  ttl_seconds: zod.number().int().positive().optional(),
  max_delegation_depth: zod.number().int().nonnegative().optional(),
  approval_mode: ApprovalModeEnum.optional(),
  created_by: zod.string().min(1),
});

export const MandateResponse = zod.object({
  mandate_id: zod.string(),
  status: MandateStatusEnum,
  issuer: zod.string(),
  subject_agent_id: zod.string(),
  governance_profile: zod.string(),
  phase: PhaseEnum,
  scope: zod.record(zod.unknown()).optional().nullable(),
  constraints: zod.record(zod.unknown()).optional().nullable(),
  budget_cents: zod.number().optional().nullable(),
  budget_spent_cents: zod.number().optional().nullable(),
  ttl_seconds: zod.number().optional().nullable(),
  max_delegation_depth: zod.number().optional().nullable(),
  parent_mandate_id: zod.string().optional().nullable(),
  delegation_depth: zod.number().optional().nullable(),
  created_at: zod.string(),
  activated_at: zod.string().optional().nullable(),
  expires_at: zod.string().optional().nullable(),
});

export const ActivateMandateRequest = zod.object({
  activated_by: zod.string().min(1),
});

export const RevokeMandateRequest = zod.object({
  revoked_by: zod.string().min(1),
  reason: zod.string().optional(),
});

export const SuspendMandateRequest = zod.object({
  suspended_by: zod.string().min(1),
  reason: zod.string().optional(),
});

export const ResumeMandateRequest = zod.object({
  resumed_by: zod.string().min(1),
  reason: zod.string().optional(),
});

export const TopUpBudgetRequest = zod.object({
  additional_cents: zod.number().int().positive(),
  performed_by: zod.string().min(1),
});

export const ExtendTTLRequest = zod.object({
  additional_seconds: zod.number().int().positive(),
  performed_by: zod.string().min(1),
});

export const DelegateRequest = zod.object({
  delegate_agent_id: zod.string().min(1),
  scope_restriction: zod.record(zod.unknown()).optional(),
  delegated_by: zod.string().min(1),
  max_depth: zod.number().int().nonnegative().optional(),
});

export const UpdateGovernanceProfileRequest = zod.object({
  governance_profile: zod.string().min(1),
  updated_by: zod.string().min(1),
});

export const EnforcementRequestSchema = zod.object({
  action: zod.string().min(1),
  agent: zod.object({
    agent_id: zod.string().min(1),
    session_id: zod.string().optional(),
  }),
  credential: zod.record(zod.unknown()),
  resource: zod.record(zod.unknown()).optional(),
  context: zod.record(zod.unknown()).optional(),
});

export const BatchEnforceRequest = zod.object({
  requests: zod.array(EnforcementRequestSchema),
  mode: zod.enum(["all_or_nothing", "independent"]).default("independent"),
});

export const CredentialIssueRequest = zod.object({
  mandate_id: zod.string().min(1),
  subject_did: zod.string().optional(),
  issuer_did: zod.string().optional(),
  credential_type: zod.enum(["PoACredential", "VerifiableCredential"]).default("PoACredential"),
});

export const PresentationRequest = zod.object({
  credential_ids: zod.array(zod.string()),
  holder_did: zod.string().optional(),
  verifier_did: zod.string().optional(),
  challenge: zod.string().optional(),
});

export const ErrorResponse = zod.object({
  error_code: zod.string(),
  message: zod.string(),
  timestamp: zod.string().optional(),
});
