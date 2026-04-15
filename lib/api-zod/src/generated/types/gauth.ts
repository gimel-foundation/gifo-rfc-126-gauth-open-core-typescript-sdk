export type MandateStatus = "DRAFT" | "ACTIVE" | "SUSPENDED" | "REVOKED" | "EXPIRED" | "PENDING_APPROVAL";
export type Phase = "exploration" | "supervised" | "autonomous";
export type ApprovalMode = "auto" | "supervised" | "four_eyes";
export type EnforcementDecision = "ALLOW" | "DENY" | "ABSTAIN";

export interface MandateSummary {
  mandate_id: string;
  status: MandateStatus;
  issuer: string;
  subject_agent_id: string;
  governance_profile: string;
  phase: Phase;
  created_at: string;
}

export interface MandateDetail extends MandateSummary {
  scope?: Record<string, unknown> | null;
  constraints?: Record<string, unknown> | null;
  budget_cents?: number | null;
  budget_spent_cents?: number | null;
  ttl_seconds?: number | null;
  max_delegation_depth?: number | null;
  parent_mandate_id?: string | null;
  delegation_depth?: number | null;
  activated_at?: string | null;
  expires_at?: string | null;
}

export interface EnforcementResult {
  decision: EnforcementDecision;
  violations?: string[];
  audit?: {
    processing_time_ms?: number;
    checks_passed?: number;
    checks_failed?: number;
  };
}

export interface PoaMapEntry {
  mandate_id: string;
  agent_id: string;
  depth: number;
  status: MandateStatus;
  parent_mandate_id?: string;
}

export interface GovernanceProfileSummary {
  profile_name: string;
  description?: string;
  phase: Phase;
  tariff_code?: string;
}

export interface AuditLogEntry {
  id: string;
  event_type: string;
  mandate_id?: string;
  agent_id?: string;
  action?: string;
  decision?: EnforcementDecision;
  detail?: string;
  created_at: string;
}

export interface CredentialSummary {
  credential_id: string;
  mandate_id: string;
  type: string;
  status: string;
  issuer_did?: string;
  subject_did?: string;
  issued_at: string;
  expires_at?: string;
}
