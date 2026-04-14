import { createHmac, timingSafeEqual, verify, createPublicKey } from "node:crypto";
import type {
  PoACredential,
  GAuthJWTClaims,
  MandateDetail,
  GovernanceProfile,
  GovernanceProfileCeiling,
  ConnectorSlotName,
  ConnectorSlotStatus,
  TariffCode,
  AvailabilityCode,
  AdapterHealthResult,
  TariffGateResult,
  SealedAdapterManifest,
  CustomerLicenseState,
  ComplianceAuditEntry,
} from "./types.js";
import {
  DEFAULT_GOVERNANCE_CEILINGS,
  CONNECTOR_SLOT_CONFIGS,
  DEPLOYMENT_POLICY_MATRIX,
  DEFAULT_CUSTOMER_LICENSE_STATE,
  tariffEffectiveLevel,
} from "./types.js";

export interface PolicyDecisionAdapter {
  readonly adapterType: "Internal";
  readonly name: string;
  evaluateMandate(mandate: { id: string; clientId: string; scopes: string[]; [key: string]: unknown }, profile: { id: string; name: string; [key: string]: unknown }): Promise<{ allowed: boolean; reason: string; violations?: string[] }>;
  validateCeilings(mandate: { id: string; clientId: string; scopes: string[]; [key: string]: unknown }, profile: { id: string; name: string; [key: string]: unknown }): Promise<{ valid: boolean; violations?: string[] }>;
  evaluateAction(action: { verb: string; resource: string; [key: string]: unknown }, mandate: { id: string; clientId: string; scopes: string[]; [key: string]: unknown }): Promise<{ allowed: boolean; reason: string; constraints?: Record<string, unknown> }>;
  adjustSeverity(baseSeverity: string, profile: { id: string; name: string; [key: string]: unknown }): string;
  healthCheck(): Promise<AdapterHealthResult>;
}

export interface OAuthEngineAdapter {
  readonly adapterType: "A";
  readonly name: string;
  readonly packageNamespace: string;
  issueToken(claims: Record<string, unknown>, options: { ttl?: number; scopes?: string[]; [key: string]: unknown }): Promise<{ token: string; expiresAt: string }>;
  validateToken(token: string): Promise<{ valid: boolean; claims?: Record<string, unknown>; error?: string }>;
  revokeToken(tokenId: string, reason: string): Promise<{ revoked: boolean; tokenId: string }>;
  getJWKS(): Promise<{ keys: Record<string, unknown>[] }>;
  introspect(token: string): Promise<{ active: boolean; claims?: Record<string, unknown> }>;
  beforeTokenIssuance(context: { clientId: string; subject: string; scopes: string[]; [key: string]: unknown }): Promise<Record<string, unknown>>;
  afterTokenIssuance(token: { token: string; expiresAt: string }, context: { clientId: string; subject: string; scopes: string[]; [key: string]: unknown }): Promise<void>;
  healthCheck(): Promise<AdapterHealthResult>;
}

export interface FoundryAdapter {
  readonly adapterType: "B";
  readonly name: string;
  readonly packageNamespace: string;
  executeAction(action: { verb: string; resource: string; [key: string]: unknown }, mandate: { id: string; clientId: string; scopes: string[]; [key: string]: unknown }): Promise<{ success: boolean; result?: unknown; error?: string }>;
  getAgentCatalog(): Promise<Array<{ id: string; name: string; capabilities: string[] }>>;
  getActionReport(actionId: string): Promise<{ actionId: string; status: string; result?: unknown }>;
  validateSandbox(agentId: string, requirements: Record<string, unknown>): Promise<{ valid: boolean; issues?: string[] }>;
  healthCheck(): Promise<AdapterHealthResult>;
}

export interface WalletAdapter {
  readonly adapterType: "B";
  readonly name: string;
  readonly packageNamespace: string;
  storeCredential(credential: Record<string, unknown>): Promise<{ id: string; stored: boolean }>;
  presentCredential(query: Record<string, unknown>): Promise<Record<string, unknown>>;
  listCredentials(filter?: Record<string, unknown>): Promise<Array<{ id: string; type: string; issuer: string }>>;
  deleteCredential(credentialId: string): Promise<{ id: string; deleted: boolean }>;
  generateSelectiveDisclosure(credential: Record<string, unknown>, disclosureFrame: Record<string, unknown>): Promise<{ token: string }>;
  healthCheck(): Promise<AdapterHealthResult>;
}

export interface GovernanceAdapter {
  readonly adapterType: "C";
  readonly name: string;
  readonly packageNamespace: string;
  checkAccess(request: { requestId: string; operation: string; resource: string; actor: { clientId: string; clientType: string }; context: Record<string, unknown> }): Promise<{ allowed: boolean; reason: string; recommendations?: string[] }>;
  getRecommendations(context: Record<string, unknown>): Promise<Array<{ id: string; recommendation: string; severity: string }>>;
  healthCheck(): Promise<AdapterHealthResult>;
}

export interface Web3IdentityAdapter {
  readonly adapterType: "C";
  readonly name: string;
  readonly packageNamespace: string;
  resolveIdentity(identifier: string): Promise<{ identifier: string; resolved: boolean; [key: string]: unknown } | null>;
  verifyCredential(credential: unknown): Promise<{ verified: boolean; details?: string }>;
  healthCheck(): Promise<AdapterHealthResult>;
}

export interface DNAIdentityAdapter {
  readonly adapterType: "C";
  readonly name: string;
  readonly packageNamespace: string;
  resolveIdentity(identifier: string): Promise<{ identifier: string; resolved: boolean; [key: string]: unknown } | null>;
  verifyBiometric(data: unknown): Promise<{ verified: boolean; details?: string }>;
  healthCheck(): Promise<AdapterHealthResult>;
}

export interface BillingAdapter {
  readonly adapterType: "D";
  readonly name: string;
  checkCredits(organizationId: string, operation: string): Promise<{ allowed: boolean; balance: number; cost: number }>;
  recordUsage(organizationId: string, operation: string, metadata?: Record<string, unknown>): Promise<void>;
  getBalance(organizationId: string): Promise<{ balanceCents: number; currency: string }>;
  healthCheck(): Promise<AdapterHealthResult>;
}

export type GAuthAdapter =
  | PolicyDecisionAdapter
  | OAuthEngineAdapter
  | FoundryAdapter
  | WalletAdapter
  | GovernanceAdapter
  | Web3IdentityAdapter
  | DNAIdentityAdapter
  | BillingAdapter;

export interface AdapterRegistrationOptions {
  trustedNamespaces?: string[];
  requireSignature?: boolean;
  signatureVerifier?: (adapter: GAuthAdapter, signature: string) => Promise<boolean>;
}

interface RegisteredAdapter {
  adapter: GAuthAdapter;
  registeredAt: string;
  namespace: string;
}

const DEFAULT_TRUSTED_NAMESPACES = [
  "@gauth/",
  "@gimel/",
  "@gimel-foundation/",
];

export class AdapterRegistry {
  private adapters = new Map<string, RegisteredAdapter>();
  private trustedNamespaces: string[];
  private requireSignature: boolean;
  private signatureVerifier?: (adapter: GAuthAdapter, signature: string) => Promise<boolean>;

  constructor(options?: AdapterRegistrationOptions) {
    this.trustedNamespaces = options?.trustedNamespaces ?? DEFAULT_TRUSTED_NAMESPACES;
    this.requireSignature = options?.requireSignature ?? false;
    this.signatureVerifier = options?.signatureVerifier;
  }

  async register(adapter: GAuthAdapter, signature?: string): Promise<void> {
    const ns = "packageNamespace" in adapter ? (adapter as { packageNamespace: string }).packageNamespace : "@gimel/internal";

    const isTrusted = this.trustedNamespaces.some((trusted) => ns.startsWith(trusted));
    if (!isTrusted) {
      throw new AdapterRegistrationError(
        `Adapter '${adapter.name}' from namespace '${ns}' is not in the trusted namespaces list. ` +
        `Trusted: ${this.trustedNamespaces.join(", ")}`,
      );
    }

    if (this.requireSignature) {
      if (!signature) {
        throw new AdapterRegistrationError(
          `Adapter '${adapter.name}' requires a cryptographic signature for registration.`,
        );
      }
      if (this.signatureVerifier) {
        const valid = await this.signatureVerifier(adapter, signature);
        if (!valid) {
          throw new AdapterRegistrationError(
            `Adapter '${adapter.name}' signature verification failed.`,
          );
        }
      }
    }

    const key = `${adapter.adapterType}:${adapter.name}`;
    if (this.adapters.has(key)) {
      throw new AdapterRegistrationError(
        `Adapter '${adapter.name}' (type ${adapter.adapterType}) is already registered.`,
      );
    }

    this.adapters.set(key, {
      adapter,
      registeredAt: new Date().toISOString(),
      namespace: ns,
    });
  }

  get<T extends GAuthAdapter>(type: string, name: string): T | undefined {
    const key = `${type}:${name}`;
    return this.adapters.get(key)?.adapter as T | undefined;
  }

  getOAuthEngine(name: string): OAuthEngineAdapter | undefined {
    return this.get<OAuthEngineAdapter>("A", name);
  }

  getFoundry(name: string): FoundryAdapter | undefined {
    return this.get<FoundryAdapter>("B", name);
  }

  getWallet(name: string): WalletAdapter | undefined {
    return this.get<WalletAdapter>("B", name);
  }

  list(): Array<{ type: string; name: string; namespace: string; registeredAt: string }> {
    return Array.from(this.adapters.entries()).map(([key, reg]) => ({
      type: reg.adapter.adapterType,
      name: reg.adapter.name,
      namespace: reg.namespace,
      registeredAt: reg.registeredAt,
    }));
  }

  unregister(type: string, name: string): boolean {
    return this.adapters.delete(`${type}:${name}`);
  }
}

export class AdapterRegistrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AdapterRegistrationError";
  }
}

export interface ConnectorSlotState {
  slotName: ConnectorSlotName;
  status: ConnectorSlotStatus;
  implementationLabel: string;
  adapter: GAuthAdapter | null;
  attestationSatisfied: boolean;
  registeredAt: string | null;
  licenseType: string | null;
  licenseAcceptedAt: string | null;
  licenseVersion: string | null;
}

export class ConnectorSlotRegistry {
  private slots = new Map<ConnectorSlotName, ConnectorSlotState>();
  private tariff: TariffCode;
  private complianceLog: ComplianceAuditEntry[] = [];

  constructor(tariff: TariffCode = "O") {
    this.tariff = tariff;
    const slotNames: ConnectorSlotName[] = ["pdp", "oauth_engine", "foundry", "wallet", "ai_governance", "web3_identity", "dna_identity"];
    for (const name of slotNames) {
      this.slots.set(name, {
        slotName: name,
        status: "null",
        implementationLabel: "None",
        adapter: null,
        attestationSatisfied: false,
        registeredAt: null,
        licenseType: null,
        licenseAcceptedAt: null,
        licenseVersion: null,
      });
    }
  }

  private resolveEffectiveTariff(): "O" | "S" | "M" | "L" {
    return tariffEffectiveLevel(this.tariff);
  }

  checkTariffGate(slotName: ConnectorSlotName): TariffGateResult {
    const effective = this.resolveEffectiveTariff();
    const availability = DEPLOYMENT_POLICY_MATRIX[slotName][effective];

    if (availability === "null") {
      return { allowed: false, reason: "Slot not available for tariff", availability };
    }

    const config = CONNECTOR_SLOT_CONFIGS[slotName];
    if (config.adapterType === "C" && (effective === "O" || effective === "S")) {
      return { allowed: false, reason: "Type C requires tariff M or higher", availability };
    }

    const slot = this.slots.get(slotName)!;

    switch (availability) {
      case "active_always":
        return { allowed: true, provenance: "gimel_managed", availability };
      case "gimel_or_user":
        return { allowed: true, provenance: "gimel_or_user", availability };
      case "user_provided_required":
        return { allowed: true, provenance: "user_must_provide", availability };
      case "null_or_user":
        return { allowed: true, provenance: "user_optional", availability };
      case "attested_gimel":
        if (config.attestationRequired && !slot.attestationSatisfied) {
          return { allowed: false, reason: "Attestation required", availability };
        }
        return { allowed: true, provenance: "attested_gimel", availability };
      case "null_or_attested_gimel":
        if (config.attestationRequired && !slot.attestationSatisfied) {
          return { allowed: true, provenance: "null_fallback_until_attested", availability };
        }
        return { allowed: true, provenance: "attested_gimel", availability };
      default:
        return { allowed: false, reason: "Unknown availability", availability };
    }
  }

  register(slotName: ConnectorSlotName, adapter: GAuthAdapter, implementationLabel: string): { success: boolean; error?: string } {
    const gate = this.checkTariffGate(slotName);
    if (!gate.allowed && gate.availability === "null") {
      return { success: false, error: `Slot ${slotName} is not available for tariff ${this.tariff}` };
    }

    const config = CONNECTOR_SLOT_CONFIGS[slotName];
    const slot = this.slots.get(slotName)!;

    if (config.adapterType === "C") {
      if ("packageNamespace" in adapter) {
        const ns = (adapter as { packageNamespace: string }).packageNamespace;
        if (!ns.startsWith("@gimel/")) {
          this.logCompliance({
            timestamp: new Date().toISOString(),
            event_type: "LICENSE_COMPLIANCE_VIOLATION",
            slot_name: slotName,
            tariff: this.tariff,
            detail: `Type C adapter '${adapter.name}' namespace '${ns}' must start with @gimel/.`,
          });
          return { success: false, error: `Type C adapter namespace must start with @gimel/; got '${ns}'` };
        }
      }

      if (!slot.attestationSatisfied) {
        slot.adapter = adapter;
        slot.implementationLabel = implementationLabel;
        slot.registeredAt = new Date().toISOString();
        slot.status = "pending";
        return { success: true };
      }
    }

    slot.adapter = adapter;
    slot.implementationLabel = implementationLabel;
    slot.registeredAt = new Date().toISOString();
    slot.status = "active";
    return { success: true };
  }

  unregister(slotName: ConnectorSlotName): { success: boolean; error?: string } {
    const config = CONNECTOR_SLOT_CONFIGS[slotName];
    if (config.mandatory) {
      return { success: false, error: `Cannot unregister ${slotName} — it is mandatory` };
    }

    const slot = this.slots.get(slotName)!;
    slot.adapter = null;
    slot.implementationLabel = "None";
    slot.status = "null";
    slot.attestationSatisfied = false;
    slot.registeredAt = null;
    slot.licenseType = null;
    slot.licenseAcceptedAt = null;
    slot.licenseVersion = null;
    return { success: true };
  }

  satisfyAttestation(slotName: ConnectorSlotName, manifest?: SealedAdapterManifest): { success: boolean; error?: string } {
    const config = CONNECTOR_SLOT_CONFIGS[slotName];
    if (!config.attestationRequired) {
      return { success: false, error: `Slot ${slotName} does not require attestation` };
    }

    const slot = this.slots.get(slotName)!;
    const hasRealAdapter = slot.adapter && !slot.adapter.name.startsWith("noop-");

    if (!manifest && hasRealAdapter) {
      this.logCompliance({
        timestamp: new Date().toISOString(),
        event_type: "MANIFEST_VERIFICATION_FAILED",
        slot_name: slotName,
        tariff: this.tariff,
        detail: "SealedAdapterManifest is required for non-NoOp Type C adapters.",
      });
      return { success: false, error: "SealedAdapterManifest is required for non-NoOp Type C adapters." };
    }

    if (manifest) {
      const validationError = this.validateManifest(manifest, slotName);
      if (validationError) {
        this.logCompliance({
          timestamp: new Date().toISOString(),
          event_type: "MANIFEST_VERIFICATION_FAILED",
          slot_name: slotName,
          tariff: this.tariff,
          detail: validationError,
        });
        return { success: false, error: validationError };
      }
    }

    slot.attestationSatisfied = true;
    if (slot.adapter && slot.status === "pending") {
      slot.status = "active";
    }
    return { success: true };
  }

  private validateManifest(manifest: SealedAdapterManifest, slotName: ConnectorSlotName): string | null {
    if (manifest.manifest_version !== "1.0") {
      return `Invalid manifest version: '${manifest.manifest_version}'; expected '1.0'.`;
    }
    if (manifest.adapter_type !== "C") {
      return `Manifest adapter_type must be 'C'; got '${manifest.adapter_type}'.`;
    }
    if (manifest.slot_name !== slotName) {
      return `Manifest slot_name '${manifest.slot_name}' does not match target slot '${slotName}'.`;
    }
    if (!manifest.namespace.startsWith("@gimel/")) {
      return `Manifest namespace '${manifest.namespace}' must start with '@gimel/'.`;
    }
    if (manifest.issuer !== "gimel-foundation") {
      return `Manifest issuer must be 'gimel-foundation'; got '${manifest.issuer}'.`;
    }
    const now = new Date();
    const issuedAt = new Date(manifest.issued_at);
    const expiresAt = new Date(manifest.expires_at);
    if (isNaN(issuedAt.getTime()) || isNaN(expiresAt.getTime())) {
      return "Manifest has invalid temporal fields.";
    }
    if (expiresAt < now) {
      return `Manifest has expired (expires_at: ${manifest.expires_at}).`;
    }
    if (issuedAt > now) {
      return `Manifest issued_at is in the future (${manifest.issued_at}).`;
    }
    if (!manifest.signature || manifest.signature.length < 64) {
      return "Manifest signature is missing or too short for Ed25519.";
    }

    const sigVerifyResult = this.verifyEd25519Signature(manifest);
    if (sigVerifyResult) return sigVerifyResult;

    return null;
  }

  private verifyEd25519Signature(manifest: SealedAdapterManifest): string | null {
    try {
      const canonicalPayload = JSON.stringify({
        manifest_version: manifest.manifest_version,
        adapter_name: manifest.adapter_name,
        adapter_type: manifest.adapter_type,
        adapter_version: manifest.adapter_version,
        slot_name: manifest.slot_name,
        namespace: manifest.namespace,
        issued_at: manifest.issued_at,
        expires_at: manifest.expires_at,
        issuer: manifest.issuer,
        ...(manifest.capabilities ? { capabilities: manifest.capabilities } : {}),
        ...(manifest.checksum ? { checksum: manifest.checksum } : {}),
      });

      const signatureBytes = Buffer.from(manifest.signature, "hex");
      if (signatureBytes.length !== 64) {
        return `Ed25519 signature must be 64 bytes; got ${signatureBytes.length}.`;
      }

      let publicKeyObj;
      try {
        publicKeyObj = createPublicKey({
          key: Buffer.from(manifest.public_key, "hex"),
          format: "der",
          type: "spki",
        });
      } catch {
        try {
          const raw = Buffer.from(manifest.public_key, "base64url");
          if (raw.length === 32) {
            const ed25519Prefix = Buffer.from("302a300506032b6570032100", "hex");
            const derKey = Buffer.concat([ed25519Prefix, raw]);
            publicKeyObj = createPublicKey({
              key: derKey,
              format: "der",
              type: "spki",
            });
          } else {
            return `Ed25519 public key has invalid length: ${raw.length} bytes (expected 32).`;
          }
        } catch {
          return "Unable to parse Ed25519 public key from manifest.";
        }
      }

      const valid = verify(
        null,
        Buffer.from(canonicalPayload),
        publicKeyObj,
        signatureBytes,
      );

      if (!valid) {
        return "Ed25519 signature verification failed: signature does not match canonical payload.";
      }

      return null;
    } catch (err) {
      return `Ed25519 signature verification error: ${err instanceof Error ? err.message : String(err)}`;
    }
  }

  acceptLicense(slotName: ConnectorSlotName, licenseVersion: string): { success: boolean; error?: string } {
    const slot = this.slots.get(slotName)!;
    slot.licenseType = "gimel_tos";
    slot.licenseAcceptedAt = new Date().toISOString();
    slot.licenseVersion = licenseVersion;
    return { success: true };
  }

  setTariff(newTariff: TariffCode): { deactivated: ConnectorSlotName[] } {
    const oldTariff = this.tariff;
    this.tariff = newTariff;

    const deactivated: ConnectorSlotName[] = [];
    const newEffective = tariffEffectiveLevel(newTariff);
    const oldEffective = tariffEffectiveLevel(oldTariff);
    const TIER_ORDER: Record<string, number> = { O: 0, S: 1, M: 2, L: 3 };

    if (TIER_ORDER[newEffective] < TIER_ORDER[oldEffective]) {
      this.logCompliance({
        timestamp: new Date().toISOString(),
        event_type: "TARIFF_DOWNGRADE",
        tariff: newTariff,
        detail: `Tariff downgraded from ${oldTariff} (effective ${oldEffective}) to ${newTariff} (effective ${newEffective}).`,
      });

      for (const [slotName, slot] of this.slots) {
        if (slot.status === "null" || !slot.adapter) continue;
        const gate = this.checkTariffGate(slotName);
        if (!gate.allowed || gate.availability === "null") {
          slot.status = "null";
          slot.adapter = null;
          slot.attestationSatisfied = false;
          deactivated.push(slotName);
          this.logCompliance({
            timestamp: new Date().toISOString(),
            event_type: "ADAPTER_DEACTIVATED",
            slot_name: slotName,
            tariff: newTariff,
            detail: `Adapter deactivated in slot '${slotName}' due to tariff downgrade to ${newTariff}.`,
          });
        }
      }
    }

    return { deactivated };
  }

  checkLicenseCompliance(): ComplianceAuditEntry[] {
    const violations: ComplianceAuditEntry[] = [];
    const effective = this.resolveEffectiveTariff();

    for (const [slotName, slot] of this.slots) {
      if (slot.status === "null" || !slot.adapter) continue;
      const config = CONNECTOR_SLOT_CONFIGS[slotName];

      if (config.adapterType === "C" && effective === "O") {
        const isNoOp = slot.adapter.name.startsWith("noop-");
        if (!isNoOp) {
          const entry: ComplianceAuditEntry = {
            timestamp: new Date().toISOString(),
            event_type: "LICENSE_COMPLIANCE_VIOLATION",
            slot_name: slotName,
            tariff: this.tariff,
            detail: `Non-NoOp Type C adapter '${slot.adapter.name}' registered at tariff ${this.tariff} (effective O). Type C requires tariff M or higher.`,
          };
          violations.push(entry);
          this.complianceLog.push(entry);
        }
      }
    }

    return violations;
  }

  getComplianceLog(): ComplianceAuditEntry[] {
    return [...this.complianceLog];
  }

  private logCompliance(entry: ComplianceAuditEntry): void {
    this.complianceLog.push(entry);
  }

  getSlotStatus(slotName: ConnectorSlotName): ConnectorSlotState {
    return { ...this.slots.get(slotName)! };
  }

  getAllSlotStatuses(): ConnectorSlotState[] {
    return Array.from(this.slots.values()).map((s) => ({ ...s }));
  }

  getTariff(): TariffCode {
    return this.tariff;
  }
}

export class NoOpPolicyDecisionAdapter implements PolicyDecisionAdapter {
  readonly adapterType = "Internal" as const;
  readonly name = "noop-pdp";

  async evaluateMandate(): Promise<{ allowed: boolean; reason: string }> {
    return { allowed: true, reason: "NoOp PDP — always permits" };
  }

  async validateCeilings(): Promise<{ valid: boolean }> {
    return { valid: true };
  }

  async evaluateAction(): Promise<{ allowed: boolean; reason: string }> {
    return { allowed: true, reason: "NoOp PDP — always permits" };
  }

  adjustSeverity(baseSeverity: string): string {
    return baseSeverity;
  }

  async healthCheck(): Promise<AdapterHealthResult> {
    return { healthy: true, latencyMs: 0, details: "NoOp PDP" };
  }
}

export class NoOpOAuthEngineAdapter implements OAuthEngineAdapter {
  readonly adapterType = "A" as const;
  readonly name = "noop-oauth";
  readonly packageNamespace = "@gauth/adapters";

  async issueToken(): Promise<{ token: string; expiresAt: string }> {
    throw new Error("NoOpOAuthEngineAdapter: issueToken not implemented. Register a real OAuth engine adapter.");
  }

  async validateToken(): Promise<{ valid: boolean; error: string }> {
    return { valid: false, error: "NoOp adapter" };
  }

  async revokeToken(_tokenId: string): Promise<{ revoked: boolean; tokenId: string }> {
    return { revoked: false, tokenId: _tokenId ?? "" };
  }

  async getJWKS(): Promise<{ keys: Record<string, unknown>[] }> {
    return { keys: [] };
  }

  async introspect(): Promise<{ active: boolean }> {
    return { active: false };
  }

  async beforeTokenIssuance(): Promise<Record<string, unknown>> {
    return {};
  }

  async afterTokenIssuance(): Promise<void> {}

  async healthCheck(): Promise<AdapterHealthResult> {
    return { healthy: false, latencyMs: 0, details: "NoOp OAuth — no real engine configured" };
  }
}

export class NoOpFoundryAdapter implements FoundryAdapter {
  readonly adapterType = "B" as const;
  readonly name = "noop-foundry";
  readonly packageNamespace = "@gauth/adapters";

  async executeAction(): Promise<{ success: boolean; error: string }> {
    return { success: false, error: "NoOpFoundryAdapter: no foundry connected." };
  }

  async getAgentCatalog(): Promise<Array<{ id: string; name: string; capabilities: string[] }>> {
    return [];
  }

  async getActionReport(_actionId: string): Promise<{ actionId: string; status: string }> {
    return { actionId: _actionId ?? "", status: "not_found" };
  }

  async validateSandbox(): Promise<{ valid: boolean; issues: string[] }> {
    return { valid: false, issues: ["No foundry connected"] };
  }

  async healthCheck(): Promise<AdapterHealthResult> {
    return { healthy: false, latencyMs: 0, details: "NoOp Foundry — no foundry connected" };
  }
}

export class NoOpWalletAdapter implements WalletAdapter {
  readonly adapterType = "B" as const;
  readonly name = "noop-wallet";
  readonly packageNamespace = "@gauth/adapters";

  async storeCredential(): Promise<{ id: string; stored: boolean }> {
    throw new Error("NoOpWalletAdapter: wallet not connected.");
  }

  async presentCredential(): Promise<Record<string, unknown>> {
    throw new Error("NoOpWalletAdapter: wallet not connected.");
  }

  async listCredentials(): Promise<Array<{ id: string; type: string; issuer: string }>> {
    return [];
  }

  async deleteCredential(): Promise<{ id: string; deleted: boolean }> {
    throw new Error("NoOpWalletAdapter: wallet not connected.");
  }

  async generateSelectiveDisclosure(): Promise<{ token: string }> {
    throw new Error("NoOpWalletAdapter: wallet not connected.");
  }

  async healthCheck(): Promise<AdapterHealthResult> {
    return { healthy: false, latencyMs: 0, details: "NoOp Wallet — no wallet connected" };
  }
}

export class NoOpGovernanceAdapter implements GovernanceAdapter {
  readonly adapterType = "C" as const;
  readonly name = "noop-ai-governance";
  readonly packageNamespace = "@gimel/ai-governance";

  async checkAccess(): Promise<{ allowed: boolean; reason: string }> {
    return { allowed: true, reason: "NoOp Governance — AI second-pass skipped, rule-based only" };
  }

  async getRecommendations(): Promise<Array<{ id: string; recommendation: string; severity: string }>> {
    return [];
  }

  async healthCheck(): Promise<AdapterHealthResult> {
    return { healthy: false, latencyMs: 0, details: "NoOp Governance — AI governance not active" };
  }
}

export class NoOpWeb3IdentityAdapter implements Web3IdentityAdapter {
  readonly adapterType = "C" as const;
  readonly name = "noop-web3-identity";
  readonly packageNamespace = "@gimel/web3-identity";

  async resolveIdentity(): Promise<null> {
    return null;
  }

  async verifyCredential(): Promise<{ verified: boolean; details: string }> {
    return { verified: false, details: "NoOp Web3 — Web3 identity not active" };
  }

  async healthCheck(): Promise<AdapterHealthResult> {
    return { healthy: false, latencyMs: 0, details: "NoOp Web3 — Web3 identity not active" };
  }
}

export class NoOpDNAIdentityAdapter implements DNAIdentityAdapter {
  readonly adapterType = "C" as const;
  readonly name = "noop-dna-identity";
  readonly packageNamespace = "@gimel/dna-identity";

  async resolveIdentity(): Promise<null> {
    return null;
  }

  async verifyBiometric(): Promise<{ verified: boolean; details: string }> {
    return { verified: false, details: "NoOp DNA — DNA identity not active" };
  }

  async healthCheck(): Promise<AdapterHealthResult> {
    return { healthy: false, latencyMs: 0, details: "NoOp DNA — DNA identity not active" };
  }
}

export class NoOpBillingAdapter implements BillingAdapter {
  readonly adapterType = "D" as const;
  readonly name = "noop-billing";

  async checkCredits(): Promise<{ allowed: boolean; balance: number; cost: number }> {
    return { allowed: true, balance: 0, cost: 0 };
  }

  async recordUsage(): Promise<void> {}

  async getBalance(): Promise<{ balanceCents: number; currency: string }> {
    return { balanceCents: 0, currency: "USD" };
  }

  async healthCheck(): Promise<AdapterHealthResult> {
    return { healthy: true, latencyMs: 0, details: "NoOp Billing — inactive (no Gimel-hosted services)" };
  }
}

export function createDefaultRegistry(): AdapterRegistry {
  return new AdapterRegistry();
}

export function computeS2SHeaders(
  body: unknown,
  platformKey: string,
  serviceSecret: string,
): { "X-GAuth-Platform-Key": string; "X-GAuth-HMAC-Signature": string } {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  const hmac = createHmac("sha256", serviceSecret);
  hmac.update(payload);
  const signature = "sha256=" + hmac.digest("hex");
  return {
    "X-GAuth-Platform-Key": platformKey,
    "X-GAuth-HMAC-Signature": signature,
  };
}

export function verifyS2SSignature(
  body: unknown,
  expectedSignature: string,
  serviceSecret: string,
): boolean {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  try {
    const hmac = createHmac("sha256", serviceSecret);
    hmac.update(payload);
    const computed = "sha256=" + hmac.digest("hex");
    if (computed.length !== expectedSignature.length) return false;
    return timingSafeEqual(Buffer.from(computed), Buffer.from(expectedSignature));
  } catch {
    return false;
  }
}
