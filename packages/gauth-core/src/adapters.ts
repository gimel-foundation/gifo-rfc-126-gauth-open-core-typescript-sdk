import type {
  PoACredential,
  GAuthJWTClaims,
  MandateDetail,
  GovernanceProfile,
  GovernanceProfileCeiling,
} from "./types.js";
import { DEFAULT_GOVERNANCE_CEILINGS } from "./types.js";

export interface OAuthEngineAdapter {
  readonly adapterType: "A";
  readonly name: string;
  readonly packageNamespace: string;

  issueToken(poa: PoACredential, options: Record<string, unknown>): Promise<string>;
  introspectToken(token: string): Promise<{ active: boolean; claims?: GAuthJWTClaims }>;
  revokeToken(token: string): Promise<void>;
  getJWKS(): Promise<Record<string, unknown>>;
}

export interface FoundryAdapter {
  readonly adapterType: "B";
  readonly name: string;
  readonly packageNamespace: string;

  executeAction(action: string, resource: string, parameters: Record<string, unknown>): Promise<{ success: boolean; result?: unknown; error?: string }>;
  validateEnvironment(): Promise<{ valid: boolean; capabilities: string[] }>;
}

export interface AIEnrichmentAdapter {
  readonly adapterType: "C";
  readonly name: string;
  readonly packageNamespace: string;

  enrichMandate(mandate: MandateDetail): Promise<{ enriched: boolean; suggestions?: Record<string, unknown>[] }>;
  assessRisk(mandate: MandateDetail): Promise<{ risk_score: number; risk_factors: string[] }>;
}

export interface RiskScoringAdapter {
  readonly adapterType: "C";
  readonly name: string;
  readonly packageNamespace: string;

  scoreMandate(mandate: MandateDetail): Promise<{ score: number; breakdown: Record<string, number>; recommendations: string[] }>;
}

export interface RegulatoryReasoningAdapter {
  readonly adapterType: "D";
  readonly name: string;
  readonly packageNamespace: string;

  evaluateCompliance(mandate: MandateDetail, regulations: string[]): Promise<{ compliant: boolean; violations: string[]; recommendations: string[] }>;
}

export type GAuthAdapter =
  | OAuthEngineAdapter
  | FoundryAdapter
  | AIEnrichmentAdapter
  | RiskScoringAdapter
  | RegulatoryReasoningAdapter;

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
    const ns = adapter.packageNamespace;

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

export class NoOpOAuthEngineAdapter implements OAuthEngineAdapter {
  readonly adapterType = "A" as const;
  readonly name = "noop-oauth";
  readonly packageNamespace = "@gauth/adapters";

  async issueToken(): Promise<string> {
    throw new Error("NoOpOAuthEngineAdapter: issueToken not implemented. Register a real OAuth engine adapter.");
  }

  async introspectToken(): Promise<{ active: boolean }> {
    return { active: false };
  }

  async revokeToken(): Promise<void> {}

  async getJWKS(): Promise<Record<string, unknown>> {
    return { keys: [] };
  }
}

export class NoOpFoundryAdapter implements FoundryAdapter {
  readonly adapterType = "B" as const;
  readonly name = "noop-foundry";
  readonly packageNamespace = "@gauth/adapters";

  async executeAction(): Promise<{ success: boolean; error: string }> {
    return { success: false, error: "NoOpFoundryAdapter: no foundry connected." };
  }

  async validateEnvironment(): Promise<{ valid: boolean; capabilities: string[] }> {
    return { valid: false, capabilities: [] };
  }
}

export function createDefaultRegistry(): AdapterRegistry {
  return new AdapterRegistry();
}
