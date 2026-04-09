# @gauth/core

**GAuth Open Core TypeScript SDK** — the reference implementation of the GAuth authorization protocol for AI agent governance.

Implements [GiFo-RFCs 0110/0111, 0115, 0116, 0117, 0118](https://gimelfoundation.com/rfcs) from Gimel Foundation.

## What is GAuth?

GAuth is an open authorization protocol that brings Power-of-Attorney (PoA) credentials to AI agent systems. It provides a structured way to:

- **Issue** PoA credentials that define what an AI agent is allowed to do
- **Enforce** those credentials at runtime via a Policy Enforcement Point (PEP)
- **Manage** mandate lifecycles (create, activate, suspend, revoke, delegate)
- **Govern** agent behavior through governance profiles, budgets, and session limits

## Installation

```bash
npm install @gauth/core
# or
pnpm add @gauth/core
```

Requires Node.js >= 18.0.0.

## Quick Start

### Define a PoA Credential

```typescript
import type { PoACredential } from "@gauth/core";

const poa: PoACredential = {
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
      "foundry.file.delete": { allowed: true, constraints: { path_patterns: ["src/**"] } },
      "foundry.command.run": { allowed: true, constraints: { denied_commands: ["rm -rf"] } },
      "foundry.agent.delegate": { allowed: false },
    },
    allowed_paths: ["src/", "tests/"],
    denied_paths: [".env", "secrets/", "node_modules/"],
  },
  requirements: {
    approval_mode: "autonomous",
    budget: { total_cents: 10000 },
    ttl_seconds: 3600,
    session_limits: { max_tool_calls: 500 },
  },
};
```

### Enforce Actions (PEP)

```typescript
import { enforceAction, isEnforcementError } from "@gauth/core";

const result = await enforceAction(
  {
    request_id: "req-001",
    timestamp: new Date().toISOString(),
    action: {
      verb: "foundry.file.create",
      resource: "src/utils/helpers.ts",
    },
    agent: { agent_id: "agent-001" },
    credential: { format: "jwt", poa_snapshot: {} },
  },
  poa,
);

if (isEnforcementError(result)) {
  console.error("PEP error:", result.message);
} else {
  console.log(result.decision); // "PERMIT" | "DENY" | "CONSTRAIN"
  console.log(result.checks);   // 16 check results (CHK-01..CHK-16)
}
```

### Manage Mandates

```typescript
import { ManagementAPI, InMemoryMandateStore } from "@gauth/core";

const api = new ManagementAPI(new InMemoryMandateStore());

const mandate = await api.createMandate({
  parties: {
    subject: "agent-001",
    customer_id: "cust-123",
    project_id: "proj-456",
    issued_by: "admin@example.com",
  },
  scope: poa.scope,
  requirements: {
    approval_mode: "autonomous",
    budget: { total_cents: 10000 },
    ttl_seconds: 3600,
  },
});

// Lifecycle: DRAFT → ACTIVE → SUSPENDED ↔ ACTIVE → REVOKED/EXPIRED
const activation = await api.activateMandate({
  mandate_id: mandate.mandate_id,
  activated_by: "admin@example.com",
});
```

### JWT Token Creation & Validation

```typescript
import { createExtendedToken, validateExtendedToken } from "@gauth/core";
import { generateKeyPair } from "jose";

const { privateKey, publicKey } = await generateKeyPair("RS256");

const token = await createExtendedToken(poa, {
  privateKey,
  keyId: "key-001",
  issuer: "https://auth.example.com",
  audience: ["https://api.example.com"],
  credentialId: "cred-001",
});

const validated = await validateExtendedToken(token, {
  publicKey,
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
});
```

## Architecture

### PEP Engine (16 Checks)

The Policy Enforcement Point evaluates every action request against 16 sequential checks:

| Check | Name | Description |
|-------|------|-------------|
| CHK-01 | Credential Integrity | Validates credential structure |
| CHK-02 | Temporal & Status | Expiry, agent match, mandate status |
| CHK-03 | Governance Profile | Profile ceiling validation |
| CHK-04 | Phase | Phase-verb compatibility |
| CHK-05 | Sector | Sector restrictions |
| CHK-06 | Region | Region/geo restrictions (EU expansion) |
| CHK-07 | Path | Allowed/denied path matching |
| CHK-08 | Verb Permission | Core verb authorization |
| CHK-09 | Verb Constraints | Verb-specific constraints |
| CHK-10 | Platform Permissions | Deployment, DB, shell, etc. |
| CHK-11 | Transaction Type | Transaction type validation |
| CHK-12 | Decision Type | Decision type validation |
| CHK-13 | Budget | Budget enforcement & capping |
| CHK-14 | Session Limits | Tool call & session limits |
| CHK-15 | Approval | Approval mode enforcement |
| CHK-16 | Delegation Chain | Delegation depth & scope |

The PEP is **fail-closed**: any check failure results in DENY.

### Governance Profiles

Five built-in profiles with increasing capability ceilings:

| Profile | Max TTL | Max Budget | Delegation | Deploy Targets |
|---------|---------|-----------|------------|----------------|
| `minimal` | 1h | $10 | 0 | none |
| `standard` | 12h | $100 | 1 | dev, staging |
| `strict` | 24h | $500 | 2 | dev, staging |
| `enterprise` | 7d | $5,000 | 3 | dev, staging, prod |
| `behoerde` | 24h | $1,000 | 2 | dev, staging |

### Mandate Lifecycle

```
DRAFT → ACTIVE → SUSPENDED (reversible)
                → REVOKED (terminal)
                → EXPIRED (terminal)
                → BUDGET_EXCEEDED (terminal)
                → SUPERSEDED (terminal)
```

- **Scope is immutable** once ACTIVE — only budget ceiling and TTL may increase
- Budget and TTL are **additive-only** (can only increase, never decrease)
- Activating a new mandate for the same agent+project **supersedes** the existing one

### Adapter System

| Type | Name | Status |
|------|------|--------|
| A | OAuthEngineAdapter | Open (MPL 2.0) |
| B | FoundryAdapter | Open (MPL 2.0) |
| C | AIEnrichmentAdapter / RiskScoringAdapter | Sealed registration |
| D | RegulatoryReasoningAdapter | Sealed registration |

Adapters must come from trusted namespaces (`@gauth/`, `@gimel/`, `@gimel-foundation/`).

## HTTP Bindings

The SDK includes HTTP request/response handlers for embedding PEP and Management API into any HTTP framework:

```typescript
import { handlePEPRequest, handleMgmtRequest } from "@gauth/core";

// PEP endpoints:
// GET  /gauth/pep/v1/health
// POST /gauth/pep/v1/enforce
// POST /gauth/pep/v1/enforce/batch
// POST /gauth/pep/v1/policy

// Management endpoints:
// POST /gauth/mgmt/v1/mandates
// GET  /gauth/mgmt/v1/mandates/:id
// POST /gauth/mgmt/v1/mandates/:id/activate
// POST /gauth/mgmt/v1/mandates/:id/revoke
// POST /gauth/mgmt/v1/mandates/:id/suspend
// POST /gauth/mgmt/v1/mandates/:id/resume
// POST /gauth/mgmt/v1/mandates/:id/budget/top-up
// POST /gauth/mgmt/v1/mandates/:id/ttl/extend
```

## License

**MPL 2.0** — embedded into the Legal Terms of Gimel Foundation gGmbH i.G.

### Exclusions (NOT covered by MPL 2.0)

The following are subject to **separate, proprietary licensing** by Gimel Foundation or Gimel Technologies GmbH:

- **AI-enabled Governance** — AI systems that autonomously control the authorization lifecycle
- **Web3 Integration** — blockchain, DLT, Web3 tokens, smart contracts
- **DNA-based Identities** — identity systems based on genetic data or genomic identifiers
- **Post-Quantum Cryptography (PQC)** — quantum-resistant cryptographic schemes and their GAuth integration

See [LICENSE](./LICENSE) for full terms.

Copyright (c) 2026 Gimel Foundation gGmbH i.G. | [gimelfoundation.com](https://gimelfoundation.com)
