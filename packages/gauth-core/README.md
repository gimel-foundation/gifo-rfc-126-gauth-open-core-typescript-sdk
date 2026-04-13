# @gauth/core

**Version 0.91.0 — Public Preview**

**GAuth Open Core TypeScript SDK** — the reference implementation of the GAuth authorization protocol for AI agent governance.

Implements [GiFo-RFCs 0110/0111, 0115, 0116 v2.2, 0117 v1.2, 0118 v1.1](https://gimelfoundation.com/rfcs) from Gimel Foundation.

## What is GAuth?

GAuth is an open authorization protocol that brings Power-of-Attorney (PoA) credentials to AI agent systems. It provides a structured way to:

- **Issue** PoA credentials that define what an AI agent is allowed to do
- **Enforce** those credentials at runtime via a Policy Enforcement Point (PEP)
- **Manage** mandate lifecycles (create, activate, suspend, revoke, delegate)
- **Govern** agent behavior through governance profiles, budgets, and session limits

## What's in the Box

| Module | Description |
|--------|-------------|
| `types` | PoA schema, enforcement types, management types, violation codes, tariff codes, connector slot model |
| `crypto` | Canonical JSON, SHA-256 checksums, scope checksum computation |
| `token` | JWT creation/validation with RS256/ES256, scope checksum verification |
| `pep` | 16-check PEP enforcement pipeline (stateless + stateful modes) |
| `management` | Mandate lifecycle CRUD, budget operations, delegation, governance profile assignment |
| `adapters` | 7-slot connector model, adapter registry, tariff gating, Type C attestation, S2S auth |
| `http` | HTTP bindings for PEP and Management API endpoints |

## Architecture

```
SDK Client
    │
    ├─ PEP Layer (RFC 0117)     → Enforce PoA credentials at runtime
    │     POST /gauth/pep/v1/enforce
    │     POST /gauth/pep/v1/enforce/batch
    │     POST /gauth/pep/v1/policy
    │     GET  /gauth/pep/v1/health
    │
    ├─ Management Layer (RFC 0118) → CRUD mandate lifecycle
    │     POST   /gauth/mgmt/v1/mandates
    │     POST   /gauth/mgmt/v1/mandates/:id/activate
    │     POST   /gauth/mgmt/v1/mandates/:id/revoke
    │     POST   /gauth/mgmt/v1/mandates/:id/suspend
    │     POST   /gauth/mgmt/v1/mandates/:id/resume
    │     POST   /gauth/mgmt/v1/mandates/:id/delegate
    │     PUT    /gauth/mgmt/v1/mandates/:id/governance-profile
    │     POST   /gauth/mgmt/v1/mandates/:id/budget/top-up
    │     POST   /gauth/mgmt/v1/mandates/:id/ttl/extend
    │
    └─ Connector Layer → 7-slot adapter model with tariff gating
```

## Installation

```bash
npm install @gauth/core
# or
pnpm add @gauth/core
```

Requires Node.js >= 18.0.0.

## Quick Start

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

### Integration Patterns

GAuth supports three deployment patterns:

| Pattern | Description | SDK Deliverable |
|---------|-------------|-----------------|
| **Sidecar** | Claims provider for existing OAuth/OIDC servers (Keycloak, Azure AD, Auth0, etc.) | `OAuthEngineAdapter` claims provider library |
| **Gateway** | PEP middleware at the API gateway (Express, Go, NGINX, Envoy) | PEP middleware library |
| **Full Stack** | Integrated OAuth + Management + PEP bundle for greenfield deployments | Deployment bundle |

### 7-Slot Connector Model

| Slot | Name | Type | Description |
|------|------|------|-------------|
| 1 | `pdp` | Internal | Policy Decision Engine (mandatory) |
| 2 | `oauth_engine` | A | OAuth/OIDC Engine (mandatory) |
| 3 | `foundry` | B | Agent Foundry (optional) |
| 4 | `wallet` | B | Credential Wallet (optional) |
| 5 | `ai_governance` | C | AI Governance — sealed, proprietary |
| 6 | `web3_identity` | C | Web3 Identity — sealed, proprietary |
| 7 | `dna_identity` | C | DNA Identity — sealed, proprietary |

### PEP Engine (16 Checks)

| Check | Name | Description |
|-------|------|-------------|
| CHK-01 | Credential Integrity | Validates credential structure and scope checksum |
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

### Governance Profiles

| Profile | Max TTL | Max Budget | Delegation | Deploy Targets |
|---------|---------|-----------|------------|----------------|
| `minimal` | 1h | $10 | 0 | none |
| `standard` | 12h | $100 | 1 | dev, staging |
| `strict` | 24h | $500 | 2 | dev, staging |
| `enterprise` | 7d | $5,000 | 3 | dev, staging, prod |
| `behoerde` | 24h | $1,000 | 2 | dev, staging |

### Tariff Gating

| Tariff | Description | Type C Access |
|--------|-------------|---------------|
| **O** (Open Core) | Self-hosted, rule-based PEP only | None |
| **S** (Small) | Entry paid tier | None |
| **M** (Medium) | Full platform with AI governance | Slots 5-6 |
| **L** (Large) | Enterprise, all adapters | Slots 5-7 |

## License — Dual-Layer Coexistence

This SDK uses a dual-layer licensing model. Both licenses coexist — they do not replace each other:

| Layer | License | Scope | Revocable? |
|-------|---------|-------|------------|
| SDK source code | MPL 2.0 | File-level copyleft on SDK files; your own files in separate modules remain under your chosen license | No — irrevocable |
| Proprietary Gimel services | Gimel Technologies ToS | Governs access to Gimel-hosted services (Auth-as-a-Service, Foundry, AI Governance, Web3 Identity, DNA Identity) | Yes — service relationship |
| Open specifications (RFCs) | Apache 2.0 | Interoperability protocols (RFC 0116, 0117, 0118) | No — irrevocable |

**In practice:** You may run the SDK in pure Open Core mode (MPL 2.0 only, self-hosted, no Gimel services) indefinitely. If you choose to use proprietary Gimel services, the Gimel Technologies ToS applies *in addition to* MPL 2.0 — not as a replacement. Your SDK code and modifications to SDK files remain MPL 2.0 regardless.

See [LICENSE](LICENSE) and [ADDITIONAL-TERMS.md](ADDITIONAL-TERMS.md) for the full legal text.

### Open Core Exclusions

Three capabilities are excluded from the open-source license and are available
only under the Gimel Technologies Terms of Service:

1. **AI-Enabled Governance** (Slot 5)
2. **Web3 Identity Integration** (Slot 6)
3. **DNA-Based Identities / PQC** (Slot 7)

The full PEP enforcement pipeline (16 checks), Management API, and all Type A/B
adapter interfaces are fully open-source under MPL 2.0.

Contributions to Excluded Components require a separate CLA. Contact: info@gimelid.com

Copyright (c) 2026 Gimel Foundation gGmbH i.G. | [gimelfoundation.com](https://gimelfoundation.com)
