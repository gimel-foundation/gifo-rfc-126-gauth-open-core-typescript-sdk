# GAuth Open Core SDK

**Version 0.9.3 — Public Preview**

**Reference implementation of the GAuth authorization protocol for AI agent governance.**

Implements [GiFo-RFCs 0110/0111, 0115, 0116 v2.2, 0117 v1.2, 0118 v1.1](https://gimelfoundation.com/rfcs) from Gimel Foundation.

## What is GAuth?

GAuth is an open authorization protocol that brings Power-of-Attorney (PoA) credentials to AI agent systems. It provides a structured way to issue, enforce, and manage credentials that define what an AI agent is allowed to do — across governance profiles, budgets, session limits, delegation chains, and deployment targets.

## Repository Structure

```
gauth-core-ts/
├── packages/
│   └── gauth-core/           # @gauth/core — TypeScript SDK
│       ├── src/
│       │   ├── types.ts       # PoA schema, governance profiles, connector model, tariffs
│       │   ├── crypto.ts      # Canonical JSON, SHA-256, scope checksums
│       │   ├── token.ts       # JWT creation/validation (RS256, ES256)
│       │   ├── pep.ts         # 16-check Policy Enforcement Point pipeline
│       │   ├── management.ts  # Mandate lifecycle CRUD, budgets, delegation
│       │   ├── adapters.ts    # 7-slot connector registry, tariff gating, S2S auth
│       │   ├── http.ts        # HTTP bindings for PEP and Management API
│       │   └── index.ts       # Public API exports
│       ├── LICENSE            # Mozilla Public License 2.0
│       ├── ADDITIONAL-TERMS.md # Gimel Foundation Additional Terms (exclusions)
│       ├── CONTRIBUTING.md    # Contribution and Release Policy v1.0
│       └── README.md          # SDK documentation
├── pnpm-workspace.yaml
└── README.md                  # ← you are here
```

## SDK Packages

| Package | npm | Description |
|---------|-----|-------------|
| [`@gauth/core`](packages/gauth-core/) | [![npm](https://img.shields.io/npm/v/@gauth/core)](https://www.npmjs.com/package/@gauth/core) | TypeScript reference implementation — PEP, Management API, 7-slot connector model |

## Quick Start

```bash
pnpm add @gauth/core
```

```typescript
import { enforceAction, isEnforcementError } from "@gauth/core";

const result = await enforceAction(
  {
    request_id: "req-001",
    timestamp: new Date().toISOString(),
    action: { verb: "foundry.file.create", resource: "src/utils/helpers.ts" },
    agent: { agent_id: "agent-001" },
    credential: { format: "jwt", poa_snapshot: {} },
  },
  poa,
);

if (isEnforcementError(result)) {
  console.error("PEP error:", result.message);
} else {
  console.log(result.decision); // "PERMIT" | "DENY" | "CONSTRAIN"
}
```

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                     GAuth SDK                          │
├────────────────┬───────────────────┬───────────────────┤
│  PEP Layer     │  Management Layer │  Connector Layer  │
│  (RFC 0117)    │  (RFC 0118)       │  (7-Slot Model)   │
│                │                   │                   │
│  16-check      │  Mandate CRUD     │  PDP (Internal)   │
│  enforcement   │  Budget ops       │  OAuth Engine (A)  │
│  pipeline      │  Delegation       │  Foundry (B)      │
│                │  Governance       │  Wallet (B)       │
│                │  profiles         │  Governance (C)   │
│                │                   │  Web3 Identity (C) │
│                │                   │  DNA Identity (C)  │
└────────────────┴───────────────────┴───────────────────┘
```

## Integration Patterns

| Pattern | Description |
|---------|-------------|
| **Sidecar** | Claims provider for existing OAuth/OIDC servers (Keycloak, Azure AD, Auth0, Ory Hydra) |
| **Gateway** | PEP middleware at the API gateway (Express, Go, NGINX, Envoy) |
| **Full Stack** | Integrated OAuth + Management + PEP bundle for greenfield deployments |

## Tariff Model

| Tariff | Description | Type C Adapters |
|--------|-------------|-----------------|
| **O** (Open Core) | Self-hosted, rule-based PEP only | None |
| **S** (Small) | Entry paid tier | None |
| **M** (Medium) | Full platform with AI governance | Slots 5–6 |
| **L** (Large) | Enterprise, all adapters | Slots 5–7 |

## Development

```bash
# Install dependencies
pnpm install

# Type check
pnpm --filter @gauth/core run typecheck

# Run tests (161 unit tests)
pnpm --filter @gauth/core run test

# Build (ESM + CJS + DTS)
pnpm --filter @gauth/core run build
```

## Contributing

See [CONTRIBUTING.md](packages/gauth-core/CONTRIBUTING.md) for the branch model, contribution streams, CI gates, and release process.

All contributions enter `main` through reviewed pull requests. The architecture team works on the `replit` integration branch; community contributors work on `feature/*` and `fix/*` branches.

## License — Dual-Layer Coexistence

This SDK uses a dual-layer licensing model. Both licenses coexist — they do not replace each other:

| Layer | License | Scope | Revocable? |
|-------|---------|-------|------------|
| SDK source code | MPL 2.0 | File-level copyleft on SDK files; your own files in separate modules remain under your chosen license | No — irrevocable |
| Proprietary Gimel services | Gimel Technologies ToS | Governs access to Gimel-hosted services (Auth-as-a-Service, Foundry, AI Governance, Web3 Identity, DNA Identity) | Yes — service relationship |
| Open specifications (RFCs) | Apache 2.0 | Interoperability protocols (RFC 0116, 0117, 0118) | No — irrevocable |

**In practice:** You may run the SDK in pure Open Core mode (MPL 2.0 only, self-hosted, no Gimel services) indefinitely. If you choose to use proprietary Gimel services, the Gimel Technologies ToS applies *in addition to* MPL 2.0 — not as a replacement. Your SDK code and modifications to SDK files remain MPL 2.0 regardless.

**CCPE Integration:** This SDK is published by the Gimel Foundation under MPL 2.0. The SDK may be used standalone under the MPL 2.0 terms alone. When integrated into a CCPE architecture pattern as defined by the Gimel Conformance Framework, the normative requirements of the applicable CCPE RFCs additionally apply.

See [LICENSE](packages/gauth-core/LICENSE) and [ADDITIONAL-TERMS.md](packages/gauth-core/ADDITIONAL-TERMS.md) for the full legal text.

### Open Core Exclusions

Three capabilities are excluded from the open-source license and are available only under the Gimel Technologies Terms of Service:

1. **AI-Enabled Governance** (Connector Slot 5)
2. **Web3 Identity Integration** (Connector Slot 6)
3. **DNA-Based Identities / PQC** (Connector Slot 7)

The full PEP enforcement pipeline (16 checks), Management API, and all Type A/B adapter interfaces are fully open-source under MPL 2.0.

Contributions to Excluded Components require a separate CLA. Contact: info@gimelid.com

---

Copyright (c) 2026 Gimel Foundation gGmbH i.G. | [gimelfoundation.com](https://gimelfoundation.com)
