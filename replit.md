# Workspace

## Overview

pnpm workspace monorepo using TypeScript. Each package manages its own dependencies.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)

## GAuth Open Core SDK (`@gauth/core`)

Located at `packages/gauth-core/`. TypeScript reference implementation of the GAuth authorization protocol (GiFo-RFCs 0110/0111, 0115, 0116 v2.2, 0117 v1.2, 0118 v1.1).

- **License**: MPL 2.0, embedded into Legal Terms of Gimel Foundation gGmbH i.G.
- **Exclusions (proprietary)**: AI-enabled Governance, Web3 Integration, DNA-based Identities, Post-Quantum Cryptography (PQC)
- **Dependencies**: `jose` (JWT), `zod` (validation)
- **Dev deps**: `tsup` (build), `vitest` (tests)
- **Build**: `pnpm --filter @gauth/core run build` — produces ESM + CJS + DTS in `dist/`
- **Version**: 0.92.0 (Public Preview)
- **Test**: `pnpm --filter @gauth/core run test` — 234 unit tests across 7 suites
- **Key modules**: `types.ts` (PoA schema, governance profiles, 7-slot connector model, tariff codes, W3C VC types), `pep.ts` (CHK-00 OAuth pre-validation + 16-check PEP engine), `management.ts` (mandate lifecycle, delegation approval gate, PoA map), `token.ts` (JWT RS256/ES256), `adapters.ts` (7-slot connector registry, manifest verification, namespace enforcement, tariff downgrade re-eval, compliance audit, S2S auth), `vc.ts` (W3C VC translation: PoA→VC, VP, Data Integrity Proofs, Bitstring Status List, SD-JWT, OID4VCI/VP), `http.ts` (HTTP bindings)
- **Adapter Types**: Internal (PDP), A (OAuth Engine), B (Foundry, Wallet), C (Governance, Web3, DNA — sealed/proprietary), D (Billing — internal)
- **Tariff Model**: O (Open Core), S (Small), M (Medium), L (Large), M+O (hybrid), L+O (hybrid) — controls adapter slot availability; hybrid codes resolve via tariffEffectiveLevel()
- **Legal Files**: `LICENSE` (MPL 2.0 + Gimel Foundation Supplementary Terms), `ADDITIONAL-TERMS.md` (exclusions), `CONTRIBUTING.md` (contribution/release policy v1.0)
- **Root README**: `README.md` — GitHub monorepo landing page with architecture overview, quick start, tariff model, and license info

## API Server (`@workspace/api-server`)

Located at `artifacts/api-server/`. Express 5 server mounting GAuth endpoints.

- **Routes**: `gauth-mgmt.ts` (Management API: mandate CRUD, delegation, budget, TTL, PoA map), `gauth-pep.ts` (PEP: enforce, batch, policy, health), `gauth-vci-vp.ts` (VCI/VP: credential issuance, presentations, DID resolution, OpenID4VCI/VP)
- **Mount path**: `/api/` prefix (e.g., `/api/gauth/mgmt/v1/mandates`)
- **Port**: 8080

## Governance Dashboard (`@workspace/dashboard`)

Located at `artifacts/dashboard/`. React + Vite + Tailwind dashboard with Gimel Foundation purple branding.

- **Pages**: Dashboard (health + stats), Mandates (list/detail), Credentials (VC list + standards), Profiles (governance profiles + tariff table), PoA Map (delegation tree)
- **Theme**: Purple primary (HSL 267 84% 58%), Gimel Foundation branding
- **API hooks**: `@workspace/api-client-react` (React Query hooks for all management/PEP endpoints)
- **Port**: 23183, preview path: `/dashboard/`

## Shared Libraries

- **`@workspace/api-zod`** (`lib/api-zod/`): Zod validation schemas for GAuth types
- **`@workspace/api-client-react`** (`lib/api-client-react/`): React Query hooks for management API endpoints
- **`@workspace/db`** (`lib/db/`): Drizzle ORM schemas for mandates, credentials, audit_logs, governance_profiles

## Documentation

- `docs/sdk-implementation-guide.md` — Full SDK integration guide
- `docs/api-reference.md` — API endpoint reference
- `CONTRIBUTING.md` — Contribution and release policy
- `ADDITIONAL-TERMS.md` — Gimel Foundation additional terms
- `LICENSE` — Mozilla Public License 2.0

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally
- `pnpm --filter @gauth/core run test` — run core SDK tests

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.
