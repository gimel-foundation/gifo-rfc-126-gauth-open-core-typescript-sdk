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

Located at `packages/gauth-core/`. TypeScript reference implementation of the GAuth authorization protocol (GiFo-RFCs 0116, 0117, 0118).

- **License**: MPL 2.0, embedded into Legal Terms of Gimel Foundation gGmbH i.G.
- **Exclusions (proprietary)**: AI-enabled Governance, Web3 Integration, DNA-based Identities, Post-Quantum Cryptography (PQC)
- **Dependencies**: `jose` (JWT), `zod` (validation)
- **Dev deps**: `tsup` (build), `vitest` (tests)
- **Build**: `pnpm --filter @gauth/core run build` — produces ESM + CJS + DTS in `dist/`
- **Version**: 0.91.0 (Public Preview)
- **Test**: `pnpm --filter @gauth/core run test` — 208 unit tests across 7 suites
- **Key modules**: `types.ts` (PoA schema, governance profiles, 7-slot connector model, tariff codes, W3C VC types), `pep.ts` (CHK-00 OAuth pre-validation + 16-check PEP engine), `management.ts` (mandate lifecycle, delegation approval gate, PoA map), `token.ts` (JWT RS256/ES256), `adapters.ts` (7-slot connector registry, manifest verification, namespace enforcement, tariff downgrade re-eval, compliance audit, S2S auth), `vc.ts` (W3C VC translation: PoA→VC, VP, Data Integrity Proofs, Bitstring Status List, SD-JWT, OID4VCI/VP), `http.ts` (HTTP bindings)
- **Adapter Types**: Internal (PDP), A (OAuth Engine), B (Foundry, Wallet), C (Governance, Web3, DNA — sealed/proprietary), D (Billing — internal)
- **Tariff Model**: O (Open Core), S (Small), M (Medium), L (Large), M+O (hybrid), L+O (hybrid) — controls adapter slot availability; hybrid codes resolve via tariffEffectiveLevel()
- **Legal Files**: `LICENSE` (MPL 2.0 + Gimel Foundation Supplementary Terms), `ADDITIONAL-TERMS.md` (exclusions), `CONTRIBUTING.md` (contribution/release policy v1.0)
- **Root README**: `README.md` — GitHub monorepo landing page with architecture overview, quick start, tariff model, and license info

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.
