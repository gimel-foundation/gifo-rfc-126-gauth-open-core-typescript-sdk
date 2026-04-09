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
- **Test**: `pnpm --filter @gauth/core run test` — 98 unit tests across 6 suites
- **Key modules**: `types.ts` (PoA schema, governance profiles), `pep.ts` (16-check PEP engine), `management.ts` (mandate lifecycle), `token.ts` (JWT), `adapters.ts` (sealed adapter registry), `http.ts` (HTTP bindings)

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.
