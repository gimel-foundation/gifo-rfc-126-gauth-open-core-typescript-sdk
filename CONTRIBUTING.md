# Contributing to GAuth Open Core SDK

Thank you for your interest in contributing to the GAuth Open Core SDK. This document outlines the contribution process and policies.

## Contribution and Release Policy v1.0

### Accepted Contributions

We welcome contributions in the following areas:

- **Bug fixes** — Corrections to existing functionality
- **Test coverage** — Additional test cases that improve confidence
- **Documentation** — Improvements to guides, API docs, and examples
- **Adapter implementations** — New NoOp or reference adapter implementations
- **Performance improvements** — Optimizations that don't change public API behavior
- **Accessibility** — Dashboard UI accessibility improvements

### Contribution Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Implement** your changes following the coding standards below.
3. **Test** — Ensure all existing tests pass (`pnpm test`) and add tests for new functionality.
4. **Type-check** — Run `pnpm typecheck` across all packages.
5. **Submit** a pull request with a clear description of the change.

### Coding Standards

- **TypeScript** — All source code must be TypeScript with strict mode enabled.
- **No `any`** — Avoid `any` types; use `unknown` with type narrowing where needed.
- **Zod schemas** — All API boundaries must use Zod for runtime validation.
- **Pure functions** — Prefer pure functions over stateful classes where practical.
- **Naming** — Use `camelCase` for variables/functions, `PascalCase` for types/classes, `UPPER_SNAKE_CASE` for constants.
- **File extensions** — Use `.ts` for source files; import with `.js` extensions for ESM compatibility.

### RFC Compliance

Changes that affect protocol behavior must reference the relevant GiFo-RFC section and version. Modifications that would break RFC compliance will not be accepted unless accompanied by an RFC amendment proposal.

### Versioning

This project follows semantic versioning with the following conventions:

- **0.91.x** — Public Preview phase (current)
- Breaking changes are expected during Public Preview
- The version will advance to 1.0.0 upon GA release

### License

By submitting a contribution, you agree that your contribution will be licensed under the MPL-2.0 license, subject to the Additional Terms described in `ADDITIONAL-TERMS.md`.

### Code of Conduct

Contributors are expected to maintain professional, respectful communication. The Gimel Foundation reserves the right to reject contributions or revoke contributor access for violations of professional conduct standards.

## Getting Started

```bash
# Install dependencies
pnpm install

# Run tests
pnpm --filter @gauth/core test

# Type-check all packages
pnpm typecheck

# Build the API server
pnpm --filter @workspace/api-server run build

# Start the dashboard
pnpm --filter @workspace/dashboard run dev
```

## Package Structure

| Package | Description |
|---------|-------------|
| `@gauth/core` | Core TypeScript SDK — types, PEP, management, adapters, VC layer |
| `@workspace/api-server` | Express API server with GAuth routes |
| `@workspace/dashboard` | React + Vite governance dashboard |
| `@workspace/db` | Drizzle ORM database schemas |
| `@workspace/api-zod` | Zod validation schemas for API boundaries |
| `@workspace/api-client-react` | React Query hooks for the management API |

## Questions?

- **Protocol questions:** rfcs@gimelfoundation.com
- **SDK issues:** Open a GitHub issue
- **Security vulnerabilities:** security@gimelfoundation.com (do not open public issues)
