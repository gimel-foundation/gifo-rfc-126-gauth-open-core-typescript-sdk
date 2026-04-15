# GAuth SDK Implementation Guide

## Overview

The `@gauth/core` TypeScript SDK provides a complete implementation of the GAuth authorization protocol for AI agent governance. This guide covers integration patterns for each major subsystem.

## Quick Start

```typescript
import {
  ManagementAPI,
  InMemoryMandateStore,
  enforceAction,
  poaToVerifiableCredential,
} from "@gauth/core";

const store = new InMemoryMandateStore();
const mgmt = new ManagementAPI(store);

const mandate = await mgmt.createMandate({
  issuer: "org:acme",
  subject_agent_id: "agent:assistant-01",
  governance_profile: "standard",
  phase: "supervised",
  budget_cents: 100_00,
  scope: {
    tools: { allowed: ["file_read", "web_search"], denied: ["shell_exec"] },
    deployment: { targets: ["development"] },
  },
});
```

## 1. Mandate Lifecycle (RFC 0110/0118)

### Creating Mandates

```typescript
const result = await mgmt.createMandate({
  issuer: "org:acme",
  subject_agent_id: "agent:my-agent",
  governance_profile: "standard",
  phase: "supervised",
  budget_cents: 50_00,
  ttl_seconds: 3600,
  max_delegation_depth: 2,
  scope: {
    tools: { allowed: ["*"], denied: ["shell_exec"] },
  },
});

if ("error_code" in result) {
  console.error(result.message);
} else {
  console.log("Created:", result.mandate_id);
}
```

### State Transitions

Mandates follow this lifecycle: `DRAFT -> ACTIVE -> SUSPENDED | REVOKED | EXPIRED`

```typescript
await mgmt.activateMandate({ mandate_id: id, activated_by: "admin" });
await mgmt.suspendMandate({ mandate_id: id, suspended_by: "admin", reason: "review" });
await mgmt.resumeMandate({ mandate_id: id, resumed_by: "admin", reason: "cleared" });
await mgmt.revokeMandate({ mandate_id: id, revoked_by: "admin", reason: "terminated" });
```

### Budget and TTL Management

```typescript
await mgmt.topUpBudget({
  mandate_id: id,
  additional_cents: 25_00,
  performed_by: "billing-system",
});

await mgmt.extendTTL({
  mandate_id: id,
  additional_seconds: 1800,
  performed_by: "admin",
});
```

## 2. Policy Enforcement Point (RFC 0111)

The PEP runs a 16-check pipeline on every action request:

```typescript
import { enforceAction } from "@gauth/core";

const decision = enforceAction(
  {
    action: { verb: "file_read", resource: "/data/report.csv" },
    agent: { agent_id: "agent:assistant-01", session_id: "sess-001" },
    credential: poaCredential,
  },
  { strict: true }
);

if (decision.decision === "ALLOW") {
  console.log("Action permitted");
} else {
  console.log("Denied:", decision.violations);
}
```

### Batch Enforcement

```typescript
import { batchEnforce } from "@gauth/core";

const results = batchEnforce(
  [request1, request2, request3],
  "fail-fast",
  poaCredential
);
```

### HTTP PEP Server

```typescript
import { handlePEPRequest } from "@gauth/core";

app.post("/gauth/pep/v1/enforce", async (req, res) => {
  const result = await handlePEPRequest({
    method: req.method,
    path: req.path,
    body: req.body,
    headers: req.headers,
  });
  res.status(result.status).json(result.body);
});
```

## 3. Delegation and Narrowing (RFC 0117)

Delegation creates child mandates with narrowed scope:

```typescript
const delegation = await mgmt.createDelegation({
  parent_mandate_id: parentId,
  delegate_agent_id: "agent:sub-agent-02",
  scope_restriction: {
    tools: { allowed: ["web_search"] },
  },
  delegated_by: "agent:assistant-01",
  max_depth: 1,
});
```

PP-07 fail-closed narrowing ensures child mandates can never exceed parent scope.

## 4. Governance Profiles

Three built-in profiles control enforcement intensity:

| Profile | Phase | Description |
|---------|-------|-------------|
| `strict` | exploration | Maximum oversight, all actions require approval |
| `standard` | supervised | Balanced governance, common actions pre-approved |
| `permissive` | autonomous | Minimal friction, broad action approval |

## 5. Tariff Model (RFC 0116)

The tariff model controls adapter licensing:

| Code | Level | Type |
|------|-------|------|
| O | Open | Community adapters |
| M | Managed | Enterprise with SLA |
| L | Licensed | Licensed with support |
| M+O | Managed | Hybrid managed + open fallback |
| L+O | Licensed | Hybrid licensed + open fallback |

```typescript
import { tariffEffectiveLevel, AdapterRegistry } from "@gauth/core";

const level = tariffEffectiveLevel("M+O");
```

## 6. Adapter Registry

Seven connector slots for extensibility:

```typescript
import { createDefaultRegistry } from "@gauth/core";

const registry = createDefaultRegistry();
```

Slots: PolicyDecision, OAuthEngine, Foundry, Wallet, Governance, Web3Identity, Billing.

## 7. Verifiable Credentials (RFC 0115)

### Issuing Credentials

```typescript
import {
  poaToVerifiableCredential,
  createDataIntegrityProof,
  attachProof,
} from "@gauth/core";

const vc = poaToVerifiableCredential(poaCredential, "did:web:issuer.example.com");
const proof = createDataIntegrityProof(vc, "did:web:issuer.example.com");
const signed = attachProof(vc, proof);
```

### Presentations

```typescript
import { createVerifiablePresentation } from "@gauth/core";

const vp = createVerifiablePresentation(
  "did:web:holder.example.com",
  [signedVc]
);
```

### DID Resolution

```typescript
import { resolveDid } from "@gauth/core";

const doc = resolveDid("did:key:z6Mk...");
const doc2 = resolveDid("did:web:example.com");
```

## 8. HTTP API Server

The SDK includes pre-built HTTP handlers for Express:

```typescript
import express from "express";
import { handlePEPRequest, handleMgmtRequest, ManagementAPI, InMemoryMandateStore } from "@gauth/core";

const app = express();
const store = new InMemoryMandateStore();
const mgmt = new ManagementAPI(store);

app.use(express.json());

app.all("/gauth/pep/v1/*", async (req, res) => {
  const result = await handlePEPRequest({ method: req.method, path: req.path, body: req.body, headers: req.headers });
  res.status(result.status).json(result.body);
});

app.all("/gauth/mgmt/v1/*", async (req, res) => {
  const result = await handleMgmtRequest({ method: req.method, path: req.path, body: req.body, headers: req.headers }, mgmt);
  res.status(result.status).json(result.body);
});
```

## 9. PoA Map

Generate a visualization of the mandate delegation hierarchy:

```typescript
const map = mgmt.generatePoaMap();
```

Returns an array of `PoaMapSummary` entries with delegation depth, parent references, and status.
