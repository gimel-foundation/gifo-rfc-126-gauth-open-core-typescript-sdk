# GAuth API Reference

## Management API Endpoints

All management endpoints are mounted under `/api/gauth/mgmt/v1/`.

### Mandates

| Method | Path | Description |
|--------|------|-------------|
| POST | `/mandates` | Create a new mandate |
| GET | `/mandates` | List all mandates |
| GET | `/mandates/:id` | Get mandate details |
| POST | `/mandates/:id/activate` | Activate a draft mandate |
| POST | `/mandates/:id/revoke` | Revoke an active mandate |
| POST | `/mandates/:id/suspend` | Suspend an active mandate |
| POST | `/mandates/:id/resume` | Resume a suspended mandate |
| POST | `/mandates/:id/budget/top-up` | Add budget to a mandate |
| POST | `/mandates/:id/ttl/extend` | Extend mandate TTL |
| POST | `/mandates/:id/delegate` | Create a delegated child mandate |
| PUT | `/mandates/:id/governance-profile` | Update governance profile |

### Other Management Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/poa-map` | Get the PoA delegation hierarchy |
| GET | `/audit-log` | Get audit log entries |
| GET | `/governance-profiles` | List governance profiles |
| GET | `/credentials` | List issued credentials |

## PEP Endpoints

All PEP endpoints are mounted under `/api/gauth/pep/v1/`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | PEP health check |
| POST | `/enforce` | Enforce a single action |
| POST | `/enforce/batch` | Enforce multiple actions |
| POST | `/policy` | Inspect enforcement policy |

## VCI/VP Endpoints

### Verifiable Credential Issuance (VCI)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/gauth/vci/v1/credentials/issue` | Issue a VC from a mandate |
| POST | `/api/gauth/vci/v1/offers` | Create a credential offer (OpenID4VCI) |
| GET | `/api/gauth/vci/v1/resolve/:did` | Resolve a DID document |

### Verifiable Presentations (VP)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/gauth/vp/v1/presentations/create` | Create a verifiable presentation |
| POST | `/api/gauth/vp/v1/requests` | Create a presentation request (OpenID4VP) |

## Health Check

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/healthz` | API server health check |

## Request/Response Formats

### Create Mandate Request

```json
{
  "issuer": "org:acme",
  "subject_agent_id": "agent:assistant-01",
  "governance_profile": "standard",
  "phase": "supervised",
  "budget_cents": 10000,
  "ttl_seconds": 3600,
  "max_delegation_depth": 2,
  "scope": {
    "tools": {
      "allowed": ["file_read", "web_search"],
      "denied": ["shell_exec"]
    }
  }
}
```

### Enforcement Request

```json
{
  "action": {
    "verb": "file_read",
    "resource": "/data/report.csv"
  },
  "agent": {
    "agent_id": "agent:assistant-01",
    "session_id": "sess-001"
  },
  "credential": { }
}
```

### Enforcement Decision Response

```json
{
  "decision": "ALLOW",
  "violations": [],
  "checks_run": 16,
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## Error Responses

All errors follow a consistent format:

```json
{
  "error_code": "MANDATE_NOT_FOUND",
  "message": "Mandate with ID 'xyz' not found",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Management Error Codes

| Code | Description |
|------|-------------|
| `MANDATE_NOT_FOUND` | Mandate ID does not exist |
| `INVALID_STATE_TRANSITION` | Cannot transition from current state |
| `INVALID_REQUEST` | Missing or invalid request fields |
| `BUDGET_EXCEEDED` | Budget limit reached |
| `DELEGATION_DEPTH_EXCEEDED` | Max delegation depth reached |
| `SCOPE_VIOLATION` | Delegated scope exceeds parent scope |

### PEP Error Codes

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Missing required fields |
| `ENFORCEMENT_ERROR` | Internal enforcement pipeline error |
| `CREDENTIAL_EXPIRED` | PoA credential has expired |
| `BUDGET_EXHAUSTED` | Budget fully consumed |
