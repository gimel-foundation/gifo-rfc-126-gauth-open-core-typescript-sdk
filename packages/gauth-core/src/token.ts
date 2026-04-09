import * as jose from "jose";
import type { CryptoKey as JoseCryptoKey } from "jose";
import type { GAuthJWTClaims, PoACredential } from "./types.js";
import { SCHEMA_VERSION } from "./types.js";
import {
  computeScopeChecksum,
  computeToolPermissionsHash,
  computePlatformPermissionsHash,
} from "./crypto.js";

const PROHIBITED_ALGORITHMS = new Set(["HS256", "HS384", "HS512"]);

export interface TokenCreationOptions {
  privateKey: JoseCryptoKey | Uint8Array;
  algorithm?: string;
  keyId: string;
  issuer: string;
  audience: string[];
  credentialId: string;
  mandateId?: string;
  mandateStatus?: string;
  expiresInSeconds?: number;
}

export async function createExtendedToken(
  poa: PoACredential,
  options: TokenCreationOptions,
): Promise<string> {
  const alg = options.algorithm ?? "RS256";

  if (PROHIBITED_ALGORITHMS.has(alg)) {
    throw new GAuthTokenError(
      `Algorithm ${alg} is prohibited by GAuth RFC 0116. Use RS256 (required) or ES256 (recommended).`,
    );
  }

  const toolPermissionsHash = await computeToolPermissionsHash(poa.scope.core_verbs);
  const platformPermissionsHash = await computePlatformPermissionsHash(
    poa.scope.platform_permissions as Record<string, unknown> | undefined,
  );
  const scopeChecksum = await computeScopeChecksum({
    governance_profile: poa.scope.governance_profile,
    phase: poa.scope.phase,
    allowed_paths: poa.scope.allowed_paths,
    denied_paths: poa.scope.denied_paths,
    active_modules: poa.scope.active_modules,
    tool_permissions_hash: toolPermissionsHash,
    platform_permissions_hash: platformPermissionsHash,
  });

  const now = Math.floor(Date.now() / 1000);
  const exp = now + (options.expiresInSeconds ?? 3600);

  const gauthClaims: GAuthJWTClaims["gauth"] = {
    version: SCHEMA_VERSION,
    credential_id: options.credentialId,
    customer_id: poa.parties.customer_id,
    project_id: poa.parties.project_id,
    scope: {
      governance_profile: poa.scope.governance_profile,
      active_modules: poa.scope.active_modules,
      phase: poa.scope.phase,
      allowed_paths: poa.scope.allowed_paths,
      denied_paths: poa.scope.denied_paths,
    },
    scope_checksum: scopeChecksum,
    tool_permissions_hash: toolPermissionsHash,
    platform_permissions_hash: platformPermissionsHash,
    issued_by: poa.parties.issued_by,
    approval_mode: poa.requirements.approval_mode,
  };

  const payload: Record<string, unknown> = {
    gauth: gauthClaims,
  };

  if (options.mandateId) {
    payload.gauth_mandate = {
      mandate_id: options.mandateId,
      mandate_status: options.mandateStatus ?? "active",
      budget: poa.requirements.budget
        ? {
            total_cents: poa.requirements.budget.total_cents,
            remaining_cents: poa.requirements.budget.remaining_cents ?? poa.requirements.budget.total_cents,
          }
        : undefined,
      session: poa.requirements.session_limits
        ? {
            session_id: poa.requirements.session_limits.session_id,
            remaining_tool_calls: poa.requirements.session_limits.remaining_tool_calls,
            max_lines_per_commit: poa.requirements.session_limits.max_lines_per_commit,
            started_at: poa.requirements.session_limits.started_at,
          }
        : undefined,
    };
  }

  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg, typ: "JWT", kid: options.keyId })
    .setIssuer(options.issuer)
    .setSubject(poa.parties.subject)
    .setAudience(options.audience)
    .setExpirationTime(exp)
    .setIssuedAt(now)
    .setNotBefore(now)
    .setJti(`tok_${crypto.randomUUID()}`)
    .sign(options.privateKey);

  return jwt;
}

export interface TokenValidationOptions {
  issuer?: string;
  audience?: string;
  jwks?: jose.JWTVerifyGetKey;
  publicKey?: JoseCryptoKey | Uint8Array;
  clockTolerance?: number;
}

export interface ValidatedToken {
  claims: GAuthJWTClaims;
  header: jose.JWTHeaderParameters;
}

export async function validateExtendedToken(
  token: string,
  options: TokenValidationOptions,
): Promise<ValidatedToken> {
  if (!options.jwks && !options.publicKey) {
    throw new GAuthTokenError("Either jwks or publicKey must be provided for token validation.");
  }

  const verifyOptions: jose.JWTVerifyOptions = {
    clockTolerance: options.clockTolerance ?? 30,
  };
  if (options.issuer) verifyOptions.issuer = options.issuer;
  if (options.audience) verifyOptions.audience = options.audience;

  let result: jose.JWTVerifyResult;
  try {
    if (options.jwks) {
      result = await jose.jwtVerify(token, options.jwks, verifyOptions);
    } else {
      result = await jose.jwtVerify(token, options.publicKey!, verifyOptions);
    }
  } catch (err) {
    if (err instanceof jose.errors.JWTExpired) {
      throw new GAuthTokenError("Token has expired.", "CREDENTIAL_EXPIRED");
    }
    if (err instanceof jose.errors.JWTClaimValidationFailed) {
      throw new GAuthTokenError(`Token claim validation failed: ${err.message}`, "CREDENTIAL_INVALID");
    }
    throw new GAuthTokenError(
      `Token verification failed: ${err instanceof Error ? err.message : String(err)}`,
      "CREDENTIAL_INVALID",
    );
  }

  const { protectedHeader } = result;

  if (PROHIBITED_ALGORITHMS.has(protectedHeader.alg)) {
    throw new GAuthTokenError(
      `Algorithm ${protectedHeader.alg} is prohibited by GAuth RFC 0116.`,
      "CREDENTIAL_INVALID",
    );
  }

  const payload = result.payload as unknown as GAuthJWTClaims;

  if (!payload.gauth) {
    throw new GAuthTokenError("Token missing required 'gauth' claims namespace.", "CREDENTIAL_INVALID");
  }

  if (payload.gauth.version !== SCHEMA_VERSION) {
    throw new GAuthTokenError(
      `Unsupported schema version: ${payload.gauth.version}. Expected ${SCHEMA_VERSION}.`,
      "CREDENTIAL_INVALID",
    );
  }

  return {
    claims: payload,
    header: protectedHeader,
  };
}

export class GAuthTokenError extends Error {
  public readonly violationCode?: string;

  constructor(message: string, violationCode?: string) {
    super(message);
    this.name = "GAuthTokenError";
    this.violationCode = violationCode;
  }
}
