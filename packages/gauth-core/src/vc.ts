/**
 * W3C Verifiable Credentials Translation Layer — Reference Scaffold v0.91.0
 *
 * This module provides structural helpers for PoA↔W3C VC translation, including
 * credential/presentation building, proof attachment, DID parsing, selective
 * disclosure framing, and OpenID4VCI/VP request construction.
 *
 * Scope for v0.91.0 Public Preview:
 * - Structural serialization and type-safe builders (not full protocol flows)
 * - DID resolution is local string parsing (no network DID document retrieval)
 * - Data Integrity Proofs default to ecdsa-rdfc-2019 suite (proof generation
 *   and verification require external cryptographic provider integration)
 * - SD-JWT helpers produce disclosure frames (actual JWT signing is external)
 * - OpenID4VCI/VP helpers produce request/offer structures (protocol transport
 *   and token exchange are external)
 *
 * Full W3C VC conformance (DID resolution, proof verification, credential
 * status checking, OpenID4VP response validation) is planned for v1.0.0.
 */
import type {
  PoACredential,
  MandateDetail,
  W3cVerifiableCredential,
  W3cVerifiablePresentation,
  W3cDataIntegrityProof,
  W3cVcCredentialSubject,
  BitstringStatusListEntry,
  SelectiveDisclosureFrame,
  OpenID4VCICredentialOffer,
  OpenID4VPPresentationRequest,
} from "./types.js";
import { computeScopeChecksum, computeToolPermissionsHash, computePlatformPermissionsHash } from "./crypto.js";

const W3C_VC_CONTEXT = "https://www.w3.org/2018/credentials/v1";
const W3C_VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";
const GAUTH_VC_CONTEXT = "https://gauth.gimelid.com/contexts/v1";
const GAUTH_DID_PREFIX = "did:web:gauth.gimelid.com";

export interface PoaToVcOptions {
  issuerDid?: string;
  holderDid?: string;
  credentialId?: string;
  includeStatus?: boolean;
  statusListCredential?: string;
  statusListIndex?: number;
}

export async function poaToVerifiableCredential(
  poa: PoACredential,
  mandateId: string,
  options?: PoaToVcOptions,
): Promise<W3cVerifiableCredential> {
  const issuer = options?.issuerDid ?? `${GAUTH_DID_PREFIX}:issuer`;
  const holderDid = options?.holderDid ?? `${GAUTH_DID_PREFIX}:agent:${poa.parties.subject}`;
  const credentialId = options?.credentialId ?? `urn:uuid:${crypto.randomUUID()}`;

  const toolPermissionsHash = await computeToolPermissionsHash(poa.scope.core_verbs);
  const platformPermissionsHash = await computePlatformPermissionsHash(
    poa.scope.platform_permissions as Record<string, unknown> | undefined,
  );
  const scopeChecksum = await computeScopeChecksum({
    governance_profile: poa.scope.governance_profile,
    phase: poa.scope.phase,
    allowed_paths: poa.scope.allowed_paths,
    denied_paths: poa.scope.denied_paths,
    allowed_regions: poa.scope.allowed_regions,
    allowed_sectors: poa.scope.allowed_sectors,
    active_modules: poa.scope.active_modules,
    tool_permissions_hash: toolPermissionsHash,
    platform_permissions_hash: platformPermissionsHash,
  });

  const coreVerbsSummary: Record<string, { allowed: boolean }> = {};
  for (const [verb, policy] of Object.entries(poa.scope.core_verbs)) {
    coreVerbsSummary[verb] = { allowed: policy.allowed };
  }

  const credentialSubject: W3cVcCredentialSubject = {
    id: holderDid,
    gauthMandate: {
      mandateId,
      governanceProfile: poa.scope.governance_profile,
      phase: poa.scope.phase,
      scopeChecksum,
      approvalMode: poa.requirements.approval_mode,
      coreVerbs: coreVerbsSummary,
    },
  };

  const vc: W3cVerifiableCredential = {
    "@context": [W3C_VC_CONTEXT, GAUTH_VC_CONTEXT],
    id: credentialId,
    type: ["VerifiableCredential", "GAuthPoACredential"],
    issuer,
    issuanceDate: new Date().toISOString(),
    credentialSubject,
  };

  if (poa.requirements.ttl_seconds) {
    vc.expirationDate = new Date(Date.now() + poa.requirements.ttl_seconds * 1000).toISOString();
  }

  if (options?.includeStatus && options.statusListCredential !== undefined && options.statusListIndex !== undefined) {
    vc.credentialStatus = {
      id: `${options.statusListCredential}#${options.statusListIndex}`,
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: String(options.statusListIndex),
      statusListCredential: options.statusListCredential,
    };
  }

  return vc;
}

export function mandateToVerifiableCredential(
  mandate: MandateDetail,
  options?: PoaToVcOptions,
): Promise<W3cVerifiableCredential> {
  const poa: PoACredential = {
    schema_version: "0116.2.2",
    parties: mandate.parties,
    delegation_chain: mandate.delegation_chain,
    scope: mandate.scope,
    requirements: mandate.requirements,
  };
  return poaToVerifiableCredential(poa, mandate.mandate_id, options);
}

export function createVerifiablePresentation(
  credentials: W3cVerifiableCredential[],
  holderDid: string,
): W3cVerifiablePresentation {
  return {
    "@context": [W3C_VC_CONTEXT],
    type: ["VerifiablePresentation"],
    holder: holderDid,
    verifiableCredential: credentials,
  };
}

export function createDataIntegrityProof(
  verificationMethod: string,
  proofValue: string,
  options?: { cryptosuite?: string; proofPurpose?: string },
): W3cDataIntegrityProof {
  return {
    type: "DataIntegrityProof",
    cryptosuite: options?.cryptosuite ?? "ecdsa-rdfc-2019",
    created: new Date().toISOString(),
    verificationMethod,
    proofPurpose: options?.proofPurpose ?? "assertionMethod",
    proofValue,
  };
}

export function attachProof(
  vc: W3cVerifiableCredential,
  proof: W3cDataIntegrityProof,
): W3cVerifiableCredential {
  return { ...vc, proof };
}

export function attachPresentationProof(
  vp: W3cVerifiablePresentation,
  proof: W3cDataIntegrityProof,
): W3cVerifiablePresentation {
  return { ...vp, proof };
}

export function resolveDid(did: string): { id: string; controller: string; type: string; publicKeyMultibase?: string } | null {
  if (!did.startsWith("did:")) return null;

  const parts = did.split(":");
  if (parts.length < 3) return null;

  const method = parts[1];

  if (method === "key") {
    const multibaseKey = parts.slice(2).join(":");
    if (multibaseKey.startsWith("z6Mk")) {
      return {
        id: `${did}#${multibaseKey}`,
        controller: did,
        type: "Ed25519VerificationKey2020",
        publicKeyMultibase: multibaseKey,
      };
    }
    if (multibaseKey.startsWith("zDn")) {
      return {
        id: `${did}#${multibaseKey}`,
        controller: did,
        type: "EcdsaSecp256r1VerificationKey2019",
        publicKeyMultibase: multibaseKey,
      };
    }
    return {
      id: `${did}#${multibaseKey}`,
      controller: did,
      type: "MultibaseVerificationKey",
      publicKeyMultibase: multibaseKey,
    };
  }

  if (method === "web") {
    return {
      id: `${did}#key-1`,
      controller: did,
      type: "JsonWebKey2020",
      publicKeyMultibase: undefined,
    };
  }

  return {
    id: `${did}#key-1`,
    controller: did,
    type: "VerificationKey",
    publicKeyMultibase: undefined,
  };
}

export function createBitstringStatusListEntry(
  index: number,
  statusListCredential: string,
  purpose: "revocation" | "suspension" = "revocation",
): BitstringStatusListEntry {
  return {
    statusListIndex: index,
    statusListCredential,
    statusPurpose: purpose,
  };
}

export function createSelectiveDisclosureFrame(
  sdFields: string[],
  subjectSdFields?: string[],
): SelectiveDisclosureFrame {
  const frame: SelectiveDisclosureFrame = {
    _sd: sdFields,
  };
  if (subjectSdFields) {
    frame.credentialSubject = { _sd: subjectSdFields };
  }
  return frame;
}

export function createCredentialOffer(
  issuerUrl: string,
  credentialTypes: string[],
  preAuthorizedCode?: string,
): OpenID4VCICredentialOffer {
  const offer: OpenID4VCICredentialOffer = {
    credential_issuer: issuerUrl,
    credentials: credentialTypes,
  };
  if (preAuthorizedCode) {
    offer.grants = {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": preAuthorizedCode,
        user_pin_required: false,
      },
    };
  }
  return offer;
}

export function createPresentationRequest(
  clientId: string,
  redirectUri: string,
  nonce: string,
  descriptors: Array<{ id: string; name: string; purpose: string; fields: Array<{ path: string[]; filter?: Record<string, unknown> }> }>,
): OpenID4VPPresentationRequest {
  return {
    response_type: "vp_token",
    client_id: clientId,
    redirect_uri: redirectUri,
    nonce,
    presentation_definition: {
      id: `pd-${crypto.randomUUID().slice(0, 8)}`,
      input_descriptors: descriptors.map((d) => ({
        id: d.id,
        name: d.name,
        purpose: d.purpose,
        constraints: {
          fields: d.fields.map((f) => ({
            path: f.path,
            filter: f.filter,
          })),
        },
      })),
    },
  };
}

export function validateVerifiableCredential(vc: W3cVerifiableCredential): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!vc["@context"] || !Array.isArray(vc["@context"]) || !vc["@context"].includes(W3C_VC_CONTEXT)) {
    errors.push("Missing or invalid @context — must include W3C VC context.");
  }
  if (!vc.id) {
    errors.push("Missing credential id.");
  }
  if (!vc.type || !Array.isArray(vc.type) || !vc.type.includes("VerifiableCredential")) {
    errors.push("Missing or invalid type — must include 'VerifiableCredential'.");
  }
  if (!vc.issuer) {
    errors.push("Missing issuer.");
  }
  if (!vc.issuanceDate) {
    errors.push("Missing issuanceDate.");
  }
  if (!vc.credentialSubject || !vc.credentialSubject.id) {
    errors.push("Missing credentialSubject or credentialSubject.id.");
  }
  if (vc.expirationDate) {
    const exp = new Date(vc.expirationDate);
    if (exp < new Date()) {
      errors.push("Credential has expired.");
    }
  }

  return { valid: errors.length === 0, errors };
}

export function validateVerifiablePresentation(vp: W3cVerifiablePresentation): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!vp["@context"] || !Array.isArray(vp["@context"]) || !vp["@context"].includes(W3C_VC_CONTEXT)) {
    errors.push("Missing or invalid @context — must include W3C VC context.");
  }
  if (!vp.type || !Array.isArray(vp.type) || !vp.type.includes("VerifiablePresentation")) {
    errors.push("Missing or invalid type — must include 'VerifiablePresentation'.");
  }
  if (!vp.holder) {
    errors.push("Missing holder.");
  }
  if (!vp.verifiableCredential || !Array.isArray(vp.verifiableCredential)) {
    errors.push("Missing or invalid verifiableCredential array.");
  } else {
    for (let i = 0; i < vp.verifiableCredential.length; i++) {
      const vcResult = validateVerifiableCredential(vp.verifiableCredential[i]);
      if (!vcResult.valid) {
        errors.push(`Credential [${i}]: ${vcResult.errors.join("; ")}`);
      }
    }
  }

  return { valid: errors.length === 0, errors };
}
