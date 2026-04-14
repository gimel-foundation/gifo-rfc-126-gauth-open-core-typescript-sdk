import { describe, it, expect } from "vitest";
import {
  poaToVerifiableCredential,
  mandateToVerifiableCredential,
  createVerifiablePresentation,
  createDataIntegrityProof,
  attachProof,
  attachPresentationProof,
  resolveDid,
  createBitstringStatusListEntry,
  createSelectiveDisclosureFrame,
  createCredentialOffer,
  createPresentationRequest,
  validateVerifiableCredential,
  validateVerifiablePresentation,
} from "../vc.js";
import type { PoACredential, MandateDetail } from "../types.js";

function makePoa(): PoACredential {
  return {
    schema_version: "0116.2.2",
    parties: {
      issuer: "https://auth.example.com",
      subject: "agent-001",
      customer_id: "cust-123",
      project_id: "proj-456",
      issued_by: "admin@example.com",
    },
    scope: {
      governance_profile: "standard",
      phase: "build",
      core_verbs: {
        "foundry.file.create": { allowed: true },
        "foundry.file.modify": { allowed: true },
      },
    },
    requirements: {
      approval_mode: "autonomous",
      budget: { total_cents: 5000 },
      ttl_seconds: 3600,
    },
  } as PoACredential;
}

function makeMandate(): MandateDetail {
  return {
    mandate_id: "mdt_test123",
    status: "ACTIVE",
    parties: {
      issuer: "https://auth.example.com",
      subject: "agent-001",
      customer_id: "cust-123",
      project_id: "proj-456",
      issued_by: "admin@example.com",
    },
    scope: {
      governance_profile: "enterprise",
      phase: "run",
      core_verbs: {
        "foundry.file.create": { allowed: true },
        "foundry.command.run": { allowed: true },
      },
    },
    requirements: {
      approval_mode: "supervised",
      budget: { total_cents: 50000, remaining_cents: 45000 },
      ttl_seconds: 7200,
    },
    scope_checksum: "sha256:test",
    tool_permissions_hash: "sha256:tools",
    platform_permissions_hash: "sha256:platform",
    delegation_chain: [],
    created_at: new Date().toISOString(),
    activated_at: new Date().toISOString(),
    budget_consumed_cents: 5000,
    audit_trail: [],
  };
}

describe("CT-CF: W3C VC Translation Layer", () => {
  it("CT-CF-001: poaToVerifiableCredential produces valid W3C VC structure", async () => {
    const poa = makePoa();
    const vc = await poaToVerifiableCredential(poa, "mdt_abc123");

    expect(vc["@context"]).toContain("https://www.w3.org/2018/credentials/v1");
    expect(vc.type).toContain("VerifiableCredential");
    expect(vc.type).toContain("GAuthPoACredential");
    expect(vc.credentialSubject.gauthMandate.mandateId).toBe("mdt_abc123");
    expect(vc.credentialSubject.gauthMandate.governanceProfile).toBe("standard");
    expect(vc.credentialSubject.gauthMandate.phase).toBe("build");
    expect(vc.credentialSubject.gauthMandate.approvalMode).toBe("autonomous");
    expect(vc.issuanceDate).toBeDefined();
    expect(vc.id).toMatch(/^urn:uuid:/);
  });

  it("CT-CF-002: VC includes GAuth-specific JSON-LD context", async () => {
    const poa = makePoa();
    const vc = await poaToVerifiableCredential(poa, "mdt_abc123");

    expect(vc["@context"]).toContain("https://gauth.gimelid.com/contexts/v1");
  });

  it("CT-CF-003: VC includes expiration date from TTL", async () => {
    const poa = makePoa();
    const vc = await poaToVerifiableCredential(poa, "mdt_abc123");

    expect(vc.expirationDate).toBeDefined();
    const exp = new Date(vc.expirationDate!);
    expect(exp.getTime()).toBeGreaterThan(Date.now());
  });

  it("CT-CF-004: VC includes credential status when requested", async () => {
    const poa = makePoa();
    const vc = await poaToVerifiableCredential(poa, "mdt_abc123", {
      includeStatus: true,
      statusListCredential: "https://gauth.gimelid.com/status/1",
      statusListIndex: 42,
    });

    expect(vc.credentialStatus).toBeDefined();
    expect(vc.credentialStatus!.type).toBe("BitstringStatusListEntry");
    expect(vc.credentialStatus!.statusListIndex).toBe("42");
    expect(vc.credentialStatus!.statusPurpose).toBe("revocation");
  });

  it("CT-CF-005: mandateToVerifiableCredential works with MandateDetail", async () => {
    const mandate = makeMandate();
    const vc = await mandateToVerifiableCredential(mandate);

    expect(vc.credentialSubject.gauthMandate.mandateId).toBe("mdt_test123");
    expect(vc.credentialSubject.gauthMandate.governanceProfile).toBe("enterprise");
    expect(vc.credentialSubject.gauthMandate.approvalMode).toBe("supervised");
  });

  it("CT-CF-006: custom issuer/holder DIDs are used when provided", async () => {
    const poa = makePoa();
    const vc = await poaToVerifiableCredential(poa, "mdt_abc123", {
      issuerDid: "did:web:custom.example.com",
      holderDid: "did:web:agent.example.com",
    });

    expect(vc.issuer).toBe("did:web:custom.example.com");
    expect(vc.credentialSubject.id).toBe("did:web:agent.example.com");
  });

  it("CT-CF-007: createVerifiablePresentation wraps VCs", async () => {
    const poa = makePoa();
    const vc = await poaToVerifiableCredential(poa, "mdt_abc123");
    const vp = createVerifiablePresentation([vc], "did:web:holder.example.com");

    expect(vp.type).toContain("VerifiablePresentation");
    expect(vp.holder).toBe("did:web:holder.example.com");
    expect(vp.verifiableCredential).toHaveLength(1);
    expect(vp.verifiableCredential[0].id).toBe(vc.id);
  });

  it("CT-CF-008: createDataIntegrityProof creates EdDSA proof", () => {
    const proof = createDataIntegrityProof(
      "did:web:gauth.gimelid.com#key-1",
      "base64urlEncodedProofValue",
    );

    expect(proof.type).toBe("DataIntegrityProof");
    expect(proof.cryptosuite).toBe("ecdsa-rdfc-2019");
    expect(proof.proofPurpose).toBe("assertionMethod");
    expect(proof.proofValue).toBe("base64urlEncodedProofValue");
    expect(proof.created).toBeDefined();
  });

  it("CT-CF-009: attachProof attaches proof to VC", async () => {
    const poa = makePoa();
    const vc = await poaToVerifiableCredential(poa, "mdt_abc123");
    const proof = createDataIntegrityProof("did:web:issuer#key-1", "proofData");
    const signed = attachProof(vc, proof);

    expect(signed.proof).toBeDefined();
    expect(signed.proof!.proofValue).toBe("proofData");
    expect(signed.id).toBe(vc.id);
  });

  it("CT-CF-010: attachPresentationProof attaches proof to VP", async () => {
    const poa = makePoa();
    const vc = await poaToVerifiableCredential(poa, "mdt_abc123");
    const vp = createVerifiablePresentation([vc], "did:web:holder");
    const proof = createDataIntegrityProof("did:web:holder#key-1", "vpProof");
    const signed = attachPresentationProof(vp, proof);

    expect(signed.proof).toBeDefined();
    expect(signed.proof!.proofValue).toBe("vpProof");
  });

  it("CT-CF-011: resolveDid parses did:web DID", () => {
    const result = resolveDid("did:web:gauth.gimelid.com");
    expect(result).not.toBeNull();
    expect(result!.controller).toBe("did:web:gauth.gimelid.com");
    expect(result!.type).toBe("JsonWebKey2020");
  });

  it("CT-CF-011b: resolveDid parses did:key Ed25519 DID", () => {
    const result = resolveDid("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    expect(result).not.toBeNull();
    expect(result!.controller).toBe("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    expect(result!.type).toBe("Ed25519VerificationKey2020");
    expect(result!.publicKeyMultibase).toBe("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    expect(result!.id).toContain("#z6Mk");
  });

  it("CT-CF-011c: resolveDid parses did:key P-256 DID", () => {
    const result = resolveDid("did:key:zDnaeWCdm62g2J3NSBMF3xEE4aJKqS6HWe3hYwi1oPYa1nJh");
    expect(result).not.toBeNull();
    expect(result!.type).toBe("EcdsaSecp256r1VerificationKey2019");
    expect(result!.publicKeyMultibase).toBeDefined();
  });

  it("CT-CF-012: resolveDid returns null for invalid DID", () => {
    expect(resolveDid("not-a-did")).toBeNull();
    expect(resolveDid("did:")).toBeNull();
  });

  it("CT-CF-013: createBitstringStatusListEntry creates entry", () => {
    const entry = createBitstringStatusListEntry(42, "https://gauth.gimelid.com/status/1");
    expect(entry.statusListIndex).toBe(42);
    expect(entry.statusPurpose).toBe("revocation");
  });

  it("CT-CF-014: createSelectiveDisclosureFrame creates SD frame", () => {
    const frame = createSelectiveDisclosureFrame(
      ["issuer", "issuanceDate"],
      ["gauthMandate"],
    );
    expect(frame._sd).toContain("issuer");
    expect(frame.credentialSubject?._sd).toContain("gauthMandate");
  });

  it("CT-CF-015: createCredentialOffer creates OID4VCI offer", () => {
    const offer = createCredentialOffer(
      "https://gauth.gimelid.com",
      ["GAuthPoACredential"],
      "pre-auth-code-123",
    );
    expect(offer.credential_issuer).toBe("https://gauth.gimelid.com");
    expect(offer.credentials).toContain("GAuthPoACredential");
    expect(offer.grants).toBeDefined();
  });

  it("CT-CF-016: createPresentationRequest creates OID4VP request", () => {
    const request = createPresentationRequest(
      "client-001",
      "https://verifier.example.com/callback",
      "nonce-abc",
      [{
        id: "gauth-poa",
        name: "GAuth PoA",
        purpose: "Verify agent authorization",
        fields: [{ path: ["$.credentialSubject.gauthMandate.governanceProfile"] }],
      }],
    );
    expect(request.response_type).toBe("vp_token");
    expect(request.presentation_definition.input_descriptors).toHaveLength(1);
    expect(request.nonce).toBe("nonce-abc");
  });

  it("CT-CF-017: validateVerifiableCredential validates good VC", async () => {
    const poa = makePoa();
    const vc = await poaToVerifiableCredential(poa, "mdt_abc123");
    const result = validateVerifiableCredential(vc);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("CT-CF-018: validateVerifiableCredential detects missing fields", () => {
    const badVc = {
      "@context": [],
      id: "",
      type: [],
      issuer: "",
      issuanceDate: "",
      credentialSubject: { id: "", gauthMandate: {} },
    } as any;

    const result = validateVerifiableCredential(badVc);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("CT-CF-019: validateVerifiablePresentation validates VP with embedded VC", async () => {
    const poa = makePoa();
    const vc = await poaToVerifiableCredential(poa, "mdt_abc123");
    const vp = createVerifiablePresentation([vc], "did:web:holder");
    const result = validateVerifiablePresentation(vp);
    expect(result.valid).toBe(true);
  });

  it("CT-CF-020: VC scope checksum is consistent", async () => {
    const poa = makePoa();
    const vc1 = await poaToVerifiableCredential(poa, "mdt_abc123");
    const vc2 = await poaToVerifiableCredential(poa, "mdt_abc123");
    expect(vc1.credentialSubject.gauthMandate.scopeChecksum).toBe(
      vc2.credentialSubject.gauthMandate.scopeChecksum,
    );
  });
});
