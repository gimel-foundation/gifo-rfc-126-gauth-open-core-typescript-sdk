import { Router, type IRouter } from "express";
import type { Request, Response } from "express";
import {
  poaToVerifiableCredential,
  createVerifiablePresentation,
  createDataIntegrityProof,
  createCredentialOffer,
  createPresentationRequest,
  resolveDid,
} from "@gauth/core";
import { mgmtApi } from "./gauth-mgmt";

const router: IRouter = Router();

router.post("/gauth/vci/v1/credentials/issue", async (req: Request, res: Response) => {
  const { mandate_id, subject_did, issuer_did } = req.body;

  if (!mandate_id) {
    res.status(400).json({ error_code: "INVALID_REQUEST", message: "mandate_id is required" });
    return;
  }

  const mandate = await mgmtApi.getMandate(mandate_id);
  if ("error_code" in mandate) {
    res.status(404).json(mandate);
    return;
  }

  const poa = {
    schema_version: "1.0" as const,
    mandate_id: mandate.mandate_id,
    issuer: mandate.parties.issuer_id,
    subject: { agent_id: mandate.parties.subject_agent_id },
    scope: mandate.scope as Record<string, unknown>,
    constraints: mandate.requirements as Record<string, unknown>,
    issued_at: mandate.created_at,
    governance_profile: (mandate.requirements?.governance_profile ?? "standard") as "strict" | "standard" | "permissive",
    phase: (mandate.requirements?.phase ?? "supervised") as "exploration" | "supervised" | "autonomous",
  };

  const vc = poaToVerifiableCredential(poa, issuer_did ?? `did:web:gauth.gimelid.com`);

  res.status(201).json({
    credential_id: `vc-${mandate_id}-${Date.now()}`,
    verifiable_credential: vc,
    format: "ldp_vc",
  });
});

router.post("/gauth/vp/v1/presentations/create", async (req: Request, res: Response) => {
  const { credentials, holder_did, challenge } = req.body;

  if (!credentials || !Array.isArray(credentials)) {
    res.status(400).json({ error_code: "INVALID_REQUEST", message: "credentials array is required" });
    return;
  }

  const vp = createVerifiablePresentation(credentials, holder_did ?? "did:web:agent.example.com");

  res.status(201).json({
    verifiable_presentation: vp,
    challenge,
  });
});

router.post("/gauth/vci/v1/offers", async (req: Request, res: Response) => {
  const { credential_type, issuer_url } = req.body;

  const offer = createCredentialOffer(
    issuer_url ?? `https://gauth.gimelid.com/vci`,
    [credential_type ?? "GAuthPoACredential"],
    `offer-${Date.now()}`,
  );

  res.status(201).json(offer);
});

router.post("/gauth/vp/v1/requests", async (req: Request, res: Response) => {
  const { client_id, redirect_uri, nonce, descriptors } = req.body;

  const request = createPresentationRequest(
    client_id ?? "gauth-governance-dashboard",
    redirect_uri ?? "https://gauth.gimelid.com/vp/callback",
    nonce ?? `nonce-${Date.now()}`,
    descriptors ?? [{ id: "poa-credential", name: "GAuth PoA Credential", purpose: "Verify agent authorization", fields: [{ path: ["$.credentialSubject.mandate_id"] }] }],
  );

  res.status(201).json(request);
});

router.get("/gauth/vci/v1/resolve/:did", async (req: Request, res: Response) => {
  const did = decodeURIComponent(req.params.did);
  const resolved = resolveDid(did);

  if (!resolved) {
    res.status(404).json({ error_code: "DID_NOT_FOUND", message: `Cannot resolve DID: ${did}` });
    return;
  }

  res.json({ did_document: resolved });
});

export default router;
