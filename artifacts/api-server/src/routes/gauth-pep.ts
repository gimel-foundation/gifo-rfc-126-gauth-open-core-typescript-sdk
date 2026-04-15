import { Router, type IRouter } from "express";
import type { Request, Response } from "express";
import { handlePEPRequest } from "@gauth/core";
import type { PEPHttpRequest } from "@gauth/core";

const router: IRouter = Router();

async function pepBridge(req: Request, res: Response): Promise<void> {
  const pepReq: PEPHttpRequest = {
    method: req.method,
    path: req.path,
    body: req.body,
    headers: req.headers as Record<string, string | undefined>,
  };

  const pepRes = await handlePEPRequest(pepReq);

  for (const [key, value] of Object.entries(pepRes.headers)) {
    res.setHeader(key, value);
  }
  res.status(pepRes.status).json(pepRes.body);
}

router.get("/gauth/pep/v1/health", pepBridge);
router.post("/gauth/pep/v1/enforce", pepBridge);
router.post("/gauth/pep/v1/enforce/batch", pepBridge);
router.post("/gauth/pep/v1/policy", pepBridge);

export default router;
