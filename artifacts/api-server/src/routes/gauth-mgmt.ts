import { Router, type IRouter } from "express";
import type { Request, Response } from "express";
import { handleMgmtRequest, InMemoryMandateStore, ManagementAPI } from "@gauth/core";
import type { MgmtHttpRequest } from "@gauth/core";

const store = new InMemoryMandateStore();
const mgmtApi = new ManagementAPI(store);

const router: IRouter = Router();

async function mgmtBridge(req: Request, res: Response): Promise<void> {
  const mgmtReq: MgmtHttpRequest = {
    method: req.method,
    path: req.path,
    body: req.body,
    headers: req.headers as Record<string, string | undefined>,
    params: req.params as Record<string, string>,
  };

  const mgmtRes = await handleMgmtRequest(mgmtReq, mgmtApi);

  for (const [key, value] of Object.entries(mgmtRes.headers)) {
    res.setHeader(key, value);
  }
  res.status(mgmtRes.status).json(mgmtRes.body);
}

router.post("/gauth/mgmt/v1/mandates", mgmtBridge);
router.get("/gauth/mgmt/v1/mandates", mgmtBridge);
router.get("/gauth/mgmt/v1/mandates/:id", mgmtBridge);
router.post("/gauth/mgmt/v1/mandates/:id/activate", mgmtBridge);
router.post("/gauth/mgmt/v1/mandates/:id/revoke", mgmtBridge);
router.post("/gauth/mgmt/v1/mandates/:id/suspend", mgmtBridge);
router.post("/gauth/mgmt/v1/mandates/:id/resume", mgmtBridge);
router.post("/gauth/mgmt/v1/mandates/:id/budget/top-up", mgmtBridge);
router.post("/gauth/mgmt/v1/mandates/:id/ttl/extend", mgmtBridge);
router.post("/gauth/mgmt/v1/mandates/:id/delegate", mgmtBridge);
router.put("/gauth/mgmt/v1/mandates/:id/governance-profile", mgmtBridge);

router.get("/gauth/mgmt/v1/poa-map", async (req: Request, res: Response) => {
  const mandateId = req.query.mandate_id as string | undefined;
  if (!mandateId) {
    res.json({ entries: [], message: "Provide ?mandate_id= to generate a PoA map for a specific mandate." });
    return;
  }
  const map = await mgmtApi.generatePoaMap(mandateId);
  if ("error_code" in map) {
    res.status(404).json(map);
    return;
  }
  res.json(map);
});

router.get("/gauth/mgmt/v1/audit-log", async (_req: Request, res: Response) => {
  res.json({ entries: [], total: 0 });
});

router.get("/gauth/mgmt/v1/governance-profiles", async (_req: Request, res: Response) => {
  res.json({ profiles: [] });
});

router.get("/gauth/mgmt/v1/credentials", async (_req: Request, res: Response) => {
  res.json({ credentials: [] });
});

export { mgmtApi, store };
export default router;
