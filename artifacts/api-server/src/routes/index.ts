import { Router, type IRouter } from "express";
import healthRouter from "./health";
import gauthPepRouter from "./gauth-pep";
import gauthMgmtRouter from "./gauth-mgmt";
import gauthVciVpRouter from "./gauth-vci-vp";

const router: IRouter = Router();

router.use(healthRouter);
router.use(gauthPepRouter);
router.use(gauthMgmtRouter);
router.use(gauthVciVpRouter);

export default router;
