import express from "express";
import { healthCheck } from "../../controllers/healthController.ts";

const router = express.Router();

router.get("/health", healthCheck);

export default router;
