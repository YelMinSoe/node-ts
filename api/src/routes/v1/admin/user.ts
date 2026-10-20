import express from "express";
import { getAllUsers } from "../../../controllers/admin/userController.ts";

const router = express.Router();

router.get("/users", getAllUsers);

export default router;
