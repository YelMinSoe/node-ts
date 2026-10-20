import express from "express";
import {
  confirmPassword,
  login,
  logout,
  refreshToken,
  register,
  verifyOtp,
} from "../../controllers/authController.ts";

const router = express.Router();

router.post("/register", register);
router.post("/verify-otp", verifyOtp);
router.post("/confirm-password", confirmPassword);
router.post("/login", login);
router.post("/logout", logout);
router.post("/refresh-token", refreshToken);

export default router;
