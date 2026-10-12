import type { NextFunction, Request, Response } from "express";
import { body, validationResult } from "express-validator";

export const register = [
  body("phone", "Invalid phone number")
    .trim()
    .notEmpty()
    .matches("^[0-9]+$")
    .isLength({ min: 5, max: 15 })
    .withMessage("Invalid phone number"),
  async (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req).array({ onlyFirstError: true });
    if (errors.length > 0) {
      const error: any = new Error(errors[0].msg);
      error.status = 400;
      error.errorCode = "Error_Invalid";
      return next(error);
    }
    res.status(200).json({ message: "register" });
  },
];

export const verifyOtp = async (req: Request, res: Response) => {
  res.status(200).json({ message: "verify-otp" });
};

export const confirmPassword = async (req: Request, res: Response) => {
  res.status(200).json({ message: "confirm-password" });
};
export const login = async (req: Request, res: Response) => {
  res.status(200).json({ message: "login" });
};

export const refreshToken = async (req: Request, res: Response) => {
  res.status(200).json({ message: "refresh-token" });
};
