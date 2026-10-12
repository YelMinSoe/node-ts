import type { NextFunction, Request, Response } from "express";
import { body, validationResult } from "express-validator";
import bcrypt from "bcrypt";

import {
  createOtp,
  getOtpByPhone,
  getUserByPhone,
  updateOtp,
} from "../services/authService.ts";
import {
  checkOtpErrorIfSameDate,
  checkOtpRow,
  checkUserExit,
} from "../utils/auth.ts";
import { generateOtp, generateToken } from "../utils/generate.ts";

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
    let phone = req.body.phone;
    if (phone.slice(0, 2) == "09") {
      phone = phone.substring(2, phone.length);
    }
    const user = await getUserByPhone(phone);
    checkUserExit(user);

    // const otp = generateOtp();
    const otp = 123456;

    const salt = await bcrypt.genSalt(10);
    const hashOtp = await bcrypt.hash(otp.toString(), salt);
    const token = generateToken();

    const otpRow = await getOtpByPhone(phone);
    let result;
    if (!otpRow) {
      const otpData = {
        phone,
        otp: hashOtp,
        rememberToken: token,
        count: 1,
      };
      result = await createOtp(otpData);
    } else {
      const lastOtpRequest = new Date(otpRow.updatedAt).toLocaleDateString();
      const today = new Date().toLocaleDateString();
      const isSameDate = lastOtpRequest === today;
      checkOtpErrorIfSameDate(isSameDate, otpRow.error);

      if (!isSameDate) {
        const otpData = {
          phone,
          otp: hashOtp,
          rememberToken: token,
          count: 1,
          error: 0,
        };
        result = await updateOtp(otpRow.id, otpData);
      } else {
        if (otpRow.count === 3) {
          const error: any = new Error(
            "OTP is allowed to request 3 times per day",
          );
          error.status = 405;
          error.errorCode = "Error_OverLimit";
          throw error;
        } else {
          const otpData = {
            phone,
            otp: hashOtp,
            rememberToken: token,
            count: { increment: 1 },
          };
          result = await updateOtp(otpRow.id, otpData);
        }
      }
    }

    res.status(200).json({
      message: `We sent OTP to 09${result!.phone}`,
      phone: result.phone,
      token: result.rememberToken,
    });
  },
];

export const verifyOtp = [
  body("phone", "Invalid phone number")
    .trim()
    .notEmpty()
    .matches("^[0-9]+$")
    .isLength({ min: 5, max: 15 }),
  body("otp", "Invalid OTP")
    .trim()
    .notEmpty()
    .matches("^[0-9]+$")
    .isLength({ min: 6, max: 6 }),
  body("token", "Invalid Token").trim().notEmpty().escape(),
  async (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req).array({ onlyFirstError: true });
    if (errors.length > 0) {
      const error: any = new Error(errors[0].msg);
      error.status = 400;
      error.errorCode = "Error_Invalid";
      return next(error);
    }
    const { phone, otp, token } = req.body;

    const user = await getUserByPhone(phone);
    checkUserExit(user);

    const otpRow = await getOtpByPhone(phone);
    checkOtpRow(otpRow);

    const lastOtpRequest = new Date(otpRow!.updatedAt).toLocaleDateString();
    const today = new Date().toLocaleDateString();
    const isSameDate = lastOtpRequest === today;
    checkOtpErrorIfSameDate(isSameDate, otpRow!.error);
    let result;
    if (otpRow?.rememberToken !== token) {
      const otpData = {
        error: 5,
      };
      result = await updateOtp(otpRow!.id, otpData);

      const error: any = new Error("Invalid token");
      error.status = 400;
      error.errorCode = "Error_Invalid";
      return next(error);
    }

    res.status(200).json({ message: "verify-otp" });
  },
];

export const confirmPassword = async (req: Request, res: Response) => {
  res.status(200).json({ message: "confirm-password" });
};
export const login = async (req: Request, res: Response) => {
  res.status(200).json({ message: "login" });
};

export const refreshToken = async (req: Request, res: Response) => {
  res.status(200).json({ message: "refresh-token" });
};
