import type { NextFunction, Request, Response } from "express";
import { body, validationResult } from "express-validator";
import bcrypt from "bcrypt";
import moment from "moment";
import jwt from "jsonwebtoken";

import {
  createOtp,
  createUser,
  getOtpByPhone,
  getUserById,
  getUserByPhone,
  updateOtp,
  updateUser,
} from "../services/authService.ts";
import {
  checkOtpErrorIfSameDate,
  checkOtpRow,
  checkUserExit,
  checkUserIfNotExist,
} from "../utils/auth.ts";
import { generateOtp, generateToken } from "../utils/generate.ts";
import { errorCode } from "../../config/errorCode.ts";

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
      error.errorCode = errorCode.invalid;
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
          error.errorCode = errorCode.overLimit;
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
      error.errorCode = errorCode.invalid;
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
    if (otpRow?.rememberToken !== token) {
      const otpData = {
        error: 5,
      };
      await updateOtp(otpRow!.id, otpData);

      const error: any = new Error("Invalid token");
      error.status = 400;
      error.errorCode = errorCode.invalid;
      return next(error);
    }
    const isExpired = moment().diff(otpRow?.updatedAt, "minutes") > 2;
    if (isExpired) {
      const error: any = new Error("OTP is expired");
      error.status = 403;
      error.errorCode = errorCode.otpExpired;
      return next(error);
    }

    const isMatchOtp = await bcrypt.compare(otp, otpRow!.otp);

    if (!isMatchOtp) {
      if (!isSameDate) {
        const otpData = {
          error: 1,
        };
        await updateOtp(otpRow!.id, otpData);
      } else {
        const otpData = {
          error: { increment: 1 },
        };
        await updateOtp(otpRow!.id, otpData);
      }
      const error: any = new Error("OTP is incorrect");
      error.status = 401;
      error.errorCode = errorCode.invalid;
      return next(error);
    }

    const verifyToken = generateToken();
    const otpData = {
      verifyToken,
      error: 0,
      count: 1,
    };
    const result = await updateOtp(otpRow!.id, otpData);

    return res.status(200).json({
      message: "OTP is successfully verified",
      phone: result.phone,
      token: result.verifyToken,
    });
  },
];

export const confirmPassword = [
  body("phone", "Invalid phone number")
    .trim()
    .notEmpty()
    .matches("^[0-9]+$")
    .isLength({ min: 5, max: 15 }),
  body("password", "Password must be 8 digits")
    .trim()
    .notEmpty()
    .matches("^[0-9]+$")
    .isLength({ min: 8, max: 8 }),
  body("token", "Invalid Token").trim().notEmpty().escape(),
  async (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req).array({ onlyFirstError: true });
    if (errors.length > 0) {
      const error: any = new Error(errors[0].msg);
      error.status = 400;
      error.errorCode = errorCode.invalid;
      return next(error);
    }
    const { phone, password, token } = req.body;
    const user = await getUserByPhone(phone);
    await checkUserExit(user);
    const otpRow = await getOtpByPhone(phone);
    await checkOtpRow(otpRow);

    if (otpRow?.error === 5) {
      const error: any = new Error("This request may be attacked");
      error.status = 400;
      error.errorCode = errorCode.attack;
      return next(error);
    }

    if (otpRow?.verifyToken !== token) {
      const otpData = {
        error: 5,
      };
      await updateOtp(otpRow!.id, otpData);

      const error: any = new Error("Invalid Token");
      error.status = 400;
      error.errorCode = errorCode.invalid;
      return next(error);
    }

    const isExpired = moment().diff(otpRow!.updatedAt, "minutes") > 10;
    if (isExpired) {
      const error: any = new Error("Your request is expired");
      error.status = 403;
      error.errorCode = errorCode.requestExpired;
      return next(error);
    }

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);
    const randomToken = "I will replace soon";

    const userData = {
      phone,
      password: hashPassword,
      randomToken,
    };
    const newUser = await createUser(userData);

    const accessTokenPayload = { id: newUser.id };
    const refreshTokenPayload = { id: newUser.id, phone: newUser.phone };
    const accessToken = jwt.sign(
      accessTokenPayload,
      process.env.ACCESS_TOKEN_SECRET!,
      { expiresIn: 60 * 10 },
    );
    const refreshToken = jwt.sign(
      refreshTokenPayload,
      process.env.REFRESH_TOKEN_SECRET!,
      { expiresIn: "30d" },
    );

    const userUpdateData = {
      randomToken: refreshToken,
    };
    await updateUser(newUser.id, userUpdateData);
    res
      .cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production" ? true : false,
        sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        maxAge: 15 * 60 * 1000,
      })
      .cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production" ? true : false,
        sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        maxAge: 30 * 24 * 60 * 60 * 1000,
      })
      .status(201)
      .json({
        message: "Successfully created an account",
        userId: newUser.id,
      });
  },
];
export const login = [
  body("phone", "Invalid phone number")
    .trim()
    .notEmpty()
    .matches("^[0-9]+$")
    .isLength({ min: 5, max: 15 }),
  body("password", "Password must be 8 digits")
    .trim()
    .notEmpty()
    .matches("^[0-9]+$")
    .isLength({ min: 8, max: 8 }),
  async (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req).array({ onlyFirstError: true });
    if (errors.length > 0) {
      const error: any = new Error(errors[0].msg);
      error.status = 400;
      error.errorCode = errorCode.invalid;
      return next(error);
    }

    const password = req.body.password;

    let phone = req.body.phone;
    if (phone.slice(0, 2) === "09") {
      phone = phone.substring(2, phone.length);
    }

    const user = await getUserByPhone(phone);
    checkUserIfNotExist(user);

    if (user?.status === "FREEZE") {
      const error: any = new Error(
        "Your account is temporarily locked.Please contact us",
      );
      error.status = 401;
      error.errorCode = errorCode.accountFreeze;
      return next(error);
    }
    const isMatchPassword = await bcrypt.compare(password, user!.password);
    if (!isMatchPassword) {
      const lastRequest = new Date(user!.updatedAt).toLocaleDateString();
      const isSameDate = lastRequest == new Date().toLocaleDateString();
      if (!isSameDate) {
        const userData = {
          errorLoginCount: 1,
        };
        await updateUser(user!.id, userData);
      } else {
        if (user!.errorLoginCount >= 2) {
          const userData = {
            status: "FREEZE",
          };
        } else {
          const userDate = {
            errorLoginCount: { increment: 1 },
          };
        }
      }
      const error: any = new Error("Password is worng");
      error.status = 401;
      error.errorCode = errorCode.invalid;
      return next(error);
    }
    const accessTokenPayload = { id: user!.id };
    const refreshTokenPayload = { id: user!.id, phone: user!.phone };
    const accessToken = jwt.sign(
      accessTokenPayload,
      process.env.ACCESS_TOKEN_SECRET!,
      { expiresIn: 60 * 10 }, //2 min in dev but 5 or 15 min in production
    );
    const refreshToken = jwt.sign(
      refreshTokenPayload,
      process.env.REFRESH_TOKEN_SECRET!,
      { expiresIn: "30d" },
    );

    const userData = {
      errorLoginCount: 0,
      randomToken: refreshToken,
    };
    await updateUser(user!.id, userData);

    res
      .cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production" ? true : false,
        sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        maxAge: 15 * 60 * 1000,
      })
      .cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production" ? true : false,
        sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        maxAge: 30 * 24 * 60 * 60 * 1000,
      })
      .status(201)
      .json({
        message: "Successfully logged in",
        userId: user!.id,
      });
  },
];

export const logout = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const refreshToken = req.cookies ? req.cookies.refreshToken : null;
  if (!refreshToken) {
    const error: any = new Error("You are not an authenticated user");
    error.status = 400;
    error.errorCode = errorCode.unauthenticated;
    return next(error);
  }
  let decoded;
  try {
    decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!) as {
      id: number;
      phone: string;
    };
  } catch (err) {
    const error: any = new Error("You are not an authenticated user");
    error.status = 400;
    error.errorCode = errorCode.unauthenticated;
    return next(error);
  }
  if (isNaN(decoded.id)) {
    const err: any = new Error("You are not unauthenticated user");
    err.status = 401;
    err.code = errorCode.unauthenticated;
    return next(err);
  }

  const user = await getUserById(decoded.id);
  checkUserIfNotExist(user);

  if (user?.phone !== decoded.phone) {
    const error: any = new Error("You are not an authenticated user");
    error.status = 400;
    error.errorCode = errorCode.unauthenticated;
    return next(error);
  }
  const userData = {
    randomToken: generateToken(),
  };
  await updateUser(user.id, userData);

  res.clearCookie("accessToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production" ? true : false,
    sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
  res.clearCookie("refreshToken");

  res.status(200).json({ message: "Successfully logged out. See you soon." });
};

export const forgetPassword = [
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
      error.errorCode = errorCode.invalid;
      return next(error);
    }
    let phone = req.body.phone;
    if (phone.slice(0, 2) == "09") {
      phone = phone.substring(2, phone.length);
    }
    const user = await getUserByPhone(phone);
    checkUserIfNotExist(user);

    // const otp = generateOtp();
    const otp = 123456;

    const salt = await bcrypt.genSalt(10);
    const hashOtp = await bcrypt.hash(otp.toString(), salt);
    const token = generateToken();

    const otpRow = await getOtpByPhone(phone);

    let result;
    const lastOtpRequest = new Date(otpRow!.updatedAt).toLocaleDateString();
    const today = new Date().toLocaleDateString();
    const isSameDate = lastOtpRequest === today;
    checkOtpErrorIfSameDate(isSameDate, otpRow!.error);

    if (!isSameDate) {
      const otpData = {
        phone,
        otp: hashOtp,
        rememberToken: token,
        count: 1,
        error: 0,
      };
      result = await updateOtp(otpRow!.id, otpData);
    } else {
      if (otpRow!.count === 3) {
        const error: any = new Error(
          "OTP is allowed to request 3 times per day",
        );
        error.status = 405;
        error.errorCode = errorCode.overLimit;
        return next(error);
      } else {
        const otpData = {
          phone,
          otp: hashOtp,
          rememberToken: token,
          count: { increment: 1 },
        };
        result = await updateOtp(otpRow!.id, otpData);
      }
    }
    res.status(200).json({
      message: `We sent OTP to 09${result!.phone}`,
      phone: result.phone,
      token: result.rememberToken,
    });
  },
];

export const refreshToken = async (req: Request, res: Response) => {
  res.status(200).json({ message: "refresh-token" });
};
