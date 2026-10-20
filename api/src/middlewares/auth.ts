import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { errorCode } from "../../config/errorCode.ts";
import { getUserById, updateUser } from "../services/authService.ts";

// types
interface CustomRequest extends Request {
  userId?: number;
}

export const auth = async (
  req: CustomRequest,
  res: Response,
  next: NextFunction,
) => {
  //   const platform = req.headers["x-platform"];
  //   if (platform === "mobile") {
  //     const accessTokenMobile = req.headers.authorization?.split(" ")[1];
  //     console.log("Request from mobile", accessTokenMobile);
  //   } else {
  //     console.log("Request from web");
  //   }
  const accessToken = req.cookies ? req.cookies.accessToken : null;
  const refreshToken = req.cookies ? req.cookies.refreshToken : null;

  if (!refreshToken) {
    const error: any = new Error("You are not unauthenticated user");
    error.status = 401;
    error.code = errorCode.unauthenticated;
    return next(error);
  }
  const generateNewToken = async () => {
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!) as {
        id: number;
        phone: string;
      };
    } catch (error) {
      const err: any = new Error("You are not unauthenticated user");
      err.status = 401;
      err.code = errorCode.unauthenticated;
      return next(err);
    }
    if (isNaN(decoded.id)) {
      const err: any = new Error("You are not unauthenticated user");
      err.status = 401;
      err.code = errorCode.unauthenticated;
      return next(err);
    }
    const user = await getUserById(decoded.id);
    if (!user) {
      const err: any = new Error("This account has not registered.");
      err.status = 401;
      err.code = errorCode.unauthenticated;
      return next(err);
    }

    if (user.phone !== decoded.phone) {
      const err: any = new Error("You are not unauthenticated user");
      err.status = 401;
      err.code = errorCode.unauthenticated;
      return next(err);
    }

    if (user.randomToken !== refreshToken) {
      const err: any = new Error("You are not unauthenticated user");
      err.status = 401;
      err.code = errorCode.unauthenticated;
      return next(err);
    }
    const accessTokenPayload = { id: user!.id };
    const refreshTokenPayload = { id: user!.id, phone: user!.phone };
    const newAccessToken = jwt.sign(
      accessTokenPayload,
      process.env.ACCESS_TOKEN_SECRET!,
      { expiresIn: 60 * 2 }, //2 min in dev but 5 or 15 min in production
    );
    const newRefreshToken = jwt.sign(
      refreshTokenPayload,
      process.env.REFRESH_TOKEN_SECRET!,
      { expiresIn: "30d" },
    );

    const userData = {
      randomToken: newRefreshToken,
    };
    await updateUser(user!.id, userData);
    res
      .cookie("accessToken", newAccessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production" ? true : false,
        sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        maxAge: 15 * 60 * 1000,
      })
      .cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production" ? true : false,
        sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        maxAge: 30 * 24 * 60 * 60 * 1000,
      });
    req.userId = user.id;
    next();
  };
  if (!accessToken) {
    generateNewToken();

    // const error: any = new Error("Access token has expired");
    // error.status = 401;
    // error.code = errorCode.accessTokenExpired;
    // return next(error);
  } else {
    // Verify access token
    let decoded;
    try {
      decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET!) as {
        id: number;
      };
      if (isNaN(decoded.id)) {
        const err: any = new Error("You are not unauthenticated user");
        err.status = 401;
        err.code = errorCode.unauthenticated;
        return next(err);
      }
      req.userId = decoded.id;
      next();
    } catch (error: any) {
      if (error.name === "TokenExpiredError") {
        generateNewToken();

        // error.message = "Access token has expired";
        // error.status = 401;
        // error.code = errorCode.accessTokenExpired;
      } else {
        error.message = "Access token is invalid";
        error.status = 400;
        error.code = errorCode.attack;
        return next(error);
      }
    }
  }
};
