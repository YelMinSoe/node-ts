import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

// types
interface CustomRequest extends Request {
  userId?: number;
}

export const auth = (req: CustomRequest, res: Response, next: NextFunction) => {
  const accessToken = req.cookies ? req.cookies.accessToken : null;
  const refreshToken = req.cookies ? req.cookies.refreshToken : null;

  if (!refreshToken) {
    const error: any = new Error("You are not unauthenticated user");
    error.status = 401;
    error.code = "Error_Unauthenticated";
    return next(error);
  }
  if (!accessToken) {
    const error: any = new Error("Access token has expired");
    error.status = 401;
    error.code = "Error_AccessTokenExpired";
    return next(error);
  }

  // Verify access token
  let decoded;
  try {
    decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET!) as {
      id: number;
    };
  } catch (error: any) {
    if (error.name === "TokenExpiredError") {
      error.message = "Access token has expired";
      error.status = 401;
      error.code = "Error_AccessTokenExpired";
    } else {
      error.message = "Access token is invalid";
      error.status = 400;
      error.code = "Error_Attack";
    }
    return next(error);
  }
  req.userId = decoded.id;

  next();
};
