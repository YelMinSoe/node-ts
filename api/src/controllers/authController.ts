import type { Request, Response } from "express";

export const register = (req: Request, res: Response) => {
  res.status(200).json({ message: "register" });
};

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
