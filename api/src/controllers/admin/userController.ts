import type { Request, Response } from "express";
// Types
interface CustomRequest extends Request {
  userId?: number;
  user?: any;
}
export const getAllUsers = (req: CustomRequest, res: Response) => {
  const user = req.user;
  res.status(200).json({ message: "All users", currentUserRole: user.role });
};
