import type { Request, Response } from "express";
// Types
interface CustomRequest extends Request {
  userId?: number;
}
export const getAllUsers = (req: CustomRequest, res: Response) => {
  const id = req.userId;
  res.status(200).json({ message: "All users", currentUserId: id });
};
