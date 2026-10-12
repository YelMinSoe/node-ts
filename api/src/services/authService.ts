import { prisma } from "../lib/prisma.ts";

export const getUserByPhone = async (phone: string) => {
  prisma.user.findUnique({ where: { phone } });
};

export const createOtp = async (otpData: any) => {
  return prisma.otp.create({ data: otpData });
};
