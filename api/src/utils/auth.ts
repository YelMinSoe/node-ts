import { errorCode } from "../../config/errorCode.ts";

export const checkUserExit = (user: any) => {
  if (user) {
    const error: any = new Error("This phone number has already been existed");
    error.status = 409;
    error.errorCode = errorCode.userExist;
    throw error;
  }
};

export const checkOtpErrorIfSameDate = (
  isSameDate: boolean,
  errorCount: number,
) => {
  if (isSameDate && errorCount === 5) {
    const error: any = new Error(
      "OTP is wrong for 5 times.Please try again torrow",
    );
    error.status = 401;
    error.errorCode = errorCode.overLimit;
    throw error;
  }
};

export const checkOtpRow = (otpRow: any) => {
  if (!otpRow) {
    const error: any = new Error("Phone number is incorrect");
    error.status = 400;
    error.errorCode = errorCode.invalid;
    throw error;
  }
};

export const checkUserIfNotExist = (user: any) => {
  if (!user) {
    const error: any = new Error("This phone number have not registered");
    error.status = 401;
    error.errorCode = "Error_Unthenticated";
    throw error;
  }
};
