export const checkUserExit = (user: any) => {
  if (user) {
    const error: any = new Error("This phone number has already been existed");
    error.status = 409;
    error.errorCode = "Error_Already_Exist";
    throw error;
  }
};
