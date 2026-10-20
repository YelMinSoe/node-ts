// Package imports
import express from "express";
import type { Request, Response, NextFunction } from "express";
import "dotenv/config";
import helmet from "helmet";
import compression from "compression";
import cors from "cors";
import morgan from "morgan";
import cookieParser from "cookie-parser";

// Local imports
import { limiter } from "./middlewares/rateLimiter.ts";
import healthRoute from "./routes/v1/health.ts";
import authRoutes from "./routes/v1/auth.ts";
import userRoutes from "./routes/v1/admin/user.ts";
import { auth } from "./middlewares/auth.ts";

export const app = express();

const whiteLists = ["http://example.com", "http://localhost:5173"];
var corsOptions = {
  origin: function (
    origin: any,
    callback: (err: Error | null, origin?: any) => void,
  ) {
    // allow requests with no origins(like mobile and postman)
    if (!origin) return callback(null, true);
    if (whiteLists.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not Allowed by CORS"));
    }
  },
  credentials: true, // allow cookies and authorizations header
};

app
  .use(morgan("dev"))
  .use(express.urlencoded({ extended: true }))
  .use(express.json())
  .use(cors(corsOptions))
  .use(helmet())
  .use(compression())
  .use(limiter)
  .use(cookieParser());

app.use("", healthRoute);
app.use("/api/v1", authRoutes);
// Admin Routes
app.use("/api/v1/admin", auth, userRoutes);

app.use((error: any, req: Request, res: Response, next: NextFunction) => {
  const status = error.status || 500;
  const message = error.message || "Server Error";
  const errorCode = error.code || "Error_Code";

  res.status(status).json({ message, error: errorCode });
});
