// Package imports
import express from "express";
import type { Request, Response, NextFunction } from "express";
import "dotenv/config";
import helmet from "helmet";
import compression from "compression";
import cors from "cors";
import morgan from "morgan";

// Local imports
import { limiter } from "./middlewares/rateLimiter.ts";
import healthRoute from "./routes/v1/health.ts";
import authRoutes from "./routes/v1/auth.ts";

export const app = express();

app
  .use(morgan("dev"))
  .use(express.urlencoded({ extended: true }))
  .use(express.json())
  .use(cors())
  .use(helmet())
  .use(compression())
  .use(limiter);

app.use("", healthRoute);
app.use("/api/v1", authRoutes);

app.use((error: any, req: Request, res: Response, next: NextFunction) => {
  const status = error.status || 500;
  const message = error.message || "Server Error";
  const errorCode = error.code || "Error_Code";

  res.status(status).json({ message, error: errorCode });
});
