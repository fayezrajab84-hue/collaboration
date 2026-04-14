import type { ErrorRequestHandler } from "express";
import { Prisma } from "@prisma/client";
import { ZodError } from "zod";
import { logger } from "../logger.js";

export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  const requestId = req.headers["x-request-id"] as string | undefined;

  if (err instanceof ZodError) {
    res.status(422).json({
      error: "Validation error",
      details: err.flatten().fieldErrors,
    });
    return;
  }

  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    if (err.code === "P2025") {
      res.status(404).json({ error: "Resource not found" });
      return;
    }
    if (err.code === "P2002") {
      res.status(409).json({ error: "Resource already exists" });
      return;
    }
  }

  logger.error("Unhandled error", {
    message: err.message,
    stack: err.stack,
    requestId,
    path: req.path,
    method: req.method,
  });

  res.status(500).json({ error: "Internal server error" });
};
