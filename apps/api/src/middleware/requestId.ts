import type { RequestHandler } from "express";
import { randomUUID } from "crypto";

export const requestId: RequestHandler = (req, _res, next) => {
  req.headers["x-request-id"] ??= randomUUID();
  next();
};
