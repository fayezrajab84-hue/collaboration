import type { RequestHandler } from "express";

export const requireAuth: RequestHandler = (req, res, next) => {
  if (req.isAuthenticated()) {
    next();
    return;
  }
  res.status(401).json({ error: "Authentication required" });
};
