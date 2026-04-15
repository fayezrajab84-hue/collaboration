import { PrismaClient } from "@prisma/client";
import { config } from "./config.js";

const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: ["error", "warn"],
  });

if (config.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}

export default prisma;
