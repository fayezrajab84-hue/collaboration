import { z } from "zod";

export const createRepoSchema = z.object({
  githubUrl: z
    .string()
    .url()
    .refine((url) => url.includes("github.com"), "Must be a GitHub URL"),
  defaultBranch: z.string().optional(),
});

export const updateRepoSchema = z.object({
  defaultBranch: z.string().min(1).optional(),
});

export const triggerScanSchema = z.object({
  scanTypes: z
    .array(z.enum(["SAST", "SCA", "SECRET", "IAC", "CONTAINER", "DAST", "PENTEST"]))
    .optional(),
  branch: z.string().optional(),
});
