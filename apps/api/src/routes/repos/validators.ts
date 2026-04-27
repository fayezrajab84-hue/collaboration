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

// Phase 27 Slice A — operator-declared container image refs this repo builds.
// Strings (not IDs) because they survive Container row recreation and are
// friendlier to type. The correlation engine matches via imageRef equality.
export const repoAssetLinksSchema = z.object({
  buildsContainerImages: z.array(z.string().min(1)).optional(),
});
