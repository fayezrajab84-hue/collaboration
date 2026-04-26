/**
 * SBOM service — proxies CycloneDX or SPDX SBOM generation to the scanner.
 *
 * Repo:      clones and runs `trivy fs --format <fmt>`.
 * Container: runs `trivy image --format <fmt> <imageRef>`.
 *
 * Returns the parsed JSON object. The Express route sets the right
 * filename/content-type headers based on the format.
 */
import axios from "axios";
import { config } from "../config.js";
import { decrypt } from "./encryptionService.js";

export type SbomFormat = "cyclonedx" | "spdx";

/** Content-Type + filename suffix per format. Used by the route to set headers. */
export const SBOM_FORMAT_META: Record<SbomFormat, { contentType: string; suffix: string }> = {
  cyclonedx: { contentType: "application/vnd.cyclonedx+json", suffix: "cdx.json"  },
  spdx:      { contentType: "application/spdx+json",          suffix: "spdx.json" },
};

export async function generateRepoSbom(input: {
  repoUrl:           string;
  branch:            string;
  encryptedGitToken: string | null;
  format?:           SbomFormat;
}): Promise<unknown> {
  const gitToken = input.encryptedGitToken ? decrypt(input.encryptedGitToken) : undefined;
  const resp = await axios.post(
    `${config.SCANNER_URL}/sbom`,
    {
      target_type: "REPOSITORY",
      format:      input.format ?? "cyclonedx",
      repo_url:    input.repoUrl,
      branch:      input.branch,
      git_token:   gitToken,
    },
    { timeout: 660_000 }, // 11 min — trivy+clone can take a while
  );
  return resp.data;
}

export async function generateContainerSbom(input: {
  imageRef: string;
  format?:  SbomFormat;
}): Promise<unknown> {
  const resp = await axios.post(
    `${config.SCANNER_URL}/sbom`,
    {
      target_type: "CONTAINER",
      format:      input.format ?? "cyclonedx",
      image_ref:   input.imageRef,
    },
    { timeout: 660_000 },
  );
  return resp.data;
}
