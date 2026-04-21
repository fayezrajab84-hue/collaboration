/**
 * SBOM service — proxies CycloneDX SBOM generation to the scanner microservice.
 *
 * Repo: clones and runs `trivy fs --format cyclonedx`.
 * Container: runs `trivy image --format cyclonedx <imageRef>`.
 *
 * Returns the parsed CycloneDX JSON object. Large but streamable; we keep it
 * as an object so the Express route can set filename/content-type headers.
 */
import axios from "axios";
import { config } from "../config.js";
import { decrypt } from "./encryptionService.js";

export async function generateRepoSbom(input: {
  repoUrl:          string;
  branch:           string;
  encryptedGitToken: string | null;
}): Promise<unknown> {
  const gitToken = input.encryptedGitToken ? decrypt(input.encryptedGitToken) : undefined;
  const resp = await axios.post(
    `${config.SCANNER_URL}/sbom`,
    {
      target_type: "REPOSITORY",
      repo_url:    input.repoUrl,
      branch:      input.branch,
      git_token:   gitToken,
    },
    { timeout: 660_000 }, // 11 min — trivy+clone can take a while
  );
  return resp.data;
}

export async function generateContainerSbom(imageRef: string): Promise<unknown> {
  const resp = await axios.post(
    `${config.SCANNER_URL}/sbom`,
    { target_type: "CONTAINER", image_ref: imageRef },
    { timeout: 660_000 },
  );
  return resp.data;
}
