import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { config } from "../config.js";

const ALGORITHM = "aes-256-gcm";
const KEY = Buffer.from(config.ENCRYPTION_KEY, "hex"); // 32 bytes

export function encrypt(plaintext: string): string {
  const iv = randomBytes(12); // 96-bit IV for GCM
  const cipher = createCipheriv(ALGORITHM, KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Pack: iv (12) + tag (16) + ciphertext
  const packed = Buffer.concat([iv, tag, encrypted]);
  return packed.toString("base64");
}

export function decrypt(packed: string): string {
  const buf = Buffer.from(packed, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ciphertext = buf.subarray(28);
  const decipher = createDecipheriv(ALGORITHM, KEY, iv);
  decipher.setAuthTag(tag);
  return decipher.update(ciphertext) + decipher.final("utf8");
}
