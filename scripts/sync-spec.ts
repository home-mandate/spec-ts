// SPDX-License-Identifier: Apache-2.0

// Copies the machine-readable files of the specification into spec/, as listed in its
// manifest, checks every SHA-256 and regenerates the schema validators in src/generated/.
// Usage: node scripts/sync-spec.ts <path to the specification repository>
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { writeValidators } from "./generate-validators.ts";

const source = process.argv[2];
if (!source) {
  console.error("usage: node scripts/sync-spec.ts <path to the specification repository>");
  process.exit(2);
}
const manifestPath = "conformance/manifest.json";
const manifest = JSON.parse(readFileSync(join(source, manifestPath), "utf8")) as {
  files: { path: string; sha256: string }[];
};
const target = join(import.meta.dirname, "..", "spec");
rmSync(target, { recursive: true, force: true });
for (const file of [...manifest.files, { path: manifestPath, sha256: "" }]) {
  const data = readFileSync(join(source, file.path));
  if (file.sha256 && createHash("sha256").update(data).digest("hex") !== file.sha256) {
    console.error(`${file.path}: SHA-256 does not match the manifest`);
    process.exit(1);
  }
  mkdirSync(dirname(join(target, file.path)), { recursive: true });
  cpSync(join(source, file.path), join(target, file.path));
}
console.log(`spec/: ${manifest.files.length} files`);
writeValidators();
console.log("src/generated/: validators regenerated");
