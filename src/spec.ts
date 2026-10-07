// SPDX-License-Identifier: Apache-2.0

// Files of the specification, copied into spec/ by scripts/sync-spec.ts, read from the file
// system: for the tests and Node.js tools only. The library itself imports what it needs
// statically (spec-data.ts, generated/), so that it runs in a web browser as well.
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dirname, "..", "spec");

export function specFile(path: string): string {
  return readFileSync(join(root, path), "utf8");
}
