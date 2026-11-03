// SPDX-License-Identifier: Apache-2.0

// Builds and packs this package and installs the tarball into an empty project, as a user
// would get it from the registry. Everything that checks the package checks this copy.
// Usage: node scripts/install-package.ts <empty directory>
// The tarball ends up in that directory, its name on the standard output.
import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");

export interface Installed {
  tarball: string;
  packageDir: string;
}

export function installPackage(directory: string): Installed {
  const project = resolve(directory);
  mkdirSync(project, { recursive: true });
  rmSync(join(ROOT, "dist"), { recursive: true, force: true });
  execFileSync(join(ROOT, "node_modules", ".bin", "tsc"), ["-p", "tsconfig.build.json"], { cwd: ROOT, stdio: "inherit" });
  const packed = execFileSync("npm", ["pack", "--json", "--pack-destination", project], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
  const tarball = join(project, (JSON.parse(packed) as { filename: string }[])[0]!.filename);
  writeFileSync(join(project, "package.json"), JSON.stringify({ name: "consumer", private: true, type: "module" }));
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball], { cwd: project, stdio: ["ignore", "ignore", "inherit"] });
  return { tarball, packageDir: join(project, "node_modules", "@home-mandate", "spec") };
}

if ((import.meta as { main?: boolean }).main) {
  const directory = process.argv[2];
  if (!directory) {
    console.error("usage: node scripts/install-package.ts <empty directory>");
    process.exit(2);
  }
  console.log(installPackage(directory).tarball);
}
