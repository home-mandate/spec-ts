// SPDX-License-Identifier: Apache-2.0

// The package as a user gets it: built, packed and installed into an empty project. Node.js
// does not run TypeScript under node_modules, so nothing here may depend on the sources.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { after, before, test } from "node:test";
import { installPackage, type Installed } from "../scripts/install-package.ts";

const ROOT = resolve(import.meta.dirname, "..");
const project = mkdtempSync(join(tmpdir(), "home-mandate-spec-package-"));
const mandate = readFileSync(join(ROOT, "spec", "examples", "voice-assistant.json"), "utf8");

let installed: Installed;

function runInProject(source: string): string {
  const file = join(project, "check.mjs");
  writeFileSync(file, source);
  return execFileSync(process.execPath, [file], { cwd: project, encoding: "utf8", env: { ...process.env, MANDATE: mandate } });
}

before(() => {
  installed = installPackage(project);
});

after(() => {
  rmSync(project, { recursive: true, force: true });
});

test("the package holds the compiled code and the data it reads, and nothing else", () => {
  const names = execFileSync("tar", ["tzf", installed.tarball], { encoding: "utf8" }).trim().split("\n").map((name) => relative("package", name));
  const unexpected = names.filter((name) =>
    !["LICENSE", "README.md", "package.json", "spec/data/forbidden-codepoints-v0.json", "spec/vocabulary/v0.json"].includes(name) &&
    !/^dist\/.+\.(?:js|d\.ts)$/.test(name));
  assert.deepEqual(unexpected, []);
  assert.ok(names.includes("dist/index.js"));
  assert.ok(names.includes("dist/browser.js"));
});

test("the package is public and names its repository", () => {
  const manifest = JSON.parse(readFileSync(join(installed.packageDir, "package.json"), "utf8")) as Record<string, unknown>;
  assert.equal(manifest.private, undefined);
  assert.deepEqual(manifest.publishConfig, { access: "public" });
  assert.equal((manifest.repository as { url: string }).url, "git+https://github.com/home-mandate/spec-ts.git");
  assert.deepEqual(manifest.dependencies, undefined);
});

test("the Node.js entry works from the installed package", () => {
  const out = runInProject(`
    import { parseMandate, verifyAuditLines, verifySigned } from "@home-mandate/spec";
    const m = parseMandate(process.env.MANDATE);
    console.log(typeof verifyAuditLines, typeof verifySigned, m.version !== undefined);
  `);
  assert.equal(out.trim(), "function function true");
});

test("the browser entry works from the installed package", () => {
  const out = runInProject(`
    import { digest, vocabularyVersion } from "@home-mandate/spec/browser";
    console.log(digest(JSON.parse(process.env.MANDATE)).startsWith("sha256:"), typeof vocabularyVersion);
  `);
  assert.equal(out.trim(), "true string");
});

test("the harness command reports the version of the package", () => {
  const version = (JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { version: string }).version;
  const out = execFileSync(join(project, "node_modules", ".bin", "mandate-harness-ts"), { input: '{"op":"capabilities"}\n', encoding: "utf8" });
  assert.equal((JSON.parse(out) as { version: string }).version, version);
});

test("a TypeScript project can compile against the types of the package", () => {
  writeFileSync(join(project, "check.ts"), `
    import { evaluate, parseMandate, type Result } from "@home-mandate/spec";
    import { vocabulary, type Mandate } from "@home-mandate/spec/browser";
    const mandate: Mandate = parseMandate("{}");
    export const result: Result = evaluate(mandate, { resource: { entity_id: "a", category: "lock" }, action: "unlock", time: "", timezone: "" });
    export const known = vocabulary;
    // @ts-expect-error the types are real: a mandate is not a number
    export const wrong: number = mandate;
    // @ts-expect-error this name is not exported
    import { notExported } from "@home-mandate/spec";
    export { notExported };
  `);
  execFileSync(join(ROOT, "node_modules", ".bin", "tsc"), [
    "--noEmit", "--strict", "--target", "ES2024", "--module", "NodeNext", "--moduleResolution", "NodeNext",
    "--skipLibCheck", "false", "--typeRoots", join(ROOT, "node_modules", "@types"), "--types", "node", "check.ts",
  ], { cwd: project, stdio: "inherit" });
});
