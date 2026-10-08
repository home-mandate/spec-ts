// SPDX-License-Identifier: Apache-2.0

// The browser entry (src/browser.ts): its whole import graph is free of Node.js built-in
// modules, packages and code compiled at run time, and it gives the results the
// conformance cases of the specification expect.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { test } from "node:test";
import ts from "typescript";
import * as browser from "@home-mandate/spec/browser";
import { mandateConformance } from "./cases.ts";

const ROOT = resolve(import.meta.dirname, "..");
const ENTRY = join(ROOT, "src", "browser.ts");

// Globals of Node.js, and the ways to compile code at run time ('unsafe-eval').
const FORBIDDEN_IDENTIFIERS = new Set(["require", "Buffer", "process", "global", "__dirname", "__filename", "eval", "Function"]);

interface Module {
  imports: string[];
  violations: string[];
}

function scan(fileName: string, text: string): Module {
  const source = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const imports: string[] = [];
  const violations: string[] = [];
  const where = (node: ts.Node) => `${relative(ROOT, fileName)}:${source.getLineAndCharacterOfPosition(node.getStart()).line + 1}`;
  const visit = (node: ts.Node): void => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      imports.push(node.moduleSpecifier.text);
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      violations.push(`${where(node)}: dynamic import`);
    } else if (ts.isImportEqualsDeclaration(node)) {
      violations.push(`${where(node)}: import = require`);
    } else if (ts.isMetaProperty(node)) {
      violations.push(`${where(node)}: import.meta`);
    } else if (ts.isIdentifier(node) && FORBIDDEN_IDENTIFIERS.has(node.text) && !isPropertyName(node)) {
      violations.push(`${where(node)}: ${node.text}`);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { imports, violations };
}

// { process: … } declares a property, it does not refer to the global; globalThis.eval
// and window.Function do, so property access is not excepted.
function isPropertyName(node: ts.Identifier): boolean {
  const parent = node.parent;
  return (ts.isPropertyAssignment(parent) || ts.isPropertyDeclaration(parent) || ts.isMethodDeclaration(parent)) && parent.name === node;
}

/** Every module the entry reaches, and every violation found in them. */
function importGraph(entry: string): { files: string[]; violations: string[] } {
  const seen = new Set<string>();
  const violations: string[] = [];
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    if (file.endsWith(".json")) {
      if (!file.startsWith(join(ROOT, "spec") + "/")) violations.push(`${relative(ROOT, file)}: JSON outside spec/`);
      continue;
    }
    const module = scan(file, readFileSync(file, "utf8"));
    violations.push(...module.violations);
    for (const specifier of module.imports) {
      if (!specifier.startsWith(".")) {
        violations.push(`${relative(ROOT, file)}: imports ${specifier}`);
        continue;
      }
      queue.push(resolve(dirname(file), specifier));
    }
  }
  return { files: [...seen].map((f) => relative(ROOT, f)).sort(), violations };
}

test("the scan finds what it must find", () => {
  const module = scan("probe.ts", [
    'import { readFileSync } from "node:fs";',
    'export { x } from "ajv";',
    'const f = new Function("return 1");',
    'const g = globalThis.eval("1");',
    "const b = Buffer.from([]);",
    "const d = import.meta.dirname;",
    'const m = await import("./x.ts");',
    "const o = { Function: 1, process: 2 };",
  ].join("\n"));
  assert.deepEqual(module.imports, ["node:fs", "ajv"]);
  assert.deepEqual(module.violations, [
    "probe.ts:3: Function", "probe.ts:4: eval", "probe.ts:5: Buffer", "probe.ts:6: import.meta", "probe.ts:7: dynamic import",
  ]);
});

test("the browser entry imports no Node.js modules, no packages and compiles no code", () => {
  const { files, violations } = importGraph(ENTRY);
  assert.deepEqual(violations, []);
  for (const required of ["src/mandate.ts", "src/evaluate.ts", "src/generated/mandate-validator.ts", "spec/vocabulary/v0.json"]) {
    assert.ok(files.includes(required), `${required} is part of the graph`);
  }
  for (const nodeOnly of ["src/spec.ts", "src/jws.ts", "src/audit.ts", "src/harness.ts"]) {
    assert.ok(!files.includes(nodeOnly), `${nodeOnly} is not part of the graph`);
  }
});

test("the generated validators contain no code compiled at run time", () => {
  for (const path of ["src/generated/mandate-validator.ts", "src/generated/audit-validator.ts"]) {
    const text = readFileSync(join(ROOT, path), "utf8");
    assert.doesNotMatch(text, /\bnew Function\b|\beval\s*\(|\brequire\s*\(/, path);
  }
});

mandateConformance("browser entry", browser);

test("parseMandate reports why a mandate is not valid", () => {
  const cases: [string, string][] = [
    ["{", "not I-JSON: "],
    ['{"a":1,"a":2}', 'not I-JSON: duplicate key "a"'],
    ["[]", "violates the schema at /: must be object"],
  ];
  for (const [text, message] of cases) {
    assert.throws(() => browser.parseMandate(text), (e: unknown) => e instanceof browser.MandateError && e.message.startsWith(message), text);
    assert.equal(browser.tryParseMandate(text), null);
  }
});

test("vocabulary and isCritical", () => {
  assert.equal(browser.vocabulary.lock?.actions.unlock?.critical, true);
  assert.ok(Object.isFrozen(browser.vocabulary) && Object.isFrozen(browser.vocabulary.lock?.actions));
  assert.equal(browser.isCritical({ category: "lock" }, "unlock"), true);
  assert.equal(browser.isCritical({ category: "lock" }, "lock"), false);
  assert.equal(browser.isCritical({ category: "lock", critical: true }, "lock"), true);
  assert.equal(browser.isCritical({ category: "lock", critical: true }, "read"), false);
  assert.equal(browser.isCritical({ category: "nope" }, "unlock"), false);
  assert.equal(browser.isCritical({}, "unlock"), false);
});
