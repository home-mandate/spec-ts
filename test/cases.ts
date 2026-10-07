// SPDX-License-Identifier: Apache-2.0

// The conformance cases of the specification for mandates, the evaluation rule, selection
// and succession (spec/conformance), registered as tests against one entry point of the
// library: the Node.js entry (conformance.test.ts) and the browser entry (browser.test.ts)
// run the same cases.
import assert from "node:assert/strict";
import { test } from "node:test";
import type * as Browser from "../src/browser.ts";
import { specFile } from "../src/spec.ts";

export type Case = Record<string, any>;

type Library = Pick<typeof Browser, "evaluate" | "isSuccessor" | "selectAndEvaluate" | "tryParseMandate">;

export function cases(path: string, key = "cases"): Case[] {
  const list = JSON.parse(specFile(path))[key] as Case[];
  assert.ok(list.length > 0, `${path} has no cases`);
  return list;
}

function mandateText(c: Case): string {
  if (c.mandate) return specFile(c.mandate);
  return c.mandate_raw ?? JSON.stringify(c.mandate_inline);
}

function request(c: Case): Browser.Request {
  return { resource: c.resource, action: c.action, parameters: c.parameters, time: c.time, timezone: c.timezone, revoked: c.revoked };
}

function assertOutcome(c: Case, result: Browser.Result): void {
  assert.equal(result.decision, c.expected, c.why);
  assert.equal(result.reason, c.reason, c.why);
  if ("rule_id" in c) assert.equal(result.rule_id ?? null, c.rule_id);
  if (c.approval_timeout) assert.equal(result.approval?.timeout, c.approval_timeout);
  assert.equal(result.approval !== undefined, result.decision === "ask");
}

/** Registers the tests of the evaluator and selection cases against the library. */
export function mandateConformance(entry: string, lib: Library): void {
  test(`${entry}: evaluation cases`, () => {
    for (const c of cases("conformance/cases-v0.json")) {
      assertOutcome(c, lib.evaluate(lib.tryParseMandate(mandateText(c)), request(c)));
    }
  });

  test(`${entry}: invalid mandates are rejected`, () => {
    for (const c of cases("conformance/invalid-v0.json")) {
      assert.equal(lib.tryParseMandate(mandateText(c)), null, `${c.id}: ${c.why}`);
    }
  });

  test(`${entry}: digests`, () => {
    for (const c of cases("conformance/digest-v0.json")) {
      assert.equal(lib.tryParseMandate(mandateText(c))?.digest, c.digest, `${c.id}: ${c.why}`);
    }
  });

  test(`${entry}: selection of the mandate`, () => {
    for (const c of cases("conformance/selection-v0.json")) {
      const stored = c.mandates.map((m: Case) => ({ mandate: JSON.stringify(m.mandate_inline), revoked: m.revoked }));
      const { selected, result } = lib.selectAndEvaluate(stored, c.subject.client_id, c.subject.principal, request(c));
      assertOutcome(c, result);
      assert.equal(selected?.id ?? null, c.selected, `${c.id}: ${c.why}`);
    }
  });

  test(`${entry}: succession of versions`, () => {
    for (const c of cases("conformance/succession-v0.json")) {
      const stored = lib.tryParseMandate(JSON.stringify(c.stored));
      assert.ok(stored);
      assert.equal(lib.isSuccessor(stored, lib.tryParseMandate(JSON.stringify(c.offered))), c.expected === "accept", `${c.id}: ${c.why}`);
    }
  });
}
