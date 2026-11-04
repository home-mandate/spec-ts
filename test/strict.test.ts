// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import { entryDigest, verifyAudit } from "../src/audit.ts";
import { selectAndEvaluate } from "../src/evaluate.ts";
import { JsonError, parseJson, parseRecorded } from "../src/ijson.ts";
import { localTime, parseTimestamp } from "../src/time.ts";

const at = parseTimestamp("2026-10-12T12:00:00Z")!;

const NONCHARACTERS = [
  '"\\ufdd0"', '"\\ufdef"', '"\\ufffe"', '"\\uffff"', '"\\ud83f\\udffe"', '"\\ud83f\\udfff"', '"\\udbff\\udfff"',
  '"﷐"', '"￿"', '"\u{1ffff}"', '"\u{10ffff}"', '{"\\uffff":1}', '{"﷐":1}', '{"a":[{"b":"\\uffff"}]}',
];

test("parseJson rejects noncharacters, parseRecorded tolerates them (SPEC-v0 sections 3.1 and 14)", () => {
  for (const text of NONCHARACTERS) {
    assert.throws(() => parseJson(text), JsonError, text);
    assert.doesNotThrow(() => parseRecorded(text), text);
  }
});

test("the neighbours of noncharacters are characters", () => {
  for (const text of ['"\\ufdcf"', '"\\ufdf0"', '"\\ufffd"', '"\\ud83f\\udffd"', '"\\ud840\\udc00"', '"﷏ﷰ�\u{1fffd}\u{20000}"']) {
    assert.doesNotThrow(() => parseJson(text), text);
  }
});

test("parseRecorded keeps every other rule", () => {
  for (const text of ['"\\ud800"', '{"a":1,"a":2}', "{} {}", '{"a":1', "", "NaN"]) {
    assert.throws(() => parseRecorded(text), JsonError, text);
  }
});

const entry = (entityId: string): string =>
  `{"agent":{"client_id":"hm-client:voice-7c21e9a4"},"evaluation":{"decision":"deny","reason":"invalid_request","rule_id":null},` +
  `"event":"decision","id":"01a0f64c-7140-7001-9007-0000a2130001","mandate":{"id":"m-voice-assistant","digest":"sha256:${"1".repeat(64)}"},` +
  `"prev":null,"principal":"household:hm-7f3a","recorded_at":"2026-10-01T09:01:00+02:00","request":{"time":"2026-10-12T19:00:00+02:00",` +
  `"timezone":"Europe/Berlin","resource":{"entity_id":"${entityId}"},"action":"turn_on"},"result":{"status":"denied","denied_by":"mandate"},"seq":1,"type":"https://home-mandate.org/audit/v0"}`;

test("an existing log with a noncharacter stays valid, with one digest for both spellings", () => {
  for (const id of ["light.\\uffff", "light.￿", "light.\\ud83f\\udfff"]) {
    assert.deepEqual(verifyAudit([entry(id)]), { valid: true, entries: 1 }, id);
  }
  assert.equal(entryDigest(entry("light.\\uffff")), entryDigest(entry("light.￿")));
  assert.equal(verifyAudit([entry("light.\\ud800")]).valid, false);
});

test("a stored document with a noncharacter is attributed to the agent it names (section 4.3)", () => {
  const other = '{"principal":"household:t","agent":{"client_id":"x:other"},"note":"\\uffff"}';
  const r = selectAndEvaluate([{ mandate: other }], "x:mine", "household:t", { resource: { entity_id: "a", category: "light" }, action: "read", time: "2026-10-12T12:00:00Z" });
  assert.equal(r.result.reason, "no_mandate");
});

test("a number is read whatever the length of its spelling (section 3.2)", () => {
  assert.equal(parseJson("180." + "0".repeat(397)), 180);
  assert.equal(parseJson("1." + "0".repeat(100_000)), 1);
  assert.equal(parseJson("1" + "0".repeat(100) + "e-100"), 1);
  assert.throws(() => parseJson("1." + "0".repeat(100_000) + "1"), JsonError);
  assert.throws(() => parseJson("1.".concat("0".repeat(500), "x")), JsonError);
});

test("reading a long number takes linear time", () => {
  const text = "1" + "0".repeat(200_000) + "1e-200001";
  const start = performance.now();
  assert.throws(() => parseJson(text), JsonError);
  assert.ok(performance.now() - start < 1000);
});

test("the spelling of a time zone name is exact (section 4.2)", () => {
  for (const zone of ["Europe/Berlin", "US/Eastern", "Asia/Kolkata", "Asia/Calcutta", "America/Nuuk", "Etc/GMT+5", "America/Argentina/Buenos_Aires", "UTC"]) {
    assert.notEqual(localTime(at, zone), null, zone);
  }
  for (const zone of ["US/EASTERN", "us/eastern", "Asia/KOLKATA", "America/NUUK", "Europe/BERLIN", "ASIA/CALCUTTA", "SystemV/AST4", "SystemV/PST8", "US/Pacific-New", "Canada/East-Saskatchewan", "Mars/Olympus"]) {
    assert.equal(localTime(at, zone), null, zone);
  }
});

test("every zone the runtime knows has its name in the list", () => {
  for (const zone of Intl.supportedValuesOf("timeZone")) {
    assert.notEqual(localTime(at, zone), null, zone);
  }
});
