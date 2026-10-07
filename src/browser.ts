// SPDX-License-Identifier: Apache-2.0

// Entry point for web browsers ("@mandate-spec/mandate-spec/browser"): validation of
// mandates, their digest, the evaluation rule and the vocabulary, without Node.js built-in
// modules and without code compiled at run time, so that it runs under a Content Security
// Policy of script-src 'self'. Signatures and audit logs are in the Node.js entry only.
// test/browser.test.ts checks the import graph of this module and runs the conformance
// cases of the specification against it.
export {
  parseMandate, tryParseMandate, MandateError, timeoutSeconds,
  type Mandate, type Rule, type Decision, type Approval,
} from "./mandate.ts";
export {
  evaluate, selectAndEvaluate, isSuccessor, isCritical,
  type Request, type Resource, type Result, type Stored,
} from "./evaluate.ts";
export {
  vocabulary,
  type Vocabulary, type VocabularyCategory, type VocabularyAction, type VocabularyParameter,
} from "./spec-data.ts";
export { displayable } from "./displaytext.ts";
export { canonicalize, digest } from "./jcs.ts";
export { parseJson, JsonError, type Json } from "./ijson.ts";
export type { Instant } from "./time.ts";
