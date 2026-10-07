// SPDX-License-Identifier: Apache-2.0

// Data files of the specification (spec/, copied by scripts/sync-spec.ts), imported as
// static JSON modules, so that they work without a file system, in a web browser as well.
import codepointFile from "../spec/data/forbidden-codepoints-v0.json" with { type: "json" };
import vocabularyFile from "../spec/vocabulary/v0.json" with { type: "json" };

export interface VocabularyParameter {
  unit?: string;
  minimum?: number;
  maximum?: number;
}

export interface VocabularyAction {
  /** Critical actions are demoted from allow to ask (SPEC-v0 section 4.1). */
  critical?: boolean;
  parameters?: Readonly<Record<string, Readonly<VocabularyParameter>>>;
}

export interface VocabularyCategory {
  actions: Readonly<Record<string, Readonly<VocabularyAction>>>;
}

/** Categories of vocabulary v0 (SPEC-v0 section 5) by name. */
export type Vocabulary = Readonly<Record<string, Readonly<VocabularyCategory>>>;

export interface Codepoints {
  forbidden: readonly (readonly [number, number])[];
  joiners: readonly number[];
  not_first: readonly (readonly [number, number])[];
}

// The modules are shared by every importer: frozen, so that no caller can change the
// vocabulary the evaluation uses.
function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export const vocabulary: Vocabulary = deepFreeze(vocabularyFile.categories) as Vocabulary;

export const codepoints: Codepoints = deepFreeze(codepointFile) as unknown as Codepoints;
