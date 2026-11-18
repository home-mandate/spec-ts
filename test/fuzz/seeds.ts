// SPDX-License-Identifier: Apache-2.0

// Seeds of the fuzz targets from the files of the specification (spec/).
import { parseMandate, type Mandate } from "../../src/mandate.ts";
import { cases } from "../cases.ts";
import { specJsonFiles } from "./fuzz.ts";

/** Every valid mandate the specification ships: the examples and the conformance mandates. */
export const shippedMandates: readonly string[] = [...specJsonFiles("examples"), ...specJsonFiles("conformance/mandates")];

/** The shipped mandates, parsed; a seed that is not valid fails the target at once. */
export const parsedMandates: readonly Mandate[] = shippedMandates.map((text) => parseMandate(text));

/** The invalid mandates of the conformance cases, as text. */
// A case given as bytes (mandate_base64) seeds its bytes read as UTF-8, with replacement
// characters where they are not.
export const invalidMandates: readonly string[] = cases("conformance/invalid-v0.json").map(
  (c) => c.mandate_raw ?? (c.mandate_base64 !== undefined ? Buffer.from(c.mandate_base64, "base64").toString("utf8") : JSON.stringify(c.mandate_inline)),
);
