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
export const invalidMandates: readonly string[] = cases("conformance/invalid-v0.json").map(
  (c) => c.mandate_raw ?? JSON.stringify(c.mandate_inline),
);
