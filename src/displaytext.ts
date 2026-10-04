// SPDX-License-Identifier: Apache-2.0

// Text displayed to humans (SPEC-v0 section 3.1 item 8), checked against the code point
// list of the specification, not against the Unicode tables of the runtime.
import { codepoints } from "./spec.ts";

function inRanges(ranges: [number, number][], cp: number): boolean {
  let low = 0;
  let high = ranges.length - 1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    const [start, end] = ranges[mid]!;
    if (cp < start) high = mid - 1;
    else if (cp > end) low = mid + 1;
    else return true;
  }
  return false;
}

export function displayable(text: string): boolean {
  const points = Array.from(text, (c) => c.codePointAt(0)!);
  if (points.length === 0) return false;
  const joiner = (cp: number) => codepoints.joiners.includes(cp);
  for (const edge of [points[0]!, points[points.length - 1]!]) {
    if (edge === 0x20 || joiner(edge)) return false;
  }
  if (inRanges(codepoints.not_first, points[0]!)) return false;
  let afterJoiner = false;
  for (const cp of points) {
    if (inRanges(codepoints.forbidden, cp)) return false;
    if (joiner(cp) && afterJoiner) return false;
    afterJoiner = joiner(cp);
  }
  return true;
}
