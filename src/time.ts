// SPDX-License-Identifier: Apache-2.0

import { ZONE_NAMES } from "./zones.ts";

// Timestamps (SPEC-v0 section 3.1 item 0) and household local time (section 4.2).

export interface Instant {
  /** Nanoseconds since the Unix epoch. */
  ns: bigint;
  /** Offset the timestamp was written with, in minutes. */
  offsetMinutes: number;
}

const TIMESTAMP =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})$/;

export function parseTimestamp(text: string): Instant | null {
  const m = TIMESTAMP.exec(text);
  if (!m) return null;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  if (year === 0 || hour > 23 || minute > 59 || second > 59) return null; // no leap seconds
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null;
  let offsetMinutes = 0;
  const zone = m[8]!;
  if (zone !== "Z") {
    if (zone === "-00:00") return null;
    const oh = Number(zone.slice(1, 3));
    const om = Number(zone.slice(4, 6));
    if (oh > 23 || om > 59) return null;
    offsetMinutes = (zone[0] === "-" ? -1 : 1) * (oh * 60 + om);
  }
  const fraction = BigInt((m[7] ?? "").padEnd(9, "0"));
  const ns = (BigInt(date.getTime()) - BigInt(offsetMinutes) * 60000n) * 1000000n + fraction;
  return { ns, offsetMinutes };
}

export function validTimestamp(text: string): boolean {
  return parseTimestamp(text) !== null;
}

const DATE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/;

/**
 * Whether text is a calendar date of RFC 3339 (full-date) of a day that exists, not in the
 * year 0000 (SPEC-v0 section 3.1 item 0, conditions.dates). Such dates order like their text.
 */
export function validDate(text: string): boolean {
  const m = DATE.exec(text);
  if (!m) return false;
  const [year, month, day] = m.slice(1, 4).map(Number) as [number, number, number];
  if (year === 0) return false;
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

export interface LocalTime {
  /** Minutes since midnight; seconds are truncated. */
  minute: number;
  /** 0 = Sunday. */
  weekday: number;
  /**
   * The calendar date as year · 10000 + month · 100 + day (SPEC-v0 section 4.2,
   * conditions.dates). Numbers, not text: in another zone a point in time of the year 9999
   * can fall on a day of the year 10000, and one of the year 0001 on a day before it (the
   * year 0 or earlier), and text would order "10000-01-01" before "1999-12-31".
   */
  day: number;
}

/** The number of a calendar date, as LocalTime.day. */
export function dayNumber(year: number, month: number, day: number): number {
  return year * 10000 + month * 100 + day;
}

/** The number of a date YYYY-MM-DD that validDate accepts. */
export function dateNumber(text: string): number {
  return dayNumber(Number(text.slice(0, 4)), Number(text.slice(5, 7)), Number(text.slice(8, 10)));
}

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function floorDiv(a: bigint, b: bigint): bigint {
  const q = a / b;
  return a % b !== 0n && a < 0n !== b < 0n ? q - 1n : q;
}

/** Household local time; null if the time zone name is not permitted or not known. */
export function localTime(at: Instant, zone: string | undefined): LocalTime | null {
  const ms = Number(floorDiv(at.ns, 1000000n));
  if (!zone) {
    const shifted = new Date(ms + at.offsetMinutes * 60000);
    return {
      minute: shifted.getUTCHours() * 60 + shifted.getUTCMinutes(), weekday: shifted.getUTCDay(),
      day: dayNumber(shifted.getUTCFullYear(), shifted.getUTCMonth() + 1, shifted.getUTCDate()),
    };
  }
  if (!zoneKnown(zone)) return null;
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: zone, weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23",
    year: "numeric", month: "2-digit", day: "2-digit", era: "short",
  }).formatToParts(new Date(ms));
  const part = (type: string) => parts.find((p) => p.type === type)!.value;
  // Before the year 1 Intl counts years of the era BC: 1 BC is the year 0.
  const year = part("era") === "BC" ? 1 - Number(part("year")) : Number(part("year"));
  return {
    minute: Number(part("hour")) * 60 + Number(part("minute")), weekday: WEEKDAYS.indexOf(part("weekday")),
    day: dayNumber(year, Number(part("month")), Number(part("day"))),
  };
}

const ZONE_PART = /^[A-Z][A-Za-z0-9_+-]*$/;

// zoneKnown implements the name rule of section 4.2. Intl matches names without regard to
// case, reports another canonical name for a link and knows names that left the database,
// so the spelling is compared with the list of the database. The runtime must know the
// zone as well.
function zoneKnown(zone: string): boolean {
  if (zone === "UTC") return true;
  const parts = zone.split("/");
  if (zone.length > 64 || parts.length < 2 || !parts.every((p) => ZONE_PART.test(p))) return false;
  if (!ZONE_NAMES.has(zone)) return false;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: zone });
    return true;
  } catch {
    return false;
  }
}
