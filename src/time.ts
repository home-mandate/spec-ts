// SPDX-License-Identifier: Apache-2.0

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

export interface LocalTime {
  /** Minutes since midnight; seconds are truncated. */
  minute: number;
  /** 0 = Sunday. */
  weekday: number;
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
    return { minute: shifted.getUTCHours() * 60 + shifted.getUTCMinutes(), weekday: shifted.getUTCDay() };
  }
  if (!zoneKnown(zone)) return null;
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: zone, weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  }).formatToParts(new Date(ms));
  const part = (type: string) => parts.find((p) => p.type === type)!.value;
  return { minute: Number(part("hour")) * 60 + Number(part("minute")), weekday: WEEKDAYS.indexOf(part("weekday")) };
}

const ZONE_PART = /^[A-Z][A-Za-z0-9_+-]*$/;

// zoneKnown implements the name rule of section 4.2. Intl matches names without regard
// to case and reports the canonical zone, so the spelling is compared here: a name that
// differs from its canonical zone only in case is not the name of the database.
function zoneKnown(zone: string): boolean {
  if (zone === "UTC") return true;
  const parts = zone.split("/");
  if (zone.length > 64 || parts.length < 2 || !parts.every((p) => ZONE_PART.test(p))) return false;
  let canonical: string;
  try {
    canonical = new Intl.DateTimeFormat("en-US", { timeZone: zone }).resolvedOptions().timeZone;
  } catch {
    return false;
  }
  return canonical === zone || canonical.toLowerCase() !== zone.toLowerCase();
}
