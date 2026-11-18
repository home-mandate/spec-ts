// SPDX-License-Identifier: Apache-2.0

// The canonical text form of an IP address or prefix of a trusted proxy (SPEC-v0 section 9.1,
// config.changed with trusted_proxy): IPv4 in dotted decimal without leading zeros; IPv6 as
// RFC 5952 section 4 writes it, an IPv4-mapped address ending in dotted decimal (RFC 5952
// section 5); a prefix without host bits; and no prefix of full length.

const IPV4_BYTES = 4;
const IPV6_BYTES = 16;
const IPV6_GROUPS = 8;

/** Whether value is an address or a prefix in its one canonical text form. */
export function canonicalProxy(value: string): boolean {
  const slash = value.indexOf("/");
  const text = slash < 0 ? value : value.slice(0, slash);
  const address = parseAddress(text);
  if (address === null || formatAddress(address) !== text) return false;
  if (slash < 0) return true;
  const bitsText = value.slice(slash + 1);
  if (!/^(0|[1-9][0-9]{0,2})$/.test(bitsText)) return false;
  const bits = Number(bitsText);
  // A prefix of full length names one address and is written as that address.
  return bits < address.length * 8 && hostBitsZero(address, bits);
}

function hostBitsZero(address: readonly number[], bits: number): boolean {
  return address.every((byte, i) => {
    const kept = Math.min(Math.max(bits - i * 8, 0), 8);
    return (byte & (0xff >> kept)) === 0;
  });
}

function parseIPv4(text: string): number[] | null {
  const parts = text.split(".");
  if (parts.length !== IPV4_BYTES || !parts.every((p) => /^(0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255)) return null;
  return parts.map(Number);
}

/** The bytes of an address: 4 for IPv4, 16 for IPv6; null if it is none. */
function parseAddress(text: string): number[] | null {
  if (!text.includes(":")) return parseIPv4(text);
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const groups = (half: string): number[] | null => {
    if (half === "") return [];
    const out: number[] = [];
    const parts = half.split(":");
    for (const [i, part] of parts.entries()) {
      if (i === parts.length - 1 && part.includes(".")) {
        const v4 = parseIPv4(part);
        if (v4 === null) return null;
        out.push((v4[0]! << 8) | v4[1]!, (v4[2]! << 8) | v4[3]!);
      } else if (/^[0-9a-fA-F]{1,4}$/.test(part)) {
        out.push(parseInt(part, 16));
      } else {
        return null;
      }
    }
    return out;
  };
  const head = groups(halves[0]!);
  const tail = halves.length === 2 ? groups(halves[1]!) : [];
  if (head === null || tail === null) return null;
  // A dotted part may only end the address.
  if (halves.length === 2 && halves[0]!.includes(".")) return null;
  const missing = IPV6_GROUPS - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const all = [...head, ...new Array<number>(halves.length === 2 ? missing : 0).fill(0), ...tail];
  return all.flatMap((g) => [g >> 8, g & 0xff]);
}

function formatAddress(address: readonly number[]): string {
  if (address.length === IPV4_BYTES) return address.join(".");
  if (address.length !== IPV6_BYTES) return "";
  if (address.slice(0, 10).every((b) => b === 0) && address[10] === 0xff && address[11] === 0xff) {
    return "::ffff:" + address.slice(12).join(".");
  }
  const groups = Array.from({ length: IPV6_GROUPS }, (_, i) => (address[2 * i]! << 8) | address[2 * i + 1]!);
  // The longest run of two or more zero groups, the first of equally long ones (RFC 5952 section 4.2).
  let [bestStart, bestLength] = [-1, 1];
  for (let i = 0; i < IPV6_GROUPS;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < IPV6_GROUPS && groups[j] === 0) j++;
    if (j - i > bestLength) [bestStart, bestLength] = [i, j - i];
    i = j;
  }
  const hex = (gs: number[]) => gs.map((g) => g.toString(16)).join(":");
  if (bestStart < 0) return hex(groups);
  return hex(groups.slice(0, bestStart)) + "::" + hex(groups.slice(bestStart + bestLength));
}
