export type Trust = "trusted" | "untrusted";
export interface Provenance { origins: string[]; trust: Trust; }
export interface Tagged<T> { value: T; provenance: Provenance; }

// Lowercased hostname, or null if the url is unparseable / host-less (e.g. "mailto:x").
// Fail-closed pattern matches policy.ts's hostOf: an empty hostname is treated as no origin.
export function originOf(url: string): string | null {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return host || null;
  } catch {
    return null;
  }
}

export function tagUntrusted<T>(value: T, url: string): Tagged<T> {
  // An unparseable source url still gets tagged untrusted; "" as origin ensures it can
  // never equal a real destination origin, so isForeignTo stays fail-closed (true) for it.
  const origin = originOf(url) ?? "";
  return { value, provenance: { origins: [origin], trust: "untrusted" } };
}

export function tagTrusted<T>(value: T): Tagged<T> {
  return { value, provenance: { origins: [], trust: "trusted" } };
}

export function merge(a: Provenance, b: Provenance): Provenance {
  const origins = Array.from(new Set([...a.origins, ...b.origins]));
  const trust: Trust = a.trust === "untrusted" || b.trust === "untrusted" ? "untrusted" : "trusted";
  return { origins, trust };
}

// Trust-aware foreignness. The origins-only rule below is kept for every case with a known
// origin, but an UNTRUSTED payload with an EMPTY origins array used to report "not foreign" to
// every destination - which silently disarmed egress rule 3 for exactly the data we know the
// LEAST about (a bridge read whose payload carried no url, a merged Assistant answer). Untrusted
// means we cannot vouch for where the data came from, so it is foreign EVERYWHERE unless it has
// a non-empty origins array whose members ALL equal the destination. Trusted provenance with no
// origins ({origins:[],trust:"trusted"} - tagTrusted, the operator's own run) stays non-foreign:
// that shape means "no page-derived data at all", not "unknown page-derived data".
export function isForeignTo(p: Provenance, destinationOrigin: string): boolean {
  if (p.trust === "untrusted" && p.origins.length === 0) return true;
  return p.origins.some(o => o !== destinationOrigin);
}
