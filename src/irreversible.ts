// Task 31 (Phase 4). See THE RISK invariant 4 in
// docs/plans/2026-08-14-comet-agent-phase4-unattended.md: "Irreversible actions still gate."
// Default posture on an unattended run is block-and-pause; only a mission that pre-authorised
// this EXACT tag may proceed (see RunManager's classifyIrreversible/checkIrreversible, wired
// into act() and credentialUse()).
//
// classifyAction is a HEURISTIC SPEED BUMP, not a wall - say so everywhere it is used. It matches
// the acted-upon element's accessible name/role (`target`) AND the current page's host
// (`currentOrigin`) against a small, fixed set of per-tag regex patterns. Both false negatives (a
// "Confirm" button with a generic accessible name that actually deletes something) and false
// positives (an unrelated "Remove filter" control that happens to share wording with a real
// destructive action) are EXPECTED and ACCEPTABLE - the real containment for an unattended run is
// mission scope + the signed, tamper-evident audit trail + the human who reviewed the grant
// BEFORE any of these tags existed, not this pattern match. Every pattern lives in ONE table
// (IRREVERSIBLE_PATTERNS) so the whole detection surface is reviewable and independently testable
// (tests/irreversible.test.ts) rather than scattered across call sites.
//
// `kind` is accepted for interface completeness / future kind-scoped patterns and call-site
// clarity, but is NOT currently consulted by the matcher - every tag below is target/host-shaped
// only, not action-kind-shaped (a CLICK named "Delete Account" and a TYPE into a field named
// "Delete Account" are equally suspicious).

export interface IrreversiblePattern {
  tag: string;
  patterns: readonly RegExp[];
}

export const IRREVERSIBLE_PATTERNS: readonly IrreversiblePattern[] = [
  {
    tag: "change-password",
    patterns: [/change.?password/i, /reset.?password/i, /update.?password/i]
  },
  // Separators are `.?` throughout, NOT literal spaces. A literal-space pattern matches
  // "Delete account" but silently misses "delete-account", "delete_account" and "deleteAccount" -
  // the same one-encoding-only gap that let percent-encoded and protocol-relative open-redirects
  // past the Phase 2 egress gate until an adversarial probe caught them. Hostnames in particular
  // are hyphenated, and `currentOrigin` is a HOST, so a literal-space pattern could never match a
  // host signal at all. Erring toward matching is the safe direction here: a false positive only
  // pauses the run for approval, a false negative lets an irreversible action through unattended.
  {
    tag: "add-oauth",
    patterns: [/authorize.?app/i, /connect.?account/i, /add.?(integration|connection)/i, /oauth.?authorize/i]
  },
  {
    tag: "payment",
    patterns: [/pay.?now/i, /checkout/i, /purchase/i, /subscribe/i, /add.?payment/i]
  },
  {
    tag: "delete",
    patterns: [/delete.?account/i, /remove.?account/i, /deactivate.?account/i, /destroy.?project/i]
  },
  {
    tag: "transfer",
    patterns: [/transfer.?ownership/i, /wire.?funds/i, /send.?money/i, /transfer.?funds/i]
  }
];

// Returns the first matching tag (table order), or null when neither `target` nor
// `currentOrigin` matches anything. Both arguments are optional and independently checked; an
// absent/empty signal simply contributes nothing (never throws, never matches).
export function classifyAction(kind: string, target: string | undefined, currentOrigin: string | undefined): string | null {
  void kind;
  const signals = [target, currentOrigin].filter((s): s is string => typeof s === "string" && s.length > 0);
  if (signals.length === 0) return null;
  for (const { tag, patterns } of IRREVERSIBLE_PATTERNS) {
    if (signals.some(s => patterns.some(p => p.test(s)))) return tag;
  }
  return null;
}
