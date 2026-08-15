// Phase 3: the four-gate decision for CREDENTIAL_FILL. This module is a pure function so the
// whole decision is unit-testable without a browser - see THE RISK note in the phase-3 plan for
// why this exists. It implements gates 1-3 of the four; gate 4 (Chromium's own origin-bound
// autofill) is enforced by the browser itself in src/actor.ts and cannot be bypassed here.
//
// Fail closed on everything: if a gate cannot be evaluated (unparseable site, missing policy
// list, unknown current origin, unreadable approval store), the answer is DENY. Never allow on
// a "probably fine".
//
// Phase 5 (Task 24) generalised this SAME function (not a copy) to also gate CREDENTIAL_USE via
// the optional CredentialContext.action field - see that field's doc comment. Gates 1/2 (site
// pre-authorisation, origin binding) are intentionally shared across every credential op; only
// gate 3's approval lookup is parameterised by action, so a fill/use/reveal approval can never
// cross-satisfy a different op.
import type { Policy } from "./policy.js";
import type { ApprovalStore, ApprovalAction } from "./approvals.js";

export interface CredentialContext {
  policy: Policy;
  site: string;
  currentOrigin: string | undefined;
  store: ApprovalStore;
  nowMs: number;
  // Phase 5: which approval TYPE gate 3 requires. Optional and defaults to CREDENTIAL_FILL so
  // every pre-Phase-5 caller (this function predates the field) is unaffected. Phase 5 callers
  // (CREDENTIAL_USE, CREDENTIAL_REVEAL) MUST set this explicitly - see THE RISK invariant 3 in
  // docs/plans/2026-08-13-comet-agent-phase5.md: an approval minted for one dangerous op must
  // never satisfy a different one.
  action?: ApprovalAction;
}

export interface CredentialDecision {
  allowed: boolean;
  reason?: string;
  approvalId?: string;
}

// Accepts either a bare hostname ("example.com", matching how credential_sites and the
// approvals store record sites) or a full absolute URL/origin ("https://example.com/login",
// matching how a run tracks its current page). Anything else - empty, protocol-relative
// ("//evil.com"), a bare host with a path/query/fragment/userinfo/port - is rejected rather than
// guessed at, so a malformed or attacker-shaped value never silently resolves to "some host".
function normalizeHost(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      const host = new URL(trimmed).hostname.toLowerCase();
      return host || undefined;
    } catch {
      return undefined;
    }
  }
  // URL-shaped but missing a scheme - never silently treat as a bare hostname.
  if (trimmed.startsWith("//")) return undefined;
  if (/[/\\?#\s@:]/.test(trimmed)) return undefined;
  return trimmed.toLowerCase();
}

export function checkCredentialFill(ctx: CredentialContext): CredentialDecision {
  const site = normalizeHost(ctx.site);
  if (!site) return { allowed: false, reason: "site unparseable or empty" };

  // Gate 1: policy pre-authorisation. Exact host match only - a site listed here does NOT
  // authorise any of its subdomains.
  const authorizedSites = new Set(
    (ctx.policy.credential_sites ?? [])
      .map(normalizeHost)
      .filter((h): h is string => h !== undefined)
  );
  if (!authorizedSites.has(site)) {
    return { allowed: false, reason: "site not authorised for credential fill" };
  }

  // Gate 2: origin binding. The run's current page must BE the authorised site, exactly - not a
  // sibling page on it, not a redirect target, not whatever an injected instruction claims.
  const origin = normalizeHost(ctx.currentOrigin);
  if (!origin || origin !== site) {
    return { allowed: false, reason: "current origin does not match credential site" };
  }

  // Gate 3: a fresh, single-use, out-of-band approval the human granted for this exact site AND
  // this exact action type (defaults to CREDENTIAL_FILL - see CredentialContext.action).
  const approval = ctx.store.find(site, ctx.nowMs, ctx.action ?? "CREDENTIAL_FILL");
  if (!approval) {
    return { allowed: false, reason: "no valid approval" };
  }

  // approvalId only - the caller consumes it AFTER a successful fill (never before, never on
  // failure). Gate 4 (the browser's own origin-bound autofill) happens next, outside this
  // function, in src/actor.ts.
  return { allowed: true, approvalId: approval.id };
}
