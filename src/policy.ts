export type ActionKind =
  | "NAVIGATE" | "READ" | "CLICK" | "TYPE" | "SELECT" | "SCROLL"
  | "WAIT" | "EXTRACT" | "SUBMIT" | "CREDENTIAL_FILL" | "CREDENTIAL_USE" | "CREDENTIAL_REVEAL" | "FINISH"
  // Task 32 (Phase 4): the quarantined one-time-code read (src/run_manager.ts's read2FA). Gated
  // the same as every other kind - must be listed in actions_allow - PLUS an extra check
  // RunManager runs itself (the run's current page origin must already be inside
  // domains_allow) since this kind carries no url for check() to validate against.
  | "READ_2FA"
  // Task 37 (Phase 6): DevTools-equivalent page inspection (src/run_manager.ts's inspect). Gated
  // the same as every other kind via actions_allow, PLUS two independent, narrower opt-ins on the
  // Policy itself (allow_cookie_inspection, allow_unredacted_inspect) that RunManager.inspect
  // checks before ever dispatching to the bridge - see THE RISK in
  // docs/plans/2026-08-14-comet-agent-phase6-inspect-assistant.md.
  | "INSPECT"
  // Task 38 (Phase 6): ask Comet's Perplexity Assistant sidebar (src/run_manager.ts's
  // assistantAsk) - routes through the user's Perplexity account and its enabled connectors
  // (GitHub etc.). Gated the same as every other ordinary kind via actions_allow alone (no extra
  // narrower opt-in like INSPECT's, since the query is the agent's own text, not page content) -
  // but the ANSWER is treated as untrusted content exactly like a page read: it merges untrusted
  // provenance and, under content_mode:"quarantined", never returns raw. See THE RISK rule 4 in
  // docs/plans/2026-08-14-comet-agent-phase6-inspect-assistant.md.
  | "ASSISTANT";

// Phase 5 Task 26 removed SUBMIT, the last member, from this set: no ActionKind is blanket-denied
// here any more. The mechanism (and the ActionKind that check() below still consults it against)
// stays in place deliberately - a future dangerous kind can be added back to it in one line - but
// today it is empty, which means EVERY action kind's gating now lives elsewhere: ordinary kinds
// (NAVIGATE/READ/CLICK/TYPE/SCROLL/WAIT/EXTRACT/SUBMIT) are governed by actions_allow + budgets +
// domain policy right below; CREDENTIAL_FILL/CREDENTIAL_USE/CREDENTIAL_REVEAL are additionally
// gated by the checks in src/credential_gate.ts (policy pre-authorisation via credential_sites,
// origin binding, a single-use out-of-band approval bound to that exact action type, and - for
// FILL - the browser's own origin-bound autofill) - every caller MUST run checkCredentialFill()
// and get an allow before ever attempting a fill/use/reveal. CREDENTIAL_REVEAL additionally
// requires `policy.allow_credential_reveal === true`, checked by RunManager.credentialReveal
// itself before the gates run - see that field's doc comment below. SUBMIT itself now requires
// nothing beyond being listed in actions_allow - a default session that never lists it still
// cannot submit; see src/actor.ts's CometActor.submit and RunManager's dispatchAct.
//
// Phase 4 Task 31 adds a SEPARATE, orthogonal gate on top of this one for UNATTENDED runs only:
// src/irreversible.ts's classifyAction() heuristically tags a specific attempted action (by
// element name/current host, not by ActionKind) as change-password/add-oauth/payment/delete/
// transfer-shaped, and RunManager blocks-and-pauses any such tag the mission did not
// pre-authorise. This set (DANGEROUS) intentionally stays empty and untouched - it is a per-KIND
// blanket switch that applies to every run (attended and unattended alike), while the Task 31
// gate is per-ATTEMPT, heuristic, and unattended-only. Do not conflate the two: widening or
// narrowing DANGEROUS is not how irreversible-action containment is implemented any more.
export const DANGEROUS: ReadonlySet<ActionKind> = new Set([]);

export interface Policy {
  domains_allow: string[];
  domains_deny?: string[];
  actions_allow: ActionKind[];
  budgets: {
    max_actions: number;
    max_domains: number;
    max_ms: number;
    // Largest path+query+fragment a single NAVIGATE may carry once the run has seen untrusted
    // (page-derived) data. Closes the "stuff the payload in the fragment of an ALLOWLISTED host"
    // exfil route, which rules 3/4 never see because they only fire on non-allowlisted origins.
    // Generous by default so ordinary deep links and search URLs are unaffected.
    max_url_payload_chars?: number;
  };
  // Governs comet_read: "quarantined" (default when unset) strips raw page/email text and
  // returns only a content_digest + element map; "raw" is an explicit per-run opt-in for
  // trusted internal sites. See src/run_manager.ts's read().
  content_mode?: "raw" | "quarantined";
  // Phase 3: sites (exact host, e.g. "example.com" - NOT a suffix/wildcard match) the run is
  // pre-authorised to fill a saved credential into. Absent or empty means none allowed. This is
  // gate 1 of 4 in checkCredentialFill (src/credential_gate.ts) - listing a site here alone does
  // NOT permit a fill; origin binding and a fresh out-of-band approval are still required.
  credential_sites?: string[];
  // Phase 5 Task 25: the single most dangerous op in the system - handing decrypted plaintext
  // (username+password) TO THE CALLER, not just typing it into the live browser. Defaults to
  // false/absent (a session that never sets this can NEVER reveal, no matter what else it opts
  // into). Even when true, credential_sites + origin binding + a fresh out-of-band approval
  // minted specifically as CREDENTIAL_REVEAL are still required - this flag is an ADDITIONAL
  // opt-in on top of those, not a replacement for any of them. See THE RISK in
  // docs/plans/2026-08-13-comet-agent-phase5.md.
  allow_credential_reveal?: boolean;
  // Task 37 (Phase 6): comet_inspect's `cookies:true` request additionally requires this flag -
  // document.cookie is session-token theft surface, and is NEVER covered by INSPECT merely being
  // in actions_allow (unlike every other inspection kind). Defaults to false/absent. See THE RISK
  // rule 2 in docs/plans/2026-08-14-comet-agent-phase6-inspect-assistant.md.
  allow_cookie_inspection?: boolean;
  // Task 37 (Phase 6): comet_inspect's `unredacted:true` request additionally requires this flag -
  // it disables the credential redactor entirely for this call, so every string comes back
  // exactly as the page/console emitted it. Defaults to false/absent; reserve for pages the user
  // trusts. See THE RISK rule 1 in docs/plans/2026-08-14-comet-agent-phase6-inspect-assistant.md.
  allow_unredacted_inspect?: boolean;
}

export interface ActionRequest { kind: ActionKind; url?: string; }

export interface PolicyState {
  started_ms: number;
  actions_used: number;
  domains_used: string[]; // JSON-serializable (not a Set) so it can go in audit + across the wire
}

export const DEFAULT_PHASE1_POLICY: Policy = {
  domains_allow: [],
  domains_deny: [],
  actions_allow: ["NAVIGATE", "READ", "CLICK", "TYPE", "SCROLL", "WAIT"],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 }
};

export function newState(nowMs: number): PolicyState {
  return { started_ms: nowMs, actions_used: 0, domains_used: [] };
}

function hostOf(url?: string): string | undefined {
  if (!url) return undefined;
  try { return new URL(url).hostname.toLowerCase(); } catch { return undefined; }
}

// Exported so RunManager can reuse it for Task 32's "current origin is inside domains_allow"
// check (src/run_manager.ts's read2FA) without a third copy of this same 3-line function.
export function hostMatches(host: string, entry: string): boolean {
  const e = entry.toLowerCase();
  return host === e || host.endsWith("." + e);
}

export function check(policy: Policy, req: ActionRequest, state: PolicyState, nowMs: number):
  { allowed: boolean; reason?: string } {
  if (DANGEROUS.has(req.kind)) return { allowed: false, reason: "dangerous action disabled in phase 1" };
  if (!policy.actions_allow.includes(req.kind)) return { allowed: false, reason: `action ${req.kind} not in actions_allow` };
  if (state.actions_used >= policy.budgets.max_actions) return { allowed: false, reason: "action budget exhausted" };
  if (nowMs - state.started_ms > policy.budgets.max_ms) return { allowed: false, reason: "time budget exhausted" };

  if (req.url !== undefined) {
    const host = hostOf(req.url);
    if (!host) return { allowed: false, reason: "unparseable or non-http(s) url" };
    if ((policy.domains_deny ?? []).some(d => hostMatches(host, d))) return { allowed: false, reason: `domain denied: ${host}` };
    if (!policy.domains_allow.some(d => hostMatches(host, d))) return { allowed: false, reason: `domain not allowlisted: ${host}` };
    const isNew = !state.domains_used.includes(host);
    if (isNew && state.domains_used.length >= policy.budgets.max_domains) return { allowed: false, reason: "domain budget exhausted" };
  }
  return { allowed: true };
}

export function consume(state: PolicyState, req: ActionRequest, host: string | undefined): PolicyState {
  const domains_used = state.domains_used.slice();
  if (host && !domains_used.includes(host)) domains_used.push(host);
  return { ...state, actions_used: state.actions_used + 1, domains_used };
}
