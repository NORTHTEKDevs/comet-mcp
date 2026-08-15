import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { check, consume, newState, hostMatches, type Policy, type ActionKind, type ActionRequest, type PolicyState } from "./policy.js";
import type { AuditRecord } from "./audit.js";
import { checkEgress, redactCredentials } from "./egress.js";
import { originOf, merge as mergeProvenance, type Provenance } from "./provenance.js";
import { extractQuarantined, type QuarantineClient, type ExtractField } from "./quarantine.js";
import { checkCredentialFill } from "./credential_gate.js";
import type { ApprovalStore } from "./approvals.js";
import type { CredentialStore } from "./credential_store.js";
import type { MissionStore } from "./missions.js";
import { isKilled } from "./kill_switch.js";
import { classifyAction } from "./irreversible.js";

// The single chokepoint every tool call passes through: check -> (deny: audit + return, actor
// NEVER called) | (allow: execute -> consume -> audit). Nothing in mcp_server.ts is allowed to
// call the actor or the bridge directly - it must go through RunManager so a denied action is
// structurally incapable of reaching the live browser, and every attempted action (allow or deny)
// produces exactly one audit record.

export interface ActorLike {
  navigate(url: string): Promise<unknown>;
  click(el: { name?: string; role?: string }): Promise<{ ok: boolean; verified?: boolean }>;
  type(text: string, el: { name?: string; role?: string }): Promise<{ ok: boolean; verified?: boolean }>;
  scroll(direction: "up" | "down" | "left" | "right", amount?: number): Promise<unknown>;
  // Phase 3: native-autofill fill (src/actor.ts). Boolean-only result surface - never a value.
  credentialFill(el: { name?: string; role?: string }): Promise<{ ok: boolean; filled: boolean }>;
  // Phase 5 Task 26: click a named submit control, or press Enter in the focused field when no
  // element is given. Only reachable via dispatchAct's SUBMIT case, which only runs after the
  // ordinary policy guard (actions_allow) has already allowed SUBMIT for this run.
  submit(el?: { name?: string; role?: string }): Promise<{ ok: boolean; verified?: boolean }>;
  // Task 38 (Phase 6): ask Comet's Perplexity Assistant sidebar - see src/actor.ts's
  // CometActor.assistantAsk. Optional so every existing ActorLike implementation/fake (which
  // never needed this) keeps compiling; RunManager.assistantAsk throws a clear, fail-closed error
  // if an actor wired without this is asked to ask - it deliberately never falls back to the raw
  // ask_perplexity/CometDriver path, which is NOT run/policy-scoped and would bypass every gate.
  assistantAsk?(query: string, timeoutMs?: number): Promise<{ answer: string }>;
}

export interface BridgeReader {
  read(payload?: Record<string, unknown>): Promise<unknown>;
  // Optional extension-driven navigation (chrome.tabs.update). Consumed by CometActor, not by
  // RunManager itself - declared here because index.ts builds ONE object for both.
  navigate?(url: string, timeoutMs?: number): Promise<{ url?: string; error?: string }>;
  // Task 37 (Phase 6): dispatches a `kind:"inspect"` bridge job (see Task 36's relay/background.js
  // routing) instead of `read`. Optional so every existing BridgeReader implementation/fake -
  // which only ever needed `read` - keeps compiling unchanged; RunManager.inspect() throws a
  // clear, fail-closed error if a bridge wired without this is asked to inspect. It deliberately
  // never falls back to `read`, which returns already-shaped page state, not a redacted
  // DevTools-equivalent inspection payload.
  inspect?(payload?: Record<string, unknown>): Promise<unknown>;
}

export interface AuditSink {
  append(rec: AuditRecord): void;
}

// CLICK/TYPE/SCROLL/SUBMIT are the action kinds dispatchAct actually implements, reachable via
// the generic act() path once the ordinary policy guard (actions_allow + budgets + domain) has
// allowed them for the run - SUBMIT included, since Phase 5 Task 26 removed it from
// policy.DANGEROUS. CREDENTIAL_FILL/CREDENTIAL_USE/CREDENTIAL_REVEAL are listed here ONLY so the
// "never reachable via act()" invariant is unit-testable end-to-end: act()'s own explicit guards
// below refuse all three before policy.check is even consulted, and no MCP tool schema exposes
// any of the three as a valid `comet_act` input either, so this union is the innermost of two
// independent walls for those three, not the only one.
export type ActKind = "CLICK" | "TYPE" | "SCROLL" | "SUBMIT" | "CREDENTIAL_FILL" | "CREDENTIAL_USE" | "CREDENTIAL_REVEAL";

export interface ActRequest {
  kind: ActKind;
  // Explicit | undefined (not just ?:) so zod's inferred .optional() output types - which
  // include undefined explicitly - are assignable here under exactOptionalPropertyTypes.
  name?: string | undefined;
  role?: string | undefined;
  text?: string | undefined;
  direction?: ("up" | "down" | "left" | "right") | undefined;
  amount?: number | undefined;
}

// Task 32 (Phase 4): scoping params for the quarantined 2FA read - passed through to BOTH the
// bridge read payload and the extractor field description, never used to construct an action or
// a navigation target themselves (see read2FA).
export interface Read2FAOptions {
  from?: string | undefined;
  subject_contains?: string | undefined;
  within_ms?: number | undefined;
}

export interface ActionResult {
  ok: boolean;
  reason?: string;
  result?: unknown;
  // Task 31 (Phase 4): set only when an unattended run's action was classified as
  // irreversible-shaped and NOT pre-authorised by the mission - the run PAUSES (stays alive) but
  // this specific attempt did not execute; see RunManager.classifyIrreversible.
  blocked?: boolean;
  needs_approval?: string;
}

export type RunStatus = PolicyState & { policy: Policy };

// Task 34 (Phase 4): the mission-aware status view for comet_mission_status - distinct from the
// plain comet_status/RunStatus above, which knows nothing about missions/kill/tripwire state.
// Purely a read: unlike checkKillSwitch, this never latches run.killed - it just reports what a
// LIVE check of the global KILL file would say right now, so a human/orchestrator polling this
// tool sees an accurate picture even for a run that has not attempted an action since the kill
// file appeared (see the `killed` field below).
export interface MissionStatusResult {
  unattended: boolean;
  mission_id?: string;
  account?: string;
  killed: boolean;
  consecutive_denials: number;
  preauthorized_irreversible: string[];
  actions_used: number;
  max_actions: number;
  domains_used: string[];
  max_domains: number;
  started_ms: number;
  max_ms: number;
}

type Now = () => number;

interface RunEntry {
  policy: Policy;
  state: PolicyState;
  // Set from the last successful navigate() only (per Phase 2 spec). Used as the destination
  // for the TYPE egress check; undefined means "no known page context yet".
  currentOrigin?: string | undefined;
  // Union of provenance seen by this run via read()/extract(), used as the egress gate's
  // provenance input for navigate()/act(TYPE) so untrusted data collected earlier in the run
  // can't be smuggled out via a later action.
  provenance: Provenance;
  // Task 30 (Phase 4): set only by beginMission(). Governs which Phase-4 controls (mission
  // budgets already flow through policy.budgets with no extra code; the tripwire below) apply -
  // an ordinary attended run started via begin() is never touched by any of them. The kill
  // switch (checkKillSwitch) is deliberately NOT gated on this flag - see THE RISK invariant 5 in
  // docs/plans/2026-08-14-comet-agent-phase4-unattended.md, "kill file checked before every
  // action" is written with no attended/unattended qualifier, and a narrower emergency stop would
  // be a foot-gun for the human trying to use it.
  unattended?: boolean;
  missionId?: string;
  missionAccount?: string | undefined;
  preauthorizedIrreversible?: string[];
  // Set once either the global kill file is observed or this run's own tripwire fires (3
  // consecutive denied actions on an unattended run). Once true, EVERY subsequent action on this
  // run is refused before it reaches policy.check, the actor, or the bridge - a killed run can
  // never un-kill itself, even if the KILL file is later removed.
  killed?: boolean;
  consecutiveDenials?: number;
}

// Generous enough that ordinary deep links and search URLs are unaffected, tight enough that a
// bulk dump into an allowlisted host's fragment is refused.
const DEFAULT_MAX_URL_PAYLOAD_CHARS = 200;

// Task 37 (Phase 6): threshold for comet_inspect's per-entry console/resources.name/cookies
// digesting - see shapeInspectResult's doc comment. Generous enough that ordinary short console
// lines, resource URLs, and cookie headers pass through inline; tight enough that a page-injected
// blob doesn't ride along as raw prose.
const MAX_INLINE_INSPECT_CHARS = 2000;

// Task 38 (Phase 6): comet_assistant_ask's quarantined excerpt bound - generous enough to show
// the gist of an answer, small enough that a connector/page-sourced injection riding along in the
// answer can't smuggle a large instruction-shaped block through as a "preview". Deliberately
// smaller than MAX_INLINE_INSPECT_CHARS: this is a bounded EXCERPT of a single answer by design
// (per the Task 38 spec), not an inline-unless-oversized field. The full answer is never returned
// under content_mode:"quarantined" - only an explicit "raw" run gets it directly.
const MAX_ASSISTANT_EXCERPT_CHARS = 500;

// "e.g. 3" per the Task 30 spec. 3 consecutive denied actions on an unattended run - not 3 total,
// not 3 of any kind - trips the tripwire; a single allowed action in between resets the streak.
const TRIPWIRE_THRESHOLD = 3;

// Task 32 (Phase 4): generous default recency window for a 2FA email when the caller does not
// give one - 10 minutes covers ordinary send/read latency without leaving a long-lived window an
// old, already-used code could be replayed from.
const DEFAULT_2FA_WINDOW_MS = 600_000;

// Task 32: the field prompt handed to the quarantined extractor - a FIXED single field so the
// only thing that can ever come back out is a typed "code" string (see src/quarantine.ts's
// key-restriction wall). The sender/subject/window are folded into the description text (and,
// separately, into the bridge read payload below) so the extraction is actually SCOPED to what
// the caller asked for, not "the most recent code anywhere in the inbox".
function twoFAFieldDescription(opts: Read2FAOptions): string {
  const from = opts.from ? ` from ${opts.from}` : "";
  const subject = opts.subject_contains ? ` with subject containing "${opts.subject_contains}"` : "";
  const windowMs = opts.within_ms ?? DEFAULT_2FA_WINDOW_MS;
  return `the one-time numeric verification/2FA code from the most recent message${from}${subject} within the last ${windowMs}ms; digits only; empty if none`;
}

// Audit target for READ_2FA: the sender/subject/window scoping, NEVER the code (the code does
// not exist yet when this is built - see read2FA's call order).
function twoFATarget(opts: Read2FAOptions): string {
  return `from=${opts.from ?? "any"} subject=${opts.subject_contains ?? "any"} within_ms=${opts.within_ms ?? DEFAULT_2FA_WINDOW_MS}`;
}

type Decision = { allowed: boolean; reason?: string | undefined };

// Task 32: "the run's current page origin must already be inside domains_allow" - the same
// matching rule policy.check() uses for a NAVIGATE url (exact host or subdomain), reused here via
// policy.ts's exported hostMatches since READ_2FA carries no url of its own for check() to
// validate. No known origin yet (undefined) is treated as out of scope - fail closed, never
// pass-through. A standalone exported function (not a RunManager method) so it can be unit-tested
// directly with origin/domains_allow combinations that read2FA's real call path can never
// currently construct - see read2FA's doc comment for why that direct coverage matters: a
// mutation to the `.some(...)` line below is caught by tests/twofa_extract.test.ts's direct unit
// tests even though RunManager.read2FA itself can never exercise a differentiating input today.
export function originInDomainsAllow(origin: string | undefined, domainsAllow: string[]): boolean {
  if (!origin) return false;
  return domainsAllow.some(d => hostMatches(origin, d));
}

function actionRequest(kind: ActionKind, url?: string): ActionRequest {
  return url === undefined ? { kind } : { kind, url };
}

function denied(reason?: string): ActionResult {
  return reason === undefined ? { ok: false } : { ok: false, reason };
}

let runCounter = 0;

// Fail-closed default for callers (older tests, ad-hoc construction) that do not pass a real
// approval store: finds nothing, consumes nothing. checkCredentialFill's gate 3 then denies with
// "no valid approval" exactly as it would for any other unreadable/absent approval store - never
// allow on a "probably fine" just because a store was not wired up.
const NO_APPROVALS: ApprovalStore = { find: () => null, consume: () => false };

export class RunManager {
  private runs = new Map<string, RunEntry>();

  constructor(
    private actor: ActorLike,
    private bridge: BridgeReader,
    private audit: AuditSink,
    private quarantine?: QuarantineClient,
    private now: Now = () => Date.now(),
    private store: ApprovalStore = NO_APPROVALS,
    // Phase 5 Task 24: the plaintext vault reader. Optional (older tests/construction sites keep
    // compiling); credentialUse fails closed ("no stored credential for site") when it is absent,
    // the same fail-closed posture NO_APPROVALS gives an unwired approval store.
    private credentialStore?: CredentialStore,
    // Task 30 (Phase 4): the signed mission grant store. Optional (older tests/construction sites
    // keep compiling); beginMission fails closed ("unattended missions not configured") when it
    // is absent - same posture as an unwired approval/credential store.
    private missionStore?: MissionStore,
    // Task 30: root dir for the global kill file (`<dataDir>/KILL`, see src/kill_switch.ts).
    // Optional; when absent the kill switch is simply inert (matches every pre-Task-30 test's
    // construction, which never wires this in), never fails open on anything else.
    private dataDir?: string
  ) {}

  begin(policy: Policy): { run_id: string } {
    const run_id = `run_${++runCounter}`;
    this.runs.set(run_id, {
      policy,
      state: newState(this.now()),
      provenance: { origins: [], trust: "trusted" }
    });
    return { run_id };
  }

  // Task 30: the ONLY way to start an unattended run - see THE RISK invariant 1 in
  // docs/plans/2026-08-14-comet-agent-phase4-unattended.md, "no unattended run may start without
  // a [...] grant". The mission is loaded (deny if none/expired/used/tampered - fileMissionStore
  // already fails closed to null on every one of those), then IMMEDIATELY consumed (single-use,
  // so a crashed/killed run can never be resumed on the same grant) before any run exists. Only
  // then is the run's policy built FROM the mission's scope + budgets - the agent never sees, and
  // cannot influence, that construction; it is exactly what the human signed.
  beginMission(missionId: string): { run_id: string } | { error: string } {
    if (this.dataDir !== undefined && isKilled(this.dataDir)) {
      return { error: "kill switch engaged" };
    }
    if (!this.missionStore) return { error: "unattended missions not configured" };

    const nowMs = this.now();
    const mission = this.missionStore.find(missionId, nowMs);
    if (!mission) return { error: "no valid mission grant" };
    if (!this.missionStore.consume(missionId, nowMs)) return { error: "mission grant could not be consumed" };

    const policy: Policy = {
      domains_allow: mission.scope.domains_allow,
      // Cast is safe: grantMission is the human/CLI-only path (Task 34); an unrecognised string
      // here just never matches any real ActionKind in policy.check's actions_allow.includes()
      // check, so it can only ever narrow, never widen, what the run can do.
      actions_allow: mission.scope.actions_allow as ActionKind[],
      budgets: mission.budgets,
      credential_sites: mission.scope.credential_sites,
      ...(mission.scope.allow_credential_reveal !== undefined
        ? { allow_credential_reveal: mission.scope.allow_credential_reveal }
        : {})
    };

    const run_id = `run_${++runCounter}`;
    this.runs.set(run_id, {
      policy,
      state: newState(nowMs),
      provenance: { origins: [], trust: "trusted" },
      unattended: true,
      missionId: mission.id,
      missionAccount: mission.scope.account,
      preauthorizedIrreversible: mission.preauthorized_irreversible,
      consecutiveDenials: 0
    });

    this.audit.append({
      ts: nowMs, run_id, actor: "agent", action: "BEGIN_MISSION",
      target: mission.id, policy_decision: "allow",
      ...(mission.scope.account !== undefined ? { reason: `account=${mission.scope.account}` } : {})
    });

    return { run_id };
  }

  status(run_id: string): RunStatus | null {
    const run = this.runs.get(run_id);
    return run ? { ...run.state, policy: run.policy } : null;
  }

  // Task 34 (Phase 4): see MissionStatusResult's doc comment above. `killed` is evaluated live
  // (run.killed OR a fresh isKilled(dataDir) check), same condition checkKillSwitch uses, but this
  // method never mutates run.killed itself - a status poll must stay a pure read, the actual
  // latching only happens on the next real action via checkKillSwitch.
  missionStatus(run_id: string): MissionStatusResult | null {
    const run = this.runs.get(run_id);
    if (!run) return null;
    const killed = run.killed === true || (this.dataDir !== undefined && isKilled(this.dataDir));
    return {
      unattended: run.unattended === true,
      ...(run.missionId !== undefined ? { mission_id: run.missionId } : {}),
      ...(run.missionAccount !== undefined ? { account: run.missionAccount } : {}),
      killed,
      consecutive_denials: run.consecutiveDenials ?? 0,
      preauthorized_irreversible: run.preauthorizedIrreversible ?? [],
      actions_used: run.state.actions_used,
      max_actions: run.policy.budgets.max_actions,
      domains_used: run.state.domains_used,
      max_domains: run.policy.budgets.max_domains,
      started_ms: run.state.started_ms,
      max_ms: run.policy.budgets.max_ms
    };
  }

  async navigate(run_id: string, url: string): Promise<ActionResult> {
    const killed = this.checkKillSwitch(run_id, "NAVIGATE", url);
    if (killed) return killed;

    const { run, decision: policyDecision } = this.guard(run_id, "NAVIGATE", url);
    const decision = this.applyNavigateEgress(run, url, policyDecision);
    this.record(run_id, "NAVIGATE", decision, url);
    if (!decision.allowed) return denied(decision.reason);

    const outcome = (await this.actor.navigate(url)) as { ok?: boolean; reason?: string } | undefined;

    // The actor verifies the browser actually LANDED on the requested host. If it did not, the
    // policy decision (which authorised THIS url) no longer describes where the browser actually
    // is, so fail loudly and audit the outcome instead of letting the caller assume success.
    if (outcome && outcome.ok === false) {
      this.audit.append({
        ts: this.now(), run_id, actor: "agent", action: "NAVIGATE",
        target: url, policy_decision: "error",
        ...(outcome.reason !== undefined ? { reason: outcome.reason } : {})
      });
      return denied(outcome.reason);
    }

    let host: string | undefined;
    try { host = new URL(url).hostname.toLowerCase(); } catch { host = undefined; }
    run.state = consume(run.state, actionRequest("NAVIGATE", url), host);
    run.currentOrigin = host;
    return { ok: true };
  }

  async read(run_id: string, target?: string): Promise<ActionResult> {
    const killed = this.checkKillSwitch(run_id, "READ", target);
    if (killed) return killed;

    const { run, decision } = this.guard(run_id, "READ");
    this.record(run_id, "READ", decision, target);
    if (!decision.allowed) return denied(decision.reason);

    const payload = target !== undefined ? { target } : undefined;
    const raw = await this.bridge.read(payload);
    run.state = consume(run.state, actionRequest("READ"), undefined);

    const result = this.shapeReadResult(run, raw);
    return { ok: true, result };
  }

  async act(run_id: string, req: ActRequest): Promise<ActionResult> {
    const target = req.kind === "SCROLL" ? req.direction : req.name;
    const killed = this.checkKillSwitch(run_id, req.kind, target);
    if (killed) return killed;

    // CREDENTIAL_FILL/CREDENTIAL_USE/CREDENTIAL_REVEAL are NOT `act` kinds. None is in
    // policy.DANGEROUS, so a policy that lists one in actions_allow would otherwise sail through
    // the generic path - skipping all the credential gates, writing a FALSE "allow" audit record,
    // and only then dying in dispatchAct's default case. Refuse them here so the dedicated gated
    // methods (credentialFill / credentialUse / credentialReveal) are the ONLY route, the audit
    // trail records an honest deny, and adding a dispatchAct case later cannot silently open a
    // bypass. SUBMIT is deliberately NOT refused here (Phase 5 Task 26): it no longer needs a
    // dedicated gate, only the ordinary policy guard right below (actions_allow + budgets +
    // domain), so it is a real dispatchAct case now - denied whenever the run's policy does not
    // list it, reachable only then.
    if (req.kind === "CREDENTIAL_FILL") {
      const decision = { allowed: false, reason: "CREDENTIAL_FILL must use the gated credential-fill path, not act()" };
      this.record(run_id, "CREDENTIAL_FILL", decision, target);
      return denied(decision.reason);
    }
    if (req.kind === "CREDENTIAL_USE") {
      const decision = { allowed: false, reason: "CREDENTIAL_USE must use the gated credential-use path, not act()" };
      this.record(run_id, "CREDENTIAL_USE", decision, target);
      return denied(decision.reason);
    }
    if (req.kind === "CREDENTIAL_REVEAL") {
      const decision = { allowed: false, reason: "CREDENTIAL_REVEAL must use the gated credential-reveal path, not act()" };
      this.record(run_id, "CREDENTIAL_REVEAL", decision, target);
      return denied(decision.reason);
    }

    const { run, decision: policyDecision } = this.guard(run_id, req.kind);
    const decision = this.applyActEgress(run, req, policyDecision);

    if (!decision.allowed) {
      this.record(run_id, req.kind, decision, target);
      return denied(decision.reason);
    }

    // Task 31 (Phase 4): irreversible-action gate, unattended runs only. Runs after policy+egress
    // already allowed this action but strictly before dispatchAct ever reaches the live actor -
    // see THE RISK invariant 4 in docs/plans/2026-08-14-comet-agent-phase4-unattended.md.
    const irr = this.classifyIrreversible(run, req.kind, target);
    if (!irr.proceed) {
      this.recordBlockedPendingApproval(run_id, req.kind, irr.tag, target);
      return { ok: false, blocked: true, needs_approval: irr.tag };
    }
    this.record(run_id, req.kind, irr.reason !== undefined ? { allowed: true, reason: irr.reason } : decision, target);

    const result = await this.dispatchAct(req);
    run.state = consume(run.state, actionRequest(req.kind), undefined);
    return { ok: true, result };
  }

  // Consumes budget as EXTRACT. Always reads RAW content from the bridge regardless of the
  // run's content_mode - content_mode only governs what comet_read hands back to the caller;
  // comet_extract's whole purpose is to be the ONLY path raw untrusted content may travel, and
  // it never leaves this method except as validated, typed fields (see src/quarantine.ts).
  async extract(run_id: string, fields: ExtractField[]): Promise<ActionResult> {
    const killed = this.checkKillSwitch(run_id, "EXTRACT", fields.map(f => f.name).join(","));
    if (killed) return killed;

    const { run, decision } = this.guard(run_id, "EXTRACT");
    this.record(run_id, "EXTRACT", decision, fields.map(f => f.name).join(","));
    if (!decision.allowed) return denied(decision.reason);

    if (!this.quarantine) throw new Error("comet_extract requires a configured quarantine client");

    const raw = await this.bridge.read(undefined);
    const obj = raw !== null && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
    const pageProvenance = this.pageProvenanceOf(obj);
    run.provenance = mergeProvenance(run.provenance, pageProvenance);

    const content = typeof obj.content === "string" ? obj.content : "";
    const extracted = await extractQuarantined(this.quarantine, content, fields);

    run.state = consume(run.state, actionRequest("EXTRACT"), undefined);
    return { ok: true, result: { fields: extracted, provenance: pageProvenance } };
  }

  // Task 32 (Phase 4): the quarantined one-time-code extraction chokepoint - see THE RISK
  // invariant 3 in docs/plans/2026-08-14-comet-agent-phase4-unattended.md: "the email/2FA read
  // is quarantined... the email body never reaches the planner as instructions." Reuses Phase
  // 2's extractQuarantined (src/quarantine.ts) with a FIXED single field ("code"), the same hard
  // wall EXTRACT relies on, so the only thing that can ever leave this method is a typed
  // numeric-code string - never raw inbox prose, never an extra key. Gated on the ordinary policy
  // guard (READ_2FA must be listed in actions_allow, same as every other kind, and checked before
  // the kill switch too - see checkKillSwitch at the top) PLUS an explicit check that the run's
  // CURRENT page origin (the email inbox, set only by a prior successful navigate) is itself
  // inside domains_allow - "the email origin is in the mission scope" per the Task 32 spec, via
  // the exported originInDomainsAllow() below (the same hostMatches predicate navigate()'s own
  // domain gate uses). Under today's invariants currentOrigin can only ever already be inside
  // domains_allow by the time read2FA runs (it is set nowhere except navigate(), which is gated
  // by that identical predicate over that identical list), so on the real call path this second
  // check cannot currently deny anything the first check would not already have prevented by
  // refusing the navigate itself - it is forward-looking defense in depth against a future code
  // path that sets currentOrigin some other way (a bridge-reported URL, session resume, multi-tab
  // tracking), not two checks that diverge on live traffic today. originInDomainsAllow is exported
  // and directly unit-tested (tests/twofa_extract.test.ts) with origin/domains_allow combinations
  // the real call path cannot yet construct, so the predicate's own logic - not merely "is it
  // called" - is mutation-covered even though RunManager.read2FA itself can never exercise a
  // differentiating input under current invariants. Exactly one audit record is written, BEFORE
  // extraction runs, so a code can never leak into it even by accident - only the sender/subject/
  // window scoping is recorded, never the code (see twoFATarget above).
  async read2FA(run_id: string, opts: Read2FAOptions = {}): Promise<ActionResult> {
    const target = twoFATarget(opts);
    const killed = this.checkKillSwitch(run_id, "READ_2FA", target);
    if (killed) return killed;

    const { run, decision: policyDecision } = this.guard(run_id, "READ_2FA");
    const decision = policyDecision.allowed && !originInDomainsAllow(run.currentOrigin, run.policy.domains_allow)
      ? { allowed: false, reason: "email origin not in mission scope" }
      : policyDecision;
    this.record(run_id, "READ_2FA", decision, target);
    if (!decision.allowed) return denied(decision.reason);

    if (!this.quarantine) throw new Error("comet_read_2fa requires a configured quarantine client");

    const payload = { from: opts.from, subject_contains: opts.subject_contains, within_ms: opts.within_ms };
    const raw = await this.bridge.read(payload);
    const obj = raw !== null && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
    run.provenance = mergeProvenance(run.provenance, this.pageProvenanceOf(obj));
    const content = typeof obj.content === "string" ? obj.content : "";

    const fields: ExtractField[] = [{ name: "code", description: twoFAFieldDescription(opts) }];
    const extracted = await extractQuarantined(this.quarantine, content, fields);

    run.state = consume(run.state, actionRequest("READ_2FA"), undefined);
    return { ok: true, result: { code: extracted.code ?? "" } };
  }

  // Task 37 (Phase 6): the comet_inspect chokepoint - DevTools-equivalent page inspection routed
  // through the extension, never CDP (THE RISK rule 5 in
  // docs/plans/2026-08-14-comet-agent-phase6-inspect-assistant.md - a debug port would make the
  // whole browser detectable, which the user explicitly rejected). Secret redaction happens in
  // the EXTENSION at the browser boundary, before this method ever sees the result - this method
  // never re-redacts; its job is purely gating (ordinary policy + the two narrower opt-ins below)
  // and content_mode shaping of whatever the extension already redacted. `cookies` and
  // `unredacted` are each a SEPARATE, explicit per-call request that requires its own Policy
  // opt-in - neither is implied by listing "cookies" in `kinds`, by the other flag, or by INSPECT
  // merely being in actions_allow (THE RISK rules 1-2). Exactly one audit record is written for
  // the policy decision (kinds only, never payload content - THE RISK invariant "no payload
  // content"), matching every other gated method in this file; a second, distinct "error" record
  // is written only if the extension itself could not evaluate the request (fail-closed - THE
  // RISK rule 6), mirroring navigate()'s actor-outcome-verification pattern.
  async inspect(run_id: string, opts: { kinds: string[]; name?: string; cookies?: boolean; unredacted?: boolean }): Promise<ActionResult> {
    const target = opts.kinds.join(",");
    const killed = this.checkKillSwitch(run_id, "INSPECT", target);
    if (killed) return killed;

    const { run, decision: policyDecision } = this.guard(run_id, "INSPECT");
    if (!policyDecision.allowed) {
      this.record(run_id, "INSPECT", policyDecision, target);
      return denied(policyDecision.reason);
    }

    if (opts.cookies === true && run.policy.allow_cookie_inspection !== true) {
      const decision = { allowed: false, reason: "cookie inspection not enabled for this session" };
      this.record(run_id, "INSPECT", decision, target);
      return denied(decision.reason);
    }

    if (opts.unredacted === true && run.policy.allow_unredacted_inspect !== true) {
      const decision = { allowed: false, reason: "unredacted inspection not enabled for this session" };
      this.record(run_id, "INSPECT", decision, target);
      return denied(decision.reason);
    }

    // Every gate passed - audit the allowed attempt (kinds only, never payload content) BEFORE
    // dispatching to the bridge, same convention as read()/extract().
    this.record(run_id, "INSPECT", policyDecision, target);

    const inspectFn = this.bridge.inspect;
    if (!inspectFn) throw new Error("comet_inspect requires a bridge configured for inspect jobs");
    const payload: Record<string, unknown> = { kinds: opts.kinds };
    if (opts.name !== undefined) payload.name = opts.name;
    if (opts.cookies === true) payload.allowCookies = true;
    if (opts.unredacted === true) payload.noRedact = true;

    const raw = await inspectFn(payload);
    const obj = raw !== null && typeof raw === "object" ? (raw as Record<string, unknown>) : {};

    // Fail closed: an inspection request the extension could not evaluate (e.g. an unknown kind)
    // comes back as { error }, never partial/unredacted data.
    if (typeof obj.error === "string") {
      this.audit.append({
        ts: this.now(), run_id, actor: "agent", action: "INSPECT",
        target, policy_decision: "error", reason: obj.error
      });
      return denied(obj.error);
    }

    run.state = consume(run.state, actionRequest("INSPECT"), undefined);
    const result = this.shapeInspectResult(run, obj);
    return { ok: true, result };
  }

  // Task 38 (Phase 6): the comet_assistant_ask chokepoint - asks Comet's Perplexity Assistant
  // sidebar, so the user's enabled Perplexity connectors (GitHub etc.) are reachable from an agent
  // run. Gated like READ/EXTRACT/INSPECT (ordinary actions_allow guard only - no extra narrower
  // opt-in, since the QUERY is the agent's own text, not page content). The ANSWER, however, is
  // untrusted content synthesized from arbitrary web pages via those connectors - a prime
  // injection vector (THE RISK rule 4) - so it is handled exactly like inspect()/read()'s raw
  // content: merged into the run's provenance and, under the default content_mode:"quarantined",
  // never returned raw - only a digest plus a bounded, REDACTED excerpt (shapeAssistantResult).
  // Exactly one audit record is written, holding the QUERY and NEVER the answer, matching
  // read2FA's "scope, never content" convention - this method never reads err.message or any
  // answer-derived text into the audit log either.
  async assistantAsk(run_id: string, query: string, timeoutMs?: number): Promise<ActionResult> {
    const killed = this.checkKillSwitch(run_id, "ASSISTANT", query);
    if (killed) return killed;

    const { run, decision } = this.guard(run_id, "ASSISTANT");
    this.record(run_id, "ASSISTANT", decision, query);
    if (!decision.allowed) return denied(decision.reason);

    const assistantFn = this.actor.assistantAsk;
    if (!assistantFn) throw new Error("comet_assistant_ask requires an actor configured for the Assistant");

    const { answer } = await assistantFn.call(this.actor, query, timeoutMs);

    run.state = consume(run.state, actionRequest("ASSISTANT"), undefined);
    const result = this.shapeAssistantResult(run, answer);
    return { ok: true, result };
  }

  // Phase 3 Task 20: the CREDENTIAL_FILL chokepoint. Runs the normal policy guard first (kind is
  // no longer blanket-denied, per Task 18), then the four-gate decision in credential_gate.ts.
  // The actor is called ONLY after both pass. Exactly one audit record is written per attempt,
  // never a credential value: a deny records the reason, an allow records the site + approval id.
  // The human's approval is spent (store.consume) only when the browser confirms the fill by
  // shape (filled:true) - a policy-allowed attempt that the browser never actually completed does
  // not burn the single-use grant.
  async credentialFill(run_id: string, site: string, el: { name?: string; role?: string }): Promise<ActionResult> {
    const killedResult = this.checkKillSwitch(run_id, "CREDENTIAL_FILL", site);
    if (killedResult) return killedResult;

    const { run, decision: policyDecision } = this.guard(run_id, "CREDENTIAL_FILL");
    if (!policyDecision.allowed) {
      this.record(run_id, "CREDENTIAL_FILL", policyDecision, site);
      return denied(policyDecision.reason);
    }

    const credDecision = checkCredentialFill({
      policy: run.policy,
      site,
      currentOrigin: run.currentOrigin,
      store: this.store,
      nowMs: this.now()
    });
    if (!credDecision.allowed) {
      this.record(run_id, "CREDENTIAL_FILL", credDecision, site);
      return denied(credDecision.reason);
    }

    // Irreversible gate, unattended runs only - same posture as act(), credentialUse() and
    // credentialReveal(). This path was the last credential method missing it: autofilling a login
    // on a page that reads as a delete/transfer/password-change context deserves the same speed
    // bump as typing the password there manually. Checked BEFORE the approval is spent, so a
    // blocked fill costs the human's single-use grant nothing.
    const irr = this.classifyIrreversible(run, "CREDENTIAL_FILL", site);
    if (!irr.proceed) {
      this.recordBlockedPendingApproval(run_id, "CREDENTIAL_FILL", irr.tag, site);
      return { ok: false, blocked: true, needs_approval: irr.tag };
    }

    // In-scope attempt about to reach the actor - resets any prior out-of-scope denial streak on
    // an unattended run (no-op otherwise). See trackTripwire's doc comment.
    this.trackTripwire(run_id, true);

    // From here on both gates have passed and we are about to touch the live browser - the
    // single most dangerous action in the system. The actor call is wrapped in try/finally so
    // exactly one audit record is written for THIS attempt no matter what happens, including an
    // actor-level throw (ghost IPC failure, bridge timeout) after every gate already passed.
    // Without this, an attempt that cleared policy + origin binding + a real out-of-band
    // approval and actually reached the browser could vanish from the tamper-evident,
    // hash-chained audit log entirely if the actor call rejected instead of resolving.
    // Deliberately never reads err.message (or any other error-derived text) into the audit
    // record below: Ghost's real element-not-found failure echoes the requested locator string
    // verbatim ("Element not found: Name(\"...\")"), and el.name/el.role are attacker-influenceable
    // (a hostile page can plant an accessible name on/near the password field that the agent then
    // passes straight into credentialFill). Letting err.message flow into the signed,
    // tamper-evident audit log would reopen exactly the "raw page content into a privileged
    // system" hole Phase 2 quarantine exists to close. A plain try/finally (no catch) still
    // guarantees exactly one audit record per attempt - including a throw - because finally
    // always runs before the exception propagates; there is nothing left to sanitize because
    // nothing error-derived is ever read.
    let fillResult: { ok: boolean; filled: boolean } | undefined;
    try {
      fillResult = await this.actor.credentialFill(el);
      if (fillResult.ok && fillResult.filled && credDecision.approvalId !== undefined) {
        this.store.consume(credDecision.approvalId, this.now());
      }
      run.state = consume(run.state, actionRequest("CREDENTIAL_FILL"), undefined);
      return { ok: fillResult.ok, result: { filled: fillResult.filled } };
    } finally {
      this.audit.append({
        ts: this.now(), run_id, actor: "agent", action: "CREDENTIAL_FILL",
        target: site, policy_decision: fillResult ? "allow" : "error",
        reason: fillResult
          ? `approval=${credDecision.approvalId ?? "unknown"} filled=${fillResult.filled}`
          : `approval=${credDecision.approvalId ?? "unknown"} error=actor error`
      });
    }
  }

  // Phase 5 Task 24: the CREDENTIAL_USE chokepoint - "parity with the human, even off the saved
  // origin". Unlike credentialFill (Phase 3), which never lets a value leave the browser's own
  // autofill, this DIRECTLY types the real decrypted password via actor.type - that is the point
  // at which a decrypted secret first transits the MCP process; see THE RISK in
  // docs/plans/2026-08-13-comet-agent-phase5.md. Runs the normal policy guard first (the kind is
  // opt-in per session, same as CREDENTIAL_FILL), then reuses checkCredentialFill's gates 1-3
  // with a DISTINCT approval action (CREDENTIAL_USE) so a fill/reveal approval can never satisfy
  // a use. A fifth gate - the vault actually holding a credential for `site` - runs only AFTER
  // those pass, with a fixed present/absent-only reason, so an unapproved caller learns nothing
  // about which sites have a saved login. On allow, the plaintext exists only across the single
  // actor.type() call below; the result and every audit record carry a boolean only, never the
  // value.
  // `username` (2026-08-15): a real vault can hold SEVERAL logins for one origin (live:
  // accounts.google.com holds 3) and the store fails closed on that ambiguity by design, which
  // made a multi-account site structurally unusable through this tool. The exact saved username
  // is the disambiguator. It adds no privilege - every gate below still applies, it only selects
  // WHICH already-authorised row gate 5 reads - and it is folded into the audit target so the
  // record says which account a run authenticated as (the username is caller input and account
  // identity, never vault-derived data).
  async credentialUse(run_id: string, site: string, el: { name?: string; role?: string }, username?: string): Promise<ActionResult> {
    const target = username === undefined ? site : `${site} user=${username}`;
    const killedResult = this.checkKillSwitch(run_id, "CREDENTIAL_USE", target);
    if (killedResult) return killedResult;

    const { run, decision: policyDecision } = this.guard(run_id, "CREDENTIAL_USE");
    if (!policyDecision.allowed) {
      this.record(run_id, "CREDENTIAL_USE", policyDecision, target);
      return denied(policyDecision.reason);
    }

    const credDecision = checkCredentialFill({
      policy: run.policy,
      site,
      currentOrigin: run.currentOrigin,
      store: this.store,
      nowMs: this.now(),
      action: "CREDENTIAL_USE"
    });
    if (!credDecision.allowed) {
      this.record(run_id, "CREDENTIAL_USE", credDecision, target);
      return denied(credDecision.reason);
    }

    // Gate 5 (use-only): the vault must actually hold a credential for `site` (matching
    // `username`, when given). Same fixed reason whether the store is unwired, the site has no
    // row, the username matches no row, ambiguity forced a null, or decryption failed - never
    // distinguish those, so this gate cannot be used to enumerate which sites have a saved login
    // or which usernames exist. Only a caller who already cleared policy + site pre-auth + origin
    // binding + a real approval can even reach this check.
    const credential = this.credentialStore ? this.credentialStore.read(site, username) : null;
    if (!credential) {
      const decision = { allowed: false, reason: "no stored credential for site" };
      this.record(run_id, "CREDENTIAL_USE", decision, target);
      return denied(decision.reason);
    }

    // Task 31 (Phase 4): irreversible-action gate, unattended runs only - same posture as act().
    // Placed after every other gate has passed but before trackTripwire/the actor call, so a
    // blocked attempt never reaches the live browser and never spends anything (the approval
    // consumed further below never runs on this path).
    const irr = this.classifyIrreversible(run, "CREDENTIAL_USE", el.name ?? el.role);
    if (!irr.proceed) {
      this.recordBlockedPendingApproval(run_id, "CREDENTIAL_USE", irr.tag, target);
      return { ok: false, blocked: true, needs_approval: irr.tag };
    }

    // In-scope attempt about to reach the actor - resets any prior out-of-scope denial streak on
    // an unattended run (no-op otherwise). See trackTripwire's doc comment.
    this.trackTripwire(run_id, true);

    // Unlike credentialFill's actor call (el.name/el.role only - never a secret), this call's
    // FIRST argument is the real decrypted password. credentialFill can safely let an actor-level
    // throw propagate unmodified to the caller because nothing it passed the actor was ever a
    // secret; here that is no longer true - a real `type` implementation that fails on the
    // password field (disabled/readonly/validation-constrained input) could echo the value it was
    // asked to type into its error text, exactly like Ghost's already-observed locator-echoing
    // failures ("Element not found: Name(\"...\")"). So this is the one actor call in the file
    // that must be wrapped in try/catch/finally, not try/finally: the finally block still writes
    // exactly one audit record per attempt (and, as always, never reads err.message or any other
    // error-derived text into it), but the catch block ALSO ensures nothing error-derived - which
    // could contain the plaintext password - ever leaves this function. On an actor-level throw we
    // resolve to a fixed, sanitized denial instead of rethrowing the original error.
    let typeResult: { ok: boolean; verified?: boolean } | undefined;
    try {
      try {
        typeResult = await this.actor.type(credential.password, el);
      } catch {
        return denied("credential use failed");
      }
      if (typeResult.ok && credDecision.approvalId !== undefined) {
        this.store.consume(credDecision.approvalId, this.now());
      }
      run.state = consume(run.state, actionRequest("CREDENTIAL_USE"), undefined);
      return { ok: typeResult.ok, result: { used: typeResult.ok } };
    } finally {
      this.audit.append({
        ts: this.now(), run_id, actor: "agent", action: "CREDENTIAL_USE",
        target, policy_decision: typeResult ? "allow" : "error",
        reason: typeResult
          ? `approval=${credDecision.approvalId ?? "unknown"} used=${typeResult.ok}${irr.reason !== undefined ? ` ${irr.reason}` : ""}`
          : `approval=${credDecision.approvalId ?? "unknown"} error=actor error`
      });
    }
  }

  // Phase 5 Task 25: the CREDENTIAL_REVEAL chokepoint - the single most dangerous op in the
  // system, because unlike credentialFill/credentialUse it hands plaintext BACK TO THE CALLER,
  // not just into the live browser. Requires everything credentialUse requires PLUS an explicit,
  // separate policy opt-in (`allow_credential_reveal === true`, checked before any gate runs -
  // see THE RISK invariant 1 in docs/plans/2026-08-13-comet-agent-phase5.md) PLUS a DISTINCT
  // approval action (CREDENTIAL_REVEAL), so neither a fill nor a use approval can ever satisfy a
  // reveal. Every deny path here is fail-closed with a fixed reason; the one allow path writes a
  // single audit record containing site + approvalId and NEVER the credential value, then returns
  // the value ONLY in the method's own return - never anywhere else.
  async credentialReveal(run_id: string, site: string): Promise<ActionResult> {
    const killedResult = this.checkKillSwitch(run_id, "CREDENTIAL_REVEAL", site);
    if (killedResult) return killedResult;

    const { run, decision: policyDecision } = this.guard(run_id, "CREDENTIAL_REVEAL");
    if (!policyDecision.allowed) {
      this.record(run_id, "CREDENTIAL_REVEAL", policyDecision, site);
      return denied(policyDecision.reason);
    }

    // The extra, reveal-specific opt-in. Checked before any of the four shared gates so a session
    // that never set this cannot even learn whether the OTHER gates would have passed.
    if (run.policy.allow_credential_reveal !== true) {
      const decision = { allowed: false, reason: "credential reveal not enabled for this session" };
      this.record(run_id, "CREDENTIAL_REVEAL", decision, site);
      return denied(decision.reason);
    }

    const credDecision = checkCredentialFill({
      policy: run.policy,
      site,
      currentOrigin: run.currentOrigin,
      store: this.store,
      nowMs: this.now(),
      action: "CREDENTIAL_REVEAL"
    });
    if (!credDecision.allowed) {
      this.record(run_id, "CREDENTIAL_REVEAL", credDecision, site);
      return denied(credDecision.reason);
    }

    // Same fixed present/absent-only reason as credentialUse's gate 5 - never distinguish an
    // unwired store from an empty vault from a decrypt failure, so this gate cannot be used to
    // enumerate which sites have a saved login. Only a caller who already cleared policy +
    // allow_credential_reveal + site pre-auth + origin binding + a real CREDENTIAL_REVEAL
    // approval can even reach this check.
    const credential = this.credentialStore ? this.credentialStore.read(site) : null;
    if (!credential) {
      const decision = { allowed: false, reason: "no stored credential for site" };
      this.record(run_id, "CREDENTIAL_REVEAL", decision, site);
      return denied(decision.reason);
    }

    // Task 31 (Phase 4): the irreversible gate, unattended runs only - same posture as act() and
    // credentialUse(). Originally omitted here because the Task 31 spec listed only the
    // act/credentialUse/submit paths, but handing plaintext to an autonomous agent while the page
    // looks like a delete/transfer/password-change context is exactly the moment that deserves the
    // speed bump. Checked BEFORE the approval is spent, so a blocked reveal costs the human
    // nothing and no credential is returned.
    const irr = this.classifyIrreversible(run, "CREDENTIAL_REVEAL", site);
    if (!irr.proceed) {
      this.recordBlockedPendingApproval(run_id, "CREDENTIAL_REVEAL", irr.tag, site);
      return { ok: false, blocked: true, needs_approval: irr.tag };
    }

    // In-scope attempt about to reveal - resets any prior out-of-scope denial streak on an
    // unattended run (no-op otherwise). See trackTripwire's doc comment.
    this.trackTripwire(run_id, true);

    // Every gate passed. Spend the single-use approval, consume the run's action budget, and
    // write the ONE audit record for this attempt - site + approvalId, never the value - before
    // returning the credential to the caller. Wrapped in try/finally (same reasoning as
    // credentialFill/credentialUse) so the audit trail cannot silently lose this attempt if
    // store.consume() itself throws (e.g. a disk I/O failure) after every gate already passed -
    // there is no actor call here to echo the value into a thrown error, so unlike credentialUse
    // this needs no catch, only the finally, purely for audit completeness.
    try {
      if (credDecision.approvalId !== undefined) {
        this.store.consume(credDecision.approvalId, this.now());
      }
      run.state = consume(run.state, actionRequest("CREDENTIAL_REVEAL"), undefined);
      return { ok: true, result: { credential } };
    } finally {
      this.audit.append({
        ts: this.now(), run_id, actor: "agent", action: "CREDENTIAL_REVEAL",
        target: site, policy_decision: "allow",
        reason: `approval=${credDecision.approvalId ?? "unknown"}`
      });
    }
  }

  private async dispatchAct(req: ActRequest): Promise<unknown> {
    switch (req.kind) {
      case "CLICK": {
        const el: { name?: string; role?: string } = {};
        if (req.name !== undefined) el.name = req.name;
        if (req.role !== undefined) el.role = req.role;
        return this.actor.click(el);
      }
      case "TYPE": {
        if (req.text === undefined) throw new Error("act TYPE requires text");
        const el: { name?: string; role?: string } = {};
        if (req.name !== undefined) el.name = req.name;
        if (req.role !== undefined) el.role = req.role;
        return this.actor.type(req.text, el);
      }
      case "SCROLL": {
        const direction = req.direction ?? "down";
        return req.amount !== undefined ? this.actor.scroll(direction, req.amount) : this.actor.scroll(direction);
      }
      case "SUBMIT": {
        // No name/role given -> submit() with no argument, which presses Enter in whatever field
        // already has focus, matching CometActor.submit's contract. Otherwise click the named
        // submit control, same el-building pattern as CLICK/TYPE above.
        if (req.name === undefined && req.role === undefined) return this.actor.submit();
        const el: { name?: string; role?: string } = {};
        if (req.name !== undefined) el.name = req.name;
        if (req.role !== undefined) el.role = req.role;
        return this.actor.submit(el);
      }
      default:
        // Unreachable: the CREDENTIAL_* kinds are refused earlier in act() itself, before
        // dispatchAct is ever called. This throw exists only so a future ActKind addition fails
        // loudly instead of silently doing nothing.
        throw new Error(`act: unsupported action kind ${req.kind}`);
    }
  }

  private guard(run_id: string, kind: ActionKind, url?: string): { run: RunEntry; decision: Decision } {
    const run = this.runs.get(run_id);
    if (!run) throw new Error(`unknown run_id: ${run_id}`);
    const decision = check(run.policy, actionRequest(kind, url), run.state, this.now());
    return { run, decision };
  }

  private pageProvenanceOf(obj: Record<string, unknown>): Provenance {
    const url = typeof obj.url === "string" ? obj.url : undefined;
    const origin = url ? originOf(url) : null;
    return { origins: origin ? [origin] : [], trust: "untrusted" };
  }

  // Defense in depth for the no-plaintext invariant. The real extension reader emits only
  // `value_present` (a boolean) and never a raw field value - but RunManager must not TRUST that.
  // The element map is the one channel that could carry a credential back to the caller, and
  // Phase 3 deliberately causes real credentials to be autofilled into page fields, so a
  // compromised or regressed reader must not be able to launder a secret through here.
  // CometActor.credentialFill applies the same stripping on its own read path.
  private static stripElementValues(elements: unknown): unknown {
    if (!Array.isArray(elements)) return elements;
    return elements.map(el => {
      if (el === null || typeof el !== "object") return el;
      const { value, ...rest } = el as Record<string, unknown>;
      return rest;
    });
  }

  // Quarantined (default): strip raw content, replace with a digest, keep the element map.
  // Raw (explicit per-run opt-in): pass content through unchanged. Both modes attach the
  // page's provenance so the caller can see where the data came from, and BOTH strip raw
  // element values - "raw" opts into page prose, never into field contents.
  private shapeReadResult(run: RunEntry, raw: unknown): unknown {
    if (raw === null || typeof raw !== "object") return raw;
    const obj0 = raw as Record<string, unknown>;
    const obj = "elements" in obj0
      ? { ...obj0, elements: RunManager.stripElementValues(obj0.elements) }
      : obj0;
    const pageProvenance = this.pageProvenanceOf(obj);
    run.provenance = mergeProvenance(run.provenance, pageProvenance);

    const mode = run.policy.content_mode ?? "quarantined";
    if (mode === "raw") {
      return { ...obj, provenance: pageProvenance };
    }

    const { content, ...rest } = obj;
    const text = typeof content === "string" ? content : "";
    const content_digest = { chars: text.length, sha256: createHash("sha256").update(text).digest("hex") };
    return { ...rest, content_digest, provenance: pageProvenance };
  }

  private static digestOf(text: string): { chars: number; sha256: string } {
    return { chars: text.length, sha256: createHash("sha256").update(text).digest("hex") };
  }

  // Task 37 (Phase 6): content_mode shaping for comet_inspect, mirroring shapeReadResult's
  // discipline - THE RISK invariant 3 in docs/plans/2026-08-14-comet-agent-phase6-inspect-
  // assistant.md: under the default "quarantined" mode, large inspection payloads come back as a
  // digest, not raw prose. The extension has already redacted every string (unless the run opted
  // into allow_unredacted_inspect); this only collapses bulk-prose bodies into a digest, exactly
  // like comet_read's content -> content_digest.
  //
  // source / scripts[].text / styles.inline[] are ALWAYS bulk prose, so they are unconditionally
  // digested. console[] / resources[].name / cookies are different: each individual entry is
  // USUALLY short (a log line, a resource URL, a cookie header) and useful to see inline for
  // debugging, but every one of them is still page-controlled and NONE of them is bounded by the
  // browser - a single console.log() call can carry an arbitrarily large string straight through
  // (proven: a 50KB injected string reached this method verbatim before this fix), same for a
  // resource's recorded URL or the raw cookie header. So those three get digested per-entry, only
  // once an individual entry exceeds MAX_INLINE_INSPECT_CHARS - small, ordinary entries stay
  // inline and readable; anything large enough to plausibly carry injected prose collapses to a
  // digest like the always-bulk fields above. `computed` is left untouched: its values are drawn
  // from a small fixed CSS-property allowlist (buildComputed's COMPUTED_STYLE_ALLOWLIST) and can
  // never carry attacker-controlled prose of meaningful size.
  private static digestIfLarge(s: string): unknown {
    return s.length > MAX_INLINE_INSPECT_CHARS ? RunManager.digestOf(s) : s;
  }

  private shapeInspectResult(run: RunEntry, raw: Record<string, unknown>): unknown {
    const pageProvenance = this.pageProvenanceOf(raw);
    run.provenance = mergeProvenance(run.provenance, pageProvenance);

    const mode = run.policy.content_mode ?? "quarantined";
    if (mode === "raw") return { ...raw, provenance: pageProvenance };

    const out: Record<string, unknown> = { ...raw };
    if (typeof out.source === "string") {
      out.source_digest = RunManager.digestOf(out.source);
      delete out.source;
    }
    if (Array.isArray(out.scripts)) {
      out.scripts = (out.scripts as unknown[]).map(entry => {
        if (entry === null || typeof entry !== "object" || typeof (entry as Record<string, unknown>).text !== "string") return entry;
        const { text, ...rest } = entry as Record<string, unknown>;
        return { ...rest, text_digest: RunManager.digestOf(text as string) };
      });
    }
    if (out.styles !== null && typeof out.styles === "object" && Array.isArray((out.styles as Record<string, unknown>).inline)) {
      const styles = out.styles as Record<string, unknown>;
      out.styles = { ...styles, inline: (styles.inline as unknown[]).map(t => (typeof t === "string" ? RunManager.digestOf(t) : t)) };
    }
    if (Array.isArray(out.console)) {
      out.console = (out.console as unknown[]).map(e => (typeof e === "string" ? RunManager.digestIfLarge(e) : e));
    }
    if (Array.isArray(out.resources)) {
      out.resources = (out.resources as unknown[]).map(entry => {
        if (entry === null || typeof entry !== "object" || typeof (entry as Record<string, unknown>).name !== "string") return entry;
        const { name, ...rest } = entry as Record<string, unknown>;
        return { ...rest, name: RunManager.digestIfLarge(name as string) };
      });
    }
    if (typeof out.cookies === "string") {
      out.cookies = RunManager.digestIfLarge(out.cookies);
    }
    return { ...out, provenance: pageProvenance };
  }

  // Task 38 (Phase 6): content_mode shaping for comet_assistant_ask, mirroring
  // shapeInspectResult's discipline. The answer has no single page origin of its own - it is
  // synthesized from arbitrary web content via the user's Perplexity connectors - so its
  // provenance is simply "untrusted, no known origins" (the same shape pageProvenanceOf falls
  // back to when a bridge payload carries no url). Under "raw" the answer passes through
  // unchanged (an explicit opt-in for trusted contexts, same as every other raw path in this
  // file); under the default "quarantined" the caller gets a digest of the FULL answer plus a
  // bounded, REDACTED excerpt - redactCredentials runs over the complete answer BEFORE truncation
  // so a secret straddling the excerpt boundary cannot survive as a half-matched, unredacted
  // fragment (see redactCredentials's own doc comment in src/egress.ts).
  private shapeAssistantResult(run: RunEntry, answer: string): unknown {
    const answerProvenance: Provenance = { origins: [], trust: "untrusted" };
    run.provenance = mergeProvenance(run.provenance, answerProvenance);

    const mode = run.policy.content_mode ?? "quarantined";
    if (mode === "raw") return { answer, provenance: answerProvenance };

    const excerpt = redactCredentials(answer).slice(0, MAX_ASSISTANT_EXCERPT_CHARS);
    return { answer_digest: RunManager.digestOf(answer), excerpt, provenance: answerProvenance };
  }

  // Only fires once the initial policy decision already allowed the navigate (a denied domain
  // is denied by policy.check regardless of path/query/fragment). Guards against a
  // credential-shaped or private-provenance payload smuggled ANYWHERE in the destination URL
  // (path, query, fragment, or userinfo), even to an allowlisted host - checkEgress's
  // credential rule is a hard invariant that must hold "regardless of destination", so this
  // always calls checkEgress rather than short-circuiting on an empty query/fragment. The
  // Task 1 fail-open lesson: never let an unusual shape fall through unchecked.
  private applyNavigateEgress(run: RunEntry, url: string, decision: Decision): Decision {
    if (!decision.allowed) return decision;
    let parsed: URL;
    try { parsed = new URL(url); } catch { return decision; }
    const userinfo = parsed.username ? `${parsed.username}${parsed.password ? ":" + parsed.password : ""}@` : "";
    const payload = `${userinfo}${parsed.pathname}${parsed.search}${parsed.hash}`;

    // Oversized-URL rule. checkEgress's rules 3/4 only fire on NON-allowlisted origins, so a bulk
    // payload stuffed into the path/query/fragment of an ALLOWLISTED host would otherwise pass.
    // Only applies once this run has actually seen untrusted data - before that there is nothing
    // page-derived to exfiltrate and ordinary long URLs must keep working.
    const maxUrlPayload = run.policy.budgets.max_url_payload_chars ?? DEFAULT_MAX_URL_PAYLOAD_CHARS;
    if (run.provenance.trust === "untrusted" && payload.length > maxUrlPayload) {
      return { allowed: false, reason: `url payload ${payload.length} chars exceeds ${maxUrlPayload} after untrusted data was read` };
    }

    const egress = checkEgress(run.policy, { destination: url, payload, provenance: run.provenance });
    return egress.allowed ? decision : { allowed: false, reason: egress.reason };
  }

  // TYPE is checked against the CURRENT page origin (set only by a successful navigate). No
  // known origin yet is treated as an unparseable egress destination - fail closed, never
  // pass-through - rather than silently allowing TYPE before any page context exists.
  private applyActEgress(run: RunEntry, req: ActRequest, decision: Decision): Decision {
    if (!decision.allowed || req.kind !== "TYPE" || req.text === undefined) return decision;
    const destination = run.currentOrigin ? `https://${run.currentOrigin}` : "";
    const egress = checkEgress(run.policy, { destination, payload: req.text, provenance: run.provenance });
    return egress.allowed ? decision : { allowed: false, reason: egress.reason };
  }

  private record(run_id: string, kind: ActionKind, decision: Decision, target?: string): void {
    this.audit.append({
      ts: this.now(),
      run_id,
      actor: "agent",
      action: kind,
      policy_decision: decision.allowed ? "allow" : "deny",
      ...(target !== undefined ? { target } : {}),
      ...(decision.reason !== undefined ? { reason: decision.reason } : {})
    });
    // Every record() call is a finalised policy decision for one attempted action, so this is the
    // single place that feeds the tripwire - see trackTripwire's doc comment for what counts.
    this.trackTripwire(run_id, decision.allowed);
  }

  // Task 30 (Phase 4): the global emergency stop, checked at the TOP of every action method
  // (navigate/read/act/extract/credentialFill/credentialUse/credentialReveal) before the guard,
  // the actor, or the bridge is ever touched - see THE RISK invariant 5. `run.killed` latches:
  // once true (from either this file check or the tripwire below), it stays true for the rest of
  // the run even if the KILL file is later removed, so a killed run can never resume itself.
  // Deliberately NOT gated on run.unattended - an emergency stop that only stopped SOME runs
  // would be a foot-gun for the human trying to use it; see the RunEntry.unattended doc comment.
  private checkKillSwitch(run_id: string, kind: ActionKind, target?: string): ActionResult | null {
    const run = this.runs.get(run_id);
    if (!run) return null; // unknown run_id - let guard() throw its usual error, unchanged
    const engaged = run.killed === true || (this.dataDir !== undefined && isKilled(this.dataDir));
    if (!engaged) return null;
    run.killed = true;
    this.audit.append({
      ts: this.now(), run_id, actor: "agent", action: kind,
      policy_decision: "killed",
      ...(target !== undefined ? { target } : {}),
      reason: "kill switch engaged"
    });
    return denied("killed");
  }

  // Task 30 (Phase 4): per-run tripwire for an UNATTENDED run only (a no-op for attended runs and
  // for a run already killed). `allowed=false` (a denied policy/credential decision - domain,
  // action kind, budget, site pre-authorisation, origin binding, missing approval, all route
  // through record()) increments the streak; `allowed=true` resets it, so this counts CONSECUTIVE
  // denials, not total ones, matching the Task 30 spec's "3 consecutive out-of-scope denials".
  // Reaching TRIPWIRE_THRESHOLD marks the run killed and writes one extra `tripwire` audit record
  // IN ADDITION TO the individual deny record record() already wrote for the triggering action -
  // so the log shows both the specific reason for that action and the fact that it tripped the
  // switch.
  private trackTripwire(run_id: string, allowed: boolean): void {
    const run = this.runs.get(run_id);
    if (!run || !run.unattended || run.killed) return;
    if (allowed) {
      run.consecutiveDenials = 0;
      return;
    }
    run.consecutiveDenials = (run.consecutiveDenials ?? 0) + 1;
    if (run.consecutiveDenials >= TRIPWIRE_THRESHOLD) {
      run.killed = true;
      this.audit.append({
        ts: this.now(), run_id, actor: "agent", action: "TRIPWIRE",
        policy_decision: "tripwire",
        reason: `${run.consecutiveDenials} consecutive denied actions`
      });
    }
  }

  // Task 31 (Phase 4): shared by act() and credentialUse() - the only two paths that can reach a
  // live, state-changing actor call for a NAMED element/target on an unattended run. NAVIGATE has
  // no acted-upon element to pattern-match and stays governed by the domain allowlist + egress
  // gate alone, per the Task 31 spec ("act/credentialUse/submit paths" - SUBMIT is one of act()'s
  // own ActKind cases, not a separate method). CREDENTIAL_FILL/CREDENTIAL_REVEAL are out of scope
  // for this task. See THE RISK invariant 4 in
  // docs/plans/2026-08-14-comet-agent-phase4-unattended.md.
  //
  // Returns `{ proceed: true }` for an attended run, or an unattended run where classifyAction saw
  // nothing irreversible-shaped - the caller proceeds exactly as before Task 31. Returns
  // `{ proceed: true, reason }` when a tag DID match but the mission's preauthorized_irreversible
  // list already covers it - the caller folds `reason` into whichever audit record it writes for
  // this (still-allowed) attempt, so the tag is visible in the log even though nothing was denied.
  // Returns `{ proceed: false, tag }` when a tag matched and was NOT preauthorized - the caller
  // MUST NOT touch the actor, MUST call recordBlockedPendingApproval, and MUST return a blocked
  // result instead of the actor's result.
  private classifyIrreversible(run: RunEntry, kind: string, target: string | undefined):
    { proceed: true; reason?: string } | { proceed: false; tag: string } {
    if (!run.unattended) return { proceed: true };
    const tag = classifyAction(kind, target, run.currentOrigin);
    if (!tag) return { proceed: true };
    if ((run.preauthorizedIrreversible ?? []).includes(tag)) {
      return { proceed: true, reason: `irreversible:${tag} preauthorized` };
    }
    return { proceed: false, tag };
  }

  // Task 31 (Phase 4): writes the ONE audit record for a blocked-pending-approval attempt
  // (`policy_decision: "blocked_pending_approval"`, deliberately NOT "deny" - this is a PAUSE
  // the mission itself did not pre-authorise, not a policy/scope violation, so it must not feed
  // the Task 30 tripwire) and drops a pending-approval file into `<DATA_DIR>/pending/` for the
  // human/orchestrator to see. Best-effort on the file: a run constructed without a dataDir (e.g.
  // an older test, or a caller that never wired one) still blocks the action and writes the audit
  // record - it just cannot also drop the convenience queue file. A disk failure while writing
  // that file must never turn a correctly-blocked action into a thrown error or a silently-lost
  // pause, so the write is wrapped in its own try/catch.
  private recordBlockedPendingApproval(run_id: string, kind: ActionKind, tag: string, target?: string): void {
    const ts = this.now();
    this.audit.append({
      ts, run_id, actor: "agent", action: kind,
      policy_decision: "blocked_pending_approval",
      ...(target !== undefined ? { target } : {}),
      reason: `irreversible:${tag} not preauthorized`
    });
    if (this.dataDir === undefined) return;
    try {
      const dir = join(this.dataDir, "pending");
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      const id = `${run_id}_${ts}_${randomBytes(4).toString("hex")}`;
      writeFileSync(join(dir, `${id}.json`), JSON.stringify({
        id, ts, run_id, kind, tag, ...(target !== undefined ? { target } : {})
      }));
    } catch {
      // Best-effort only - see doc comment above.
    }
  }
}
