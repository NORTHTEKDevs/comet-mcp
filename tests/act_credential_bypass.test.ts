import { describe, it, expect } from "vitest";
import { RunManager, type ActorLike, type BridgeReader, type AuditSink } from "../src/run_manager.js";
import type { Policy } from "../src/policy.js";

// Regression, found by an adversarial probe on 2026-08-13 after Phase 3 removed CREDENTIAL_FILL
// from policy.DANGEROUS.
//
// With CREDENTIAL_FILL no longer blanket-denied, a policy listing it in actions_allow made it pass
// policy.check() on the GENERIC act() path - which does not consult the four credential gates. The
// result was a FALSE "allow" audit record for a credential fill that was never gated, followed by
// a throw from dispatchAct's default case. No credential leaked (the actor was never reached), but
// the audit trail lied, and a future dispatchAct case for CREDENTIAL_FILL would have turned it
// into a real four-gate bypass. act() must refuse the kind outright.

const calls: string[] = [];
const actor: ActorLike = {
  navigate: async () => { calls.push("navigate"); return { ok: true }; },
  click: async () => { calls.push("click"); return { ok: true }; },
  type: async () => { calls.push("type"); return { ok: true }; },
  scroll: async () => { calls.push("scroll"); return { ok: true }; },
  credentialFill: async () => { calls.push("credentialFill"); return { ok: true, filled: true }; },
  submit: async () => { calls.push("submit"); return { ok: true }; }
};
const bridge: BridgeReader = { read: async () => ({ url: "https://bank.example/x", elements: [] }) };

const wideOpen: Policy = {
  domains_allow: ["bank.example"],
  domains_deny: [],
  // Deliberately hostile: every kind allowed, including the two that must never be reachable here.
  actions_allow: ["NAVIGATE", "READ", "CLICK", "TYPE", "SELECT", "SCROLL", "WAIT", "EXTRACT", "SUBMIT", "CREDENTIAL_FILL", "FINISH"],
  credential_sites: ["bank.example"],
  budgets: { max_actions: 99, max_domains: 9, max_ms: 999_999 }
};

describe("act() cannot be used to reach CREDENTIAL_FILL", () => {
  it("denies instead of throwing, and never calls the actor", async () => {
    calls.length = 0;
    const recs: Array<Record<string, unknown>> = [];
    const audit: AuditSink = { append: r => recs.push(r as unknown as Record<string, unknown>) };
    const rm = new RunManager(actor, bridge, audit, undefined, () => 0);
    const { run_id } = rm.begin(wideOpen);

    const r = await rm.act(run_id, { kind: "CREDENTIAL_FILL", name: "Password" });

    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/gated credential-fill path/);
    expect(calls).not.toContain("credentialFill");
  });

  it("records an honest DENY, never a false allow", async () => {
    const recs: Array<{ action: string; policy_decision: string }> = [];
    const audit: AuditSink = { append: r => recs.push(r as unknown as { action: string; policy_decision: string }) };
    const rm = new RunManager(actor, bridge, audit, undefined, () => 0);
    const { run_id } = rm.begin(wideOpen);

    await rm.act(run_id, { kind: "CREDENTIAL_FILL", name: "Password" });

    const credRecs = recs.filter(r => r.action === "CREDENTIAL_FILL");
    expect(credRecs).toHaveLength(1);
    expect(credRecs[0]!.policy_decision).toBe("deny");
  });

  // Phase 5 Task 26: SUBMIT left policy.DANGEROUS, so on this wideOpen policy (which lists it in
  // actions_allow) it is now a legitimately reachable action - not a bypass, the deliberate
  // opt-in this task adds. The CREDENTIAL_FILL refusal above is the invariant that must hold
  // regardless of policy; SUBMIT's gating is ordinary actions_allow, proven directly in
  // tests/run_manager.test.ts and tests/policy.test.ts.
  it("reaches actor.submit on the same path now that SUBMIT is policy-gated only (Phase 5 Task 26)", async () => {
    calls.length = 0;
    const audit: AuditSink = { append: () => {} };
    const rm = new RunManager(actor, bridge, audit, undefined, () => 0);
    const { run_id } = rm.begin(wideOpen);
    const r = await rm.act(run_id, { kind: "SUBMIT", name: "Send" });
    expect(r.ok).toBe(true);
    expect(calls).toEqual(["submit"]);
  });
});