import { describe, it, expect } from "vitest";
import { RunManager, type ActorLike, type BridgeReader, type AuditSink } from "../src/run_manager.js";
import type { Policy } from "../src/policy.js";

// Defense in depth for the no-plaintext invariant, found by an adversarial probe on 2026-08-13.
// The real extension reader never emits a raw field `value` - but RunManager used to forward the
// element map from the bridge untouched, so a compromised or regressed reader could have laundered
// a just-autofilled credential straight back to the caller. Phase 3 makes real credentials appear
// in page fields, which is exactly what turns this from theoretical into worth closing.

const SENTINEL = "hunter2-SENTINEL-DO-NOT-LEAK";

const hostileBridge: BridgeReader = {
  read: async () => ({
    url: "https://bank.example/login",
    title: "Login",
    content: "some page prose",
    elements: [
      { ref: 0, name: "Password", role: "edit", type: "password", value_present: true, value: SENTINEL },
      { ref: 1, name: "Search", role: "edit", value_present: true, value: "q3 report" }
    ]
  })
};

const actor: ActorLike = {
  navigate: async () => ({ ok: true }),
  click: async () => ({ ok: true }),
  type: async () => ({ ok: true }),
  scroll: async () => ({ ok: true }),
  credentialFill: async () => ({ ok: true, filled: true })
};
const noAudit: AuditSink = { append: () => {} };

const policy = (over: Partial<Policy> = {}): Policy => ({
  domains_allow: ["bank.example"],
  domains_deny: [],
  actions_allow: ["NAVIGATE", "READ"],
  budgets: { max_actions: 99, max_domains: 9, max_ms: 999_999 },
  ...over
});

describe("comet_read strips raw element values", () => {
  it("never forwards a field value in quarantined mode", async () => {
    const rm = new RunManager(actor, hostileBridge, noAudit, undefined, () => 0);
    const { run_id } = rm.begin(policy());
    const r = await rm.read(run_id, "page");
    const blob = JSON.stringify(r);
    expect(blob).not.toContain(SENTINEL);
    expect(blob).not.toContain("q3 report");
  });

  // "raw" opts into page PROSE, not into field contents - the credential invariant is not
  // something a per-run flag may switch off.
  it("never forwards a field value in raw mode either", async () => {
    const rm = new RunManager(actor, hostileBridge, noAudit, undefined, () => 0);
    const { run_id } = rm.begin(policy({ content_mode: "raw" }));
    const r = await rm.read(run_id, "page");
    const blob = JSON.stringify(r);
    expect(blob).not.toContain(SENTINEL);
    expect(blob).toContain("some page prose"); // raw mode still returns prose
  });

  it("preserves the useful element metadata while dropping only the value", async () => {
    const rm = new RunManager(actor, hostileBridge, noAudit, undefined, () => 0);
    const { run_id } = rm.begin(policy());
    const r = await rm.read(run_id, "page");
    const els = (r.result as { elements: Array<Record<string, unknown>> }).elements;
    expect(els).toHaveLength(2);
    expect(els[0]).toMatchObject({ ref: 0, name: "Password", role: "edit", type: "password", value_present: true });
    expect("value" in els[0]!).toBe(false);
  });
});
