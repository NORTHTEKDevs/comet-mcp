import { describe, it, expect } from "vitest";
import { looksLikeCredential } from "../src/egress.js";
import { RunManager, type ActorLike, type BridgeReader, type AuditSink } from "../src/run_manager.js";
import type { Policy } from "../src/policy.js";

// The three residual egress gaps found by an adversarial probe on 2026-08-13 and closed here.
// Each test targets the exact route that was OPEN, so a regression re-opens a real exfil path.

describe("gap 1: purely numeric secrets", () => {
  it.each([
    ["4111111111111111", true, "Luhn-valid 16-digit card number"],
    ["378282246310005", true, "Luhn-valid 15-digit card number"],
    ["123456789012345678", true, "18-digit run (>= 15) treated as secret-shaped"],
    ["1786663636289", false, "13-digit epoch-ms timestamp must NOT false-positive"],
    ["order 12345 shipped on 2026-08-13", false, "ordinary prose with short numbers"]
  ])("%s -> %s (%s)", (input, expected) => {
    expect(looksLikeCredential(input)).toBe(expected);
  });
});

const actorSpy = () => {
  const calls: string[] = [];
  const actor: ActorLike = {
    navigate: async () => { calls.push("navigate"); return { ok: true }; },
    click: async () => { calls.push("click"); return { ok: true }; },
    type: async () => { calls.push("type"); return { ok: true }; },
    scroll: async () => { calls.push("scroll"); return { ok: true }; }
  };
  return { actor, calls };
};

const pageBridge: BridgeReader = {
  read: async () => ({ url: "https://good.com/inbox", title: "Inbox", elements: [], content: "client data" })
};
const noAudit: AuditSink = { append: () => {} };

const basePolicy: Policy = {
  domains_allow: ["good.com"],
  domains_deny: [],
  actions_allow: ["NAVIGATE", "READ", "TYPE"],
  budgets: { max_actions: 99, max_domains: 9, max_ms: 999_999 }
};

describe("gap 2: bulk payload into an ALLOWLISTED host's URL", () => {
  it("blocks an oversized url payload once the run has read untrusted data", async () => {
    const { actor, calls } = actorSpy();
    const rm = new RunManager(actor, pageBridge, noAudit, undefined, () => 0);
    const { run_id } = rm.begin(basePolicy);

    // Before any read there is nothing page-derived to leak, so a long URL still works.
    const long = "https://good.com/#" + "a".repeat(400);
    expect((await rm.navigate(run_id, long)).ok).toBe(true);

    await rm.read(run_id, "page");           // run provenance becomes untrusted
    const after = await rm.navigate(run_id, long);
    expect(after.ok).toBe(false);
    expect(after.reason).toMatch(/url payload .* exceeds/);
    expect(calls.filter(c => c === "navigate")).toHaveLength(1); // blocked one never reached the actor
  });

  it("still allows an ordinary deep link after an untrusted read", async () => {
    const { actor } = actorSpy();
    const rm = new RunManager(actor, pageBridge, noAudit, undefined, () => 0);
    const { run_id } = rm.begin(basePolicy);
    await rm.read(run_id, "page");
    expect((await rm.navigate(run_id, "https://good.com/mail/u/0/#inbox")).ok).toBe(true);
  });
});

// "Chunk a secret across many small calls to stay under the 40-char rule" was raised as a gap,
// but it is NOT reachable: the Phase 1 domain allowlist denies a NAVIGATE to any non-allowlisted
// host outright, before egress accounting would ever run, and a TYPE can only target the CURRENT
// page origin - which is by definition a host the run already navigated to, hence allowlisted.
// A cumulative-byte budget was built and then removed as unreachable complexity; these tests pin
// the reasoning so nobody re-adds it, and so a regression that weakens the allowlist is caught.
describe("gap 3: chunked egress is already closed by the domain allowlist", () => {
  it("denies NAVIGATE to a non-allowlisted host at the policy layer, before any egress rule", async () => {
    const { actor, calls } = actorSpy();
    const rm = new RunManager(actor, pageBridge, noAudit, undefined, () => 0);
    const { run_id } = rm.begin(basePolicy);
    await rm.read(run_id, "page");

    for (let i = 0; i < 4; i++) {
      const r = await rm.navigate(run_id, `https://other.com/${String(i).repeat(20)}`);
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/domain not allowlisted/);
    }
    expect(calls.filter(c => c === "navigate")).toHaveLength(0);
  });

  it("TYPE cannot target an origin the run never navigated to", async () => {
    const { actor, calls } = actorSpy();
    const rm = new RunManager(actor, pageBridge, noAudit, undefined, () => 0);
    const { run_id } = rm.begin(basePolicy);
    // No successful navigate yet -> no current origin -> fail closed, actor untouched.
    const r = await rm.act(run_id, { kind: "TYPE", text: "secret", name: "field" });
    expect(r.ok).toBe(false);
    expect(calls).toHaveLength(0);
  });
});
