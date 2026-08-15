import { describe, it, expect } from "vitest";
import { RunManager, type ActorLike, type BridgeReader, type AuditSink } from "../src/run_manager.js";
import type { Policy } from "../src/policy.js";

// Gap found by an adversarial probe after the Phase 4 gauntlet, and flagged by the Task 31
// reviewer: credentialReveal() was the one secret-touching path NOT run through the irreversible
// gate. The Task 31 spec listed only act/credentialUse/submit, so it was spec-compliant - but
// handing plaintext to an AUTONOMOUS agent while the page looks like a delete/transfer/password
// -change context is exactly the moment that deserves the speed bump. The gate must run BEFORE the
// single-use approval is spent, so a blocked reveal costs the human nothing.

const SENTINEL = "hunter2-SENTINEL";
const SITE = "bank.example";

const mkActor = (): ActorLike => ({
  navigate: async (u: string) => { TAB_URL = u; return { ok: true }; },
  click: async () => ({ ok: true }),
  type: async () => ({ ok: true }),
  scroll: async () => ({ ok: true }),
  credentialFill: async () => ({ ok: true, filled: true }),
  submit: async () => ({ ok: true })
});
// The live tab url is origin binding's source of truth (see RunManager.bindLiveOrigin), so the
// fake tab follows navigation instead of pinning one url a real browser could not hold.
let TAB_URL: string | undefined = `https://${SITE}/x`;
const bridge: BridgeReader = { read: async () => ({ url: TAB_URL, elements: [] }) };
const credStore = { read: (o: string) => (o === SITE ? { username: "u", password: SENTINEL } : null) };

function approvals() {
  const list = [{ id: "ap-reveal", site: SITE, action: "CREDENTIAL_REVEAL" as const, expires_ms: 10_000, used: false }];
  return {
    list,
    find: (s: string, n: number, a?: string) =>
      list.find(x => x.site === s && !x.used && x.expires_ms > n && (a === undefined || x.action === a)) ?? null,
    consume: (id: string) => { const x = list.find(y => y.id === id); if (!x || x.used) return false; x.used = true; return true; }
  };
}

const policy: Policy = {
  domains_allow: [SITE],
  domains_deny: [],
  actions_allow: ["NAVIGATE", "CREDENTIAL_REVEAL"],
  credential_sites: [SITE],
  allow_credential_reveal: true,
  budgets: { max_actions: 20, max_domains: 5, max_ms: 99_999 }
};

// An unattended run whose current page reads as a destructive context.
async function unattendedRunOn(page: string, appr: ReturnType<typeof approvals>, audit: AuditSink) {
  const rm = new RunManager(mkActor(), bridge, audit, undefined, () => 0, appr, credStore);
  const { run_id } = rm.begin(policy);
  // Force the unattended posture the gate keys off, exactly as beginMission would.
  (rm as unknown as { runs: Map<string, Record<string, unknown>> }).runs.get(run_id)!.unattended = true;
  (rm as unknown as { runs: Map<string, Record<string, unknown>> }).runs.get(run_id)!.preauthorizedIrreversible = [];
  await rm.navigate(run_id, page);
  return { rm, run_id };
}

describe("credentialReveal honours the irreversible gate on unattended runs", () => {
  it("blocks a reveal in a destructive-looking context and does NOT spend the approval", async () => {
    const appr = approvals();
    const recs: Array<Record<string, unknown>> = [];
    const audit: AuditSink = { append: r => recs.push(r as unknown as Record<string, unknown>) };
    // A site whose own host carries the destructive signal, since the gate sees currentOrigin.
    const destructive: Policy = { ...policy, domains_allow: ["delete-account.example"], credential_sites: ["delete-account.example"] };
    const apprD = approvals();
    apprD.list[0]!.site = "delete-account.example";
    const credD = { read: () => ({ username: "u", password: SENTINEL }) };
    const rm = new RunManager(mkActor(), bridge, audit, undefined, () => 0, apprD, credD);
    const { run_id } = rm.begin(destructive);
    const runs = (rm as unknown as { runs: Map<string, Record<string, unknown>> }).runs;
    runs.get(run_id)!.unattended = true;
    runs.get(run_id)!.preauthorizedIrreversible = [];
    await rm.navigate(run_id, "https://delete-account.example/settings");

    const r = await rm.credentialReveal(run_id, "delete-account.example");

    expect(r.ok).toBe(false);
    expect((r as { blocked?: boolean }).blocked).toBe(true);
    expect(apprD.list[0]!.used).toBe(false);               // the human's grant was NOT spent
    expect(JSON.stringify(r)).not.toContain(SENTINEL);      // and no plaintext came back
    expect(JSON.stringify(recs)).not.toContain(SENTINEL);
  });

  it("still reveals normally when the context is not destructive", async () => {
    const appr = approvals();
    const recs: Array<Record<string, unknown>> = [];
    const audit: AuditSink = { append: r => recs.push(r as unknown as Record<string, unknown>) };
    const { rm, run_id } = await unattendedRunOn(`https://${SITE}/login`, appr, audit);
    const r = await rm.credentialReveal(run_id, SITE);
    expect(r.ok).toBe(true);
    expect((r.result as { credential: { password: string } }).credential.password).toBe(SENTINEL);
    expect(appr.list[0]!.used).toBe(true);
    expect(JSON.stringify(recs)).not.toContain(SENTINEL); // audit still never holds the value
  });
});
