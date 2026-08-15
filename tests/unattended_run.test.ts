import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RunManager } from "../src/run_manager.js";
import { fileMissionStore, grantMission, type Mission } from "../src/missions.js";
import type { QuarantineClient } from "../src/quarantine.js";

function keys() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    pub: publicKey.export({ type: "spki", format: "pem" }).toString()
  };
}

function freshDir(prefix = "unattended-"): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

const fakeQuarantine = (): QuarantineClient => ({ complete: async () => "{}" });

const fakeActor = () => {
  const calls: string[] = [];
  return {
    calls,
    navigate: async (_u: string) => { calls.push("nav"); },
    type: async (_t: string, _el: any) => { calls.push("type"); return { ok: true, verified: true }; },
    scroll: async (_d: string, _amount?: number) => { calls.push("scroll"); return { ok: true }; },
    click: async (_el: any) => { calls.push("click"); return { ok: true, verified: true }; },
    submit: async (_el?: any) => { calls.push("submit"); return { ok: true, verified: true }; }
  };
};
const fakeBridge = () => ({
  read: async (_p?: unknown) => ({ url: "https://good.example.com", elements: [], content: "ok" })
});
const fakeAudit = () => { const recs: any[] = []; return { recs, append: (r: any) => recs.push(r) }; };

function baseMissionGrant(overrides?: Partial<Omit<Mission, "id" | "used">>): Omit<Mission, "id" | "used"> {
  return {
    scope: {
      domains_allow: ["good.example.com"],
      credential_sites: [],
      actions_allow: ["NAVIGATE", "READ"],
      account: "client-a"
    },
    budgets: { max_actions: 50, max_ms: 600_000, max_domains: 5 },
    preauthorized_irreversible: [],
    expires_ms: Date.now() + 60_000,
    ...overrides
  };
}

describe("RunManager unattended (Task 30)", () => {
  it("beginMission without a configured mission store is denied, no run", () => {
    const rm = new RunManager(fakeActor() as any, fakeBridge() as any, fakeAudit() as any, fakeQuarantine(), () => 0);
    const result = rm.beginMission("whatever");
    expect("error" in result).toBe(true);
    expect("run_id" in result).toBe(false);
  });

  it("beginMission with no grant is denied, no run", () => {
    const dir = freshDir();
    const { pub } = keys();
    const missionStore = fileMissionStore(dir, pub);
    const rm = new RunManager(
      fakeActor() as any, fakeBridge() as any, fakeAudit() as any, fakeQuarantine(), () => 0,
      undefined, undefined, missionStore
    );
    const result = rm.beginMission("no-such-mission");
    expect("error" in result).toBe(true);
    expect("run_id" in result).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("beginMission with a valid grant starts an unattended run scoped to the mission", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(dir, pub);
    const granted = grantMission(dir, priv, baseMissionGrant());
    const rm = new RunManager(
      fakeActor() as any, fakeBridge() as any, fakeAudit() as any, fakeQuarantine(), () => 0,
      undefined, undefined, missionStore
    );
    const result = rm.beginMission(granted.id);
    expect("run_id" in result).toBe(true);
    const run_id = (result as any).run_id;
    const status = rm.status(run_id);
    expect(status?.policy.domains_allow).toEqual(["good.example.com"]);
    expect(status?.policy.actions_allow).toEqual(["NAVIGATE", "READ"]);
    rmSync(dir, { recursive: true, force: true });
  });

  it("a second beginMission on the same (now consumed) mission is denied", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(dir, pub);
    const granted = grantMission(dir, priv, baseMissionGrant());
    const rm = new RunManager(
      fakeActor() as any, fakeBridge() as any, fakeAudit() as any, fakeQuarantine(), () => 0,
      undefined, undefined, missionStore
    );
    const first = rm.beginMission(granted.id);
    expect("run_id" in first).toBe(true);
    const second = rm.beginMission(granted.id);
    expect("error" in second).toBe(true);
    expect("run_id" in second).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("a killed file aborts the very next action mid-run and audits killed", async () => {
    const missionsDir = freshDir("missions-");
    const dataDir = freshDir("data-");
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(missionsDir, pub);
    const granted = grantMission(missionsDir, priv, baseMissionGrant());
    const actor = fakeActor(); const audit = fakeAudit();
    const rm = new RunManager(
      actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0,
      undefined, undefined, missionStore, dataDir
    );
    const { run_id } = rm.beginMission(granted.id) as any;

    const first = await rm.navigate(run_id, "https://good.example.com");
    expect(first.ok).toBe(true);
    expect(actor.calls).toEqual(["nav"]);

    writeFileSync(join(dataDir, "KILL"), "");

    const second = await rm.navigate(run_id, "https://good.example.com");
    expect(second.ok).toBe(false);
    expect(second.reason).toBe("killed");
    expect(audit.recs.at(-1).policy_decision).toBe("killed");
    expect(actor.calls).toEqual(["nav"]); // second navigate never reached the actor

    // Once killed, the run stays dead even without re-checking the file (belt and suspenders).
    const third = await rm.navigate(run_id, "https://good.example.com");
    expect(third.ok).toBe(false);
    expect(actor.calls).toEqual(["nav"]);

    rmSync(missionsDir, { recursive: true, force: true });
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("budget exhaustion terminates the mission run", async () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(dir, pub);
    const granted = grantMission(dir, priv, baseMissionGrant({ budgets: { max_actions: 1, max_ms: 600_000, max_domains: 5 } }));
    const rm = new RunManager(
      fakeActor() as any, fakeBridge() as any, fakeAudit() as any, fakeQuarantine(), () => 0,
      undefined, undefined, missionStore
    );
    const { run_id } = rm.beginMission(granted.id) as any;
    const first = await rm.navigate(run_id, "https://good.example.com");
    expect(first.ok).toBe(true);
    const second = await rm.navigate(run_id, "https://good.example.com");
    expect(second.ok).toBe(false);
    expect(second.reason).toBe("action budget exhausted");
    rmSync(dir, { recursive: true, force: true });
  });

  it("navigation outside the mission's domain scope is a hard deny (egress gate already enforces this for unattended runs)", async () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(dir, pub);
    const granted = grantMission(dir, priv, baseMissionGrant());
    const actor = fakeActor();
    const rm = new RunManager(
      actor as any, fakeBridge() as any, fakeAudit() as any, fakeQuarantine(), () => 0,
      undefined, undefined, missionStore
    );
    const { run_id } = rm.beginMission(granted.id) as any;
    const r = await rm.navigate(run_id, "https://attacker.example.com");
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("domain not allowlisted: attacker.example.com");
    expect(actor.calls.length).toBe(0);
    rmSync(dir, { recursive: true, force: true });
  });

  it("3 consecutive out-of-scope denials trip the switch, killing the run", async () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(dir, pub);
    const granted = grantMission(dir, priv, baseMissionGrant());
    const actor = fakeActor(); const audit = fakeAudit();
    const rm = new RunManager(
      actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0,
      undefined, undefined, missionStore
    );
    const { run_id } = rm.beginMission(granted.id) as any;

    for (let i = 0; i < 3; i++) {
      const r = await rm.navigate(run_id, "https://attacker.example.com");
      expect(r.ok).toBe(false);
    }
    expect(audit.recs.filter((r: any) => r.policy_decision === "tripwire").length).toBe(1);

    // The run is now killed - even an IN-scope action is refused, actor never reached.
    const after = await rm.navigate(run_id, "https://good.example.com");
    expect(after.ok).toBe(false);
    expect(actor.calls.length).toBe(0);
    rmSync(dir, { recursive: true, force: true });
  });

  it("an intervening allowed action resets the consecutive-denial counter (2 denials + 1 allow + 2 denials does not trip)", async () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(dir, pub);
    const granted = grantMission(dir, priv, baseMissionGrant());
    const actor = fakeActor(); const audit = fakeAudit();
    const rm = new RunManager(
      actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0,
      undefined, undefined, missionStore
    );
    const { run_id } = rm.beginMission(granted.id) as any;

    await rm.navigate(run_id, "https://attacker.example.com"); // deny 1
    await rm.navigate(run_id, "https://attacker.example.com"); // deny 2
    const ok = await rm.navigate(run_id, "https://good.example.com"); // allow - resets counter
    expect(ok.ok).toBe(true);
    await rm.navigate(run_id, "https://attacker.example.com"); // deny 1 again
    await rm.navigate(run_id, "https://attacker.example.com"); // deny 2 again
    expect(audit.recs.some((r: any) => r.policy_decision === "tripwire")).toBe(false);

    const stillWorks = await rm.navigate(run_id, "https://good.example.com");
    expect(stillWorks.ok).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  });
});
