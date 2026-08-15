import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifyAction, IRREVERSIBLE_PATTERNS } from "../src/irreversible.js";
import { RunManager } from "../src/run_manager.js";
import { fileMissionStore, grantMission, type Mission } from "../src/missions.js";
import { fileApprovalStore, grantApproval } from "../src/approvals.js";
import type { CredentialStore } from "../src/credential_store.js";
import type { Policy } from "../src/policy.js";
import type { QuarantineClient } from "../src/quarantine.js";

function keys() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    pub: publicKey.export({ type: "spki", format: "pem" }).toString()
  };
}

function freshDir(prefix = "irreversible-"): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

const fakeQuarantine = (): QuarantineClient => ({ complete: async () => "{}" });

function fakeActor() {
  const calls: string[] = [];
  return {
    calls,
    navigate: async (_u: string) => { calls.push("nav"); },
    type: async (_t: string, _el: any) => { calls.push("type"); return { ok: true, verified: true }; },
    scroll: async (_d: string, _amount?: number) => { calls.push("scroll"); return { ok: true }; },
    click: async (_el: any) => { calls.push("click"); return { ok: true, verified: true }; },
    submit: async (_el?: any) => { calls.push("submit"); return { ok: true, verified: true }; }
  };
}
const fakeBridge = () => ({
  read: async (_p?: unknown) => ({ url: "https://good.example.com", elements: [], content: "ok" })
});
function fakeAudit() {
  const recs: any[] = [];
  return { recs, append: (r: any) => recs.push(r) };
}
function fakeCredentialStore(map: Record<string, { username: string; password: string }>): CredentialStore {
  return { read: (origin) => map[origin] ?? null };
}

function baseMissionGrant(overrides?: Partial<Omit<Mission, "id" | "used">>): Omit<Mission, "id" | "used"> {
  return {
    scope: {
      domains_allow: ["good.example.com"],
      credential_sites: [],
      actions_allow: ["NAVIGATE", "READ", "CLICK"],
      account: "client-a"
    },
    budgets: { max_actions: 50, max_ms: 600_000, max_domains: 5 },
    preauthorized_irreversible: [],
    expires_ms: Date.now() + 60_000,
    ...overrides
  };
}

describe("classifyAction (Task 31)", () => {
  it("matches every pattern in the table to its own tag", () => {
    for (const { tag, patterns } of IRREVERSIBLE_PATTERNS) {
      for (const p of patterns) {
        // Build a plausible sample string from the pattern source so every listed pattern is
        // proven to actually fire, not just believed to.
        const sample = p.source.replace(/\\?\./g, " ").replace(/[()?\\]/g, "");
        expect(classifyAction("CLICK", sample, undefined), `pattern ${p} for tag ${tag}`).toBe(tag);
      }
    }
  });

  it("matches via the currentOrigin signal alone (target undefined)", () => {
    expect(classifyAction("CLICK", undefined, "checkout.example.com")).toBe("payment");
  });

  it("matches via the target signal alone (currentOrigin undefined)", () => {
    expect(classifyAction("CLICK", "Delete Account", undefined)).toBe("delete");
  });

  it("ordinary actions return null", () => {
    for (const target of ["Save", "Submit", "Cancel", "Next", "Search", "Close", "up", "down"]) {
      expect(classifyAction("CLICK", target, "app.example.com")).toBeNull();
    }
  });

  it("both signals absent returns null, never throws", () => {
    expect(classifyAction("CLICK", undefined, undefined)).toBeNull();
  });
});

describe("RunManager irreversible gate - unattended runs (Task 31)", () => {
  it("a matched action under default posture is blocked+paused+pending-written; the actor is never called", async () => {
    const missionsDir = freshDir("missions-");
    const dataDir = freshDir("data-");
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(missionsDir, pub);
    const granted = grantMission(missionsDir, priv, baseMissionGrant());
    const actor = fakeActor();
    const audit = fakeAudit();
    const rm = new RunManager(
      actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0,
      undefined, undefined, missionStore, dataDir
    );
    const { run_id } = rm.beginMission(granted.id) as any;
    await rm.navigate(run_id, "https://good.example.com");

    const result = await rm.act(run_id, { kind: "CLICK", name: "Delete Account" });

    expect(result.ok).toBe(false);
    expect((result as any).blocked).toBe(true);
    expect((result as any).needs_approval).toBe("delete");
    expect(actor.calls).toEqual(["nav"]); // click never reached the actor

    const last = audit.recs.at(-1);
    expect(last.policy_decision).toBe("blocked_pending_approval");
    expect(last.reason).toContain("delete");

    const pendingDir = join(dataDir, "pending");
    const files = readdirSync(pendingDir);
    expect(files.length).toBe(1);
    const pending = JSON.parse(readFileSync(join(pendingDir, files[0]!), "utf8"));
    expect(pending.tag).toBe("delete");
    expect(pending.run_id).toBe(run_id);

    rmSync(missionsDir, { recursive: true, force: true });
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("the SAME action with the tag pre-authorized proceeds to the actor", async () => {
    const missionsDir = freshDir("missions-");
    const dataDir = freshDir("data-");
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(missionsDir, pub);
    const granted = grantMission(missionsDir, priv, baseMissionGrant({ preauthorized_irreversible: ["delete"] }));
    const actor = fakeActor();
    const audit = fakeAudit();
    const rm = new RunManager(
      actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0,
      undefined, undefined, missionStore, dataDir
    );
    const { run_id } = rm.beginMission(granted.id) as any;
    await rm.navigate(run_id, "https://good.example.com");

    const result = await rm.act(run_id, { kind: "CLICK", name: "Delete Account" });

    expect(result.ok).toBe(true);
    expect(actor.calls).toEqual(["nav", "click"]);
    const last = audit.recs.at(-1);
    expect(last.policy_decision).toBe("allow");
    expect(last.reason).toContain("delete");
    expect(last.reason).toContain("preauthorized");

    // No pending-approval file written for a preauthorized attempt.
    const pendingDir = join(dataDir, "pending");
    let files: string[] = [];
    try { files = readdirSync(pendingDir); } catch { /* dir may not exist - also fine */ }
    expect(files.length).toBe(0);

    rmSync(missionsDir, { recursive: true, force: true });
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("a non-matching action on an unattended run is unaffected (no tag, ordinary allow)", async () => {
    const missionsDir = freshDir("missions-");
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(missionsDir, pub);
    const granted = grantMission(missionsDir, priv, baseMissionGrant());
    const actor = fakeActor();
    const rm = new RunManager(
      actor as any, fakeBridge() as any, fakeAudit() as any, fakeQuarantine(), () => 0,
      undefined, undefined, missionStore
    );
    const { run_id } = rm.beginMission(granted.id) as any;
    await rm.navigate(run_id, "https://good.example.com");

    const result = await rm.act(run_id, { kind: "CLICK", name: "Save" });
    expect(result.ok).toBe(true);
    expect(actor.calls).toEqual(["nav", "click"]);
    rmSync(missionsDir, { recursive: true, force: true });
  });

  it("attended runs are not affected - the same matched click proceeds normally", async () => {
    const actor = fakeActor();
    const audit = fakeAudit();
    const rm = new RunManager(actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0);
    const policy: Policy = {
      domains_allow: ["good.example.com"],
      actions_allow: ["NAVIGATE", "CLICK"],
      budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 }
    };
    const { run_id } = rm.begin(policy);
    await rm.navigate(run_id, "https://good.example.com");

    const result = await rm.act(run_id, { kind: "CLICK", name: "Delete Account" });

    expect(result.ok).toBe(true);
    expect(actor.calls).toEqual(["nav", "click"]);
    expect((result as any).blocked).toBeUndefined();
    const last = audit.recs.at(-1);
    expect(last.policy_decision).toBe("allow");
  });
});

describe("RunManager.credentialUse irreversible gate - unattended runs (Task 31)", () => {
  const SENTINEL_PASSWORD = "S3ntinel-Irr-Do-Not-Leak";

  function missionForCredentialUse(preauthorized: string[] = []) {
    return baseMissionGrant({
      scope: {
        domains_allow: ["good.example.com"],
        credential_sites: ["good.example.com"],
        actions_allow: ["NAVIGATE", "CREDENTIAL_USE"],
        account: "client-a"
      },
      preauthorized_irreversible: preauthorized
    });
  }

  it("a change-password-shaped credentialUse is blocked+paused under default posture; the actor is never called", async () => {
    const missionsDir = freshDir("missions-");
    const approvalsDir = freshDir("approvals-");
    const dataDir = freshDir("data-");
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(missionsDir, pub);
    const granted = grantMission(missionsDir, priv, missionForCredentialUse());
    grantApproval(approvalsDir, "good.example.com", 60_000, "CREDENTIAL_USE");
    const approvalStore = fileApprovalStore(approvalsDir);
    const credentialStore = fakeCredentialStore({ "good.example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const actor = fakeActor();
    const audit = fakeAudit();
    const rm = new RunManager(
      actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0,
      approvalStore, credentialStore, missionStore, dataDir
    );
    const { run_id } = rm.beginMission(granted.id) as any;
    await rm.navigate(run_id, "https://good.example.com");

    const result = await rm.credentialUse(run_id, "good.example.com", { name: "Change Password" });

    expect(result.ok).toBe(false);
    expect((result as any).blocked).toBe(true);
    expect((result as any).needs_approval).toBe("change-password");
    expect(actor.calls).toEqual(["nav"]); // type() never reached the actor

    const last = audit.recs.at(-1);
    expect(last.policy_decision).toBe("blocked_pending_approval");
    expect(JSON.stringify(audit.recs)).not.toContain(SENTINEL_PASSWORD);

    // the approval survives an attempt that never reached the actor
    expect(approvalStore.find("good.example.com", 0, "CREDENTIAL_USE")).not.toBeNull();

    rmSync(missionsDir, { recursive: true, force: true });
    rmSync(approvalsDir, { recursive: true, force: true });
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("the SAME credentialUse with change-password pre-authorized proceeds to the actor, still no plaintext in audit", async () => {
    const missionsDir = freshDir("missions-");
    const approvalsDir = freshDir("approvals-");
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(missionsDir, pub);
    const granted = grantMission(missionsDir, priv, missionForCredentialUse(["change-password"]));
    grantApproval(approvalsDir, "good.example.com", 60_000, "CREDENTIAL_USE");
    const approvalStore = fileApprovalStore(approvalsDir);
    const credentialStore = fakeCredentialStore({ "good.example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const actor = fakeActor();
    const audit = fakeAudit();
    const rm = new RunManager(
      actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0,
      approvalStore, credentialStore, missionStore
    );
    const { run_id } = rm.beginMission(granted.id) as any;
    await rm.navigate(run_id, "https://good.example.com");

    const result = await rm.credentialUse(run_id, "good.example.com", { name: "Change Password" });

    expect(result.ok).toBe(true);
    expect(actor.calls).toEqual(["nav", "type"]);
    expect(JSON.stringify(audit.recs)).not.toContain(SENTINEL_PASSWORD);
    const last = audit.recs.at(-1);
    expect(last.reason).toContain("change-password");

    rmSync(missionsDir, { recursive: true, force: true });
    rmSync(approvalsDir, { recursive: true, force: true });
  });
});
