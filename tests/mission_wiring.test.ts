// Task 34 (Phase 4): the mission-aware status view (RunManager.missionStatus) plus the MCP-level
// wiring for comet_begin_mission and comet_mission_status - see
// docs/plans/2026-08-14-comet-agent-phase4-unattended.md Task 34. scripts/mission.mjs and
// scripts/kill.mjs are the human's out-of-band CLI paths and are not covered here (same as
// scripts/approve.mjs - no vitest coverage for CLI scripts in this repo; they are exercised by
// hand against dist/, matching every other scripts/*.mjs in this project).
import { describe, it, expect, afterEach } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { build_mcp_server } from "../src/mcp_server.js";
import { RunManager, type ActorLike, type BridgeReader, type AuditSink } from "../src/run_manager.js";
import { fileMissionStore, grantMission, type Mission } from "../src/missions.js";
import type { QuarantineClient } from "../src/quarantine.js";
import type { Policy } from "../src/policy.js";

function keys() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    pub: publicKey.export({ type: "spki", format: "pem" }).toString()
  };
}

const dirs: string[] = [];
function trackedDir(prefix = "mission-wiring-"): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}
afterEach(() => {
  while (dirs.length) {
    rmSync(dirs.pop()!, { recursive: true, force: true });
  }
});

function fakeActor(): ActorLike {
  return {
    navigate: async () => ({ ok: true }),
    click: async () => ({ ok: true, verified: true }),
    type: async () => ({ ok: true, verified: true }),
    scroll: async () => ({ ok: true }),
    credentialFill: async () => ({ ok: true, filled: true }),
    submit: async () => ({ ok: true, verified: true })
  };
}
function fakeBridge(): BridgeReader {
  return { read: async () => ({ url: "https://clienta.example.com", elements: [], content: "" }) };
}
function fakeAudit(): AuditSink {
  return { append: () => {} };
}
function fakeQuarantine(): QuarantineClient {
  return { complete: async () => JSON.stringify({ code: "" }) };
}

function clientAMissionGrant(overrides?: Partial<Omit<Mission, "id" | "used">>): Omit<Mission, "id" | "used"> {
  return {
    scope: {
      domains_allow: ["clienta.example.com"],
      credential_sites: [],
      actions_allow: ["NAVIGATE"],
      account: "client-a"
    },
    budgets: { max_actions: 50, max_ms: 600_000, max_domains: 5 },
    preauthorized_irreversible: ["delete"],
    expires_ms: Date.now() + 60_000,
    ...overrides
  };
}

const basePolicy: Policy = {
  domains_allow: ["example.com"],
  actions_allow: ["NAVIGATE"],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 }
};

describe("RunManager.missionStatus", () => {
  it("returns null for an unknown run_id", () => {
    const rm = new RunManager(fakeActor(), fakeBridge(), fakeAudit(), fakeQuarantine(), () => 0);
    expect(rm.missionStatus("no-such-run")).toBeNull();
  });

  it("reports an ordinary attended run as not unattended, with no mission id/account, not killed", () => {
    const rm = new RunManager(fakeActor(), fakeBridge(), fakeAudit(), fakeQuarantine(), () => 1000);
    const { run_id } = rm.begin(basePolicy);
    const s = rm.missionStatus(run_id)!;
    expect(s.unattended).toBe(false);
    expect(s.mission_id).toBeUndefined();
    expect(s.account).toBeUndefined();
    expect(s.killed).toBe(false);
    expect(s.consecutive_denials).toBe(0);
    expect(s.preauthorized_irreversible).toEqual([]);
    expect(s.actions_used).toBe(0);
    expect(s.max_actions).toBe(50);
    expect(s.domains_used).toEqual([]);
    expect(s.max_domains).toBe(5);
    expect(s.started_ms).toBe(1000);
    expect(s.max_ms).toBe(300_000);
  });

  it("reports an unattended run's mission id, account, and pre-authorized irreversible tags", () => {
    const dir = trackedDir("missions-");
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(dir, pub);
    const granted = grantMission(dir, priv, clientAMissionGrant());
    const rm = new RunManager(
      fakeActor(), fakeBridge(), fakeAudit(), fakeQuarantine(), () => 0,
      undefined, undefined, missionStore
    );
    const { run_id } = rm.beginMission(granted.id) as { run_id: string };
    const s = rm.missionStatus(run_id)!;
    expect(s.unattended).toBe(true);
    expect(s.mission_id).toBe(granted.id);
    expect(s.account).toBe("client-a");
    expect(s.killed).toBe(false);
    expect(s.preauthorized_irreversible).toEqual(["delete"]);
  });

  it("reflects the global KILL file live, even before any action has latched run.killed", () => {
    const missionsDir = trackedDir("missions-");
    const dataDir = trackedDir("data-");
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(missionsDir, pub);
    const granted = grantMission(missionsDir, priv, clientAMissionGrant());
    const rm = new RunManager(
      fakeActor(), fakeBridge(), fakeAudit(), fakeQuarantine(), () => 0,
      undefined, undefined, missionStore, dataDir
    );
    const { run_id } = rm.beginMission(granted.id) as { run_id: string };
    expect(rm.missionStatus(run_id)!.killed).toBe(false);

    writeFileSync(join(dataDir, "KILL"), "");
    expect(rm.missionStatus(run_id)!.killed).toBe(true);
  });

  it("reflects the tripwire's consecutive-denial count and the resulting kill", async () => {
    const dir = trackedDir("missions-");
    const { priv, pub } = keys();
    const missionStore = fileMissionStore(dir, pub);
    const granted = grantMission(dir, priv, clientAMissionGrant());
    const rm = new RunManager(
      fakeActor(), fakeBridge(), fakeAudit(), fakeQuarantine(), () => 0,
      undefined, undefined, missionStore
    );
    const { run_id } = rm.beginMission(granted.id) as { run_id: string };

    for (let i = 0; i < 3; i++) {
      await rm.navigate(run_id, "https://clientb.example.com"); // out of scope
    }
    const s = rm.missionStatus(run_id)!;
    expect(s.consecutive_denials).toBeGreaterThanOrEqual(3);
    expect(s.killed).toBe(true);
  });
});

// MCP-level wiring: comet_begin_mission dispatches to RunManager.beginMission with mission_id;
// comet_mission_status dispatches to RunManager.missionStatus with run_id. Fakes, not the real
// RunManager, matching tests/twofa_extract.test.ts's "Phase 4 Task 32 MCP wiring" pattern.
const fakeDriver = () => ({ ask: async () => ({ answer: "", sources: [] }) });

function fakeRunManager() {
  const calls: { method: string; args: unknown[] }[] = [];
  const rm = {
    begin: (policy: unknown) => { calls.push({ method: "begin", args: [policy] }); return { run_id: "run_1" }; },
    beginMission: (missionId: string) => { calls.push({ method: "beginMission", args: [missionId] }); return { run_id: "run_1" }; },
    missionStatus: (runId: string) => {
      calls.push({ method: "missionStatus", args: [runId] });
      return { unattended: true, mission_id: "m1", account: "client-a", killed: false, consecutive_denials: 0, preauthorized_irreversible: [], actions_used: 0, max_actions: 50, domains_used: [], max_domains: 5, started_ms: 0, max_ms: 300000 };
    },
    status: (...args: unknown[]) => { calls.push({ method: "status", args }); return null; }
  };
  return { rm: rm as unknown as RunManager, calls };
}

async function connected(rm: RunManager) {
  const server = build_mcp_server(fakeDriver() as any, rm);
  const client = new Client({ name: "test-client", version: "0.0.1" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, server };
}

describe("Phase 4 Task 34 MCP wiring", () => {
  it("lists comet_begin_mission and comet_mission_status as tools", async () => {
    const { rm } = fakeRunManager();
    const { client } = await connected(rm);
    const { tools } = await client.listTools();
    const names = tools.map(t => t.name);
    expect(names).toContain("comet_begin_mission");
    expect(names).toContain("comet_mission_status");
  });

  it("comet_begin_mission dispatches to RunManager.beginMission with mission_id and returns its result verbatim", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    const result = await client.callTool({
      name: "comet_begin_mission",
      arguments: { mission_id: "mission-abc" }
    });
    const call = calls.find(c => c.method === "beginMission");
    expect(call).toBeDefined();
    expect(call!.args).toEqual(["mission-abc"]);
    const content = (result as any).content;
    const parsed = JSON.parse(content[0].text);
    expect(parsed).toEqual({ run_id: "run_1" });
  });

  it("comet_mission_status dispatches to RunManager.missionStatus with run_id and returns its result verbatim", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    const result = await client.callTool({
      name: "comet_mission_status",
      arguments: { run_id: "run_1" }
    });
    const call = calls.find(c => c.method === "missionStatus");
    expect(call).toBeDefined();
    expect(call!.args).toEqual(["run_1"]);
    const content = (result as any).content;
    const parsed = JSON.parse(content[0].text);
    expect(parsed.unattended).toBe(true);
    expect(parsed.mission_id).toBe("m1");
    expect(parsed.account).toBe("client-a");
  });
});
