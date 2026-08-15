import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { build_mcp_server } from "../src/mcp_server.js";
import { RunManager } from "../src/run_manager.js";
import { fileApprovalStore, grantApproval } from "../src/approvals.js";
import type { Policy } from "../src/policy.js";

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "credwire-"));
}

const fakeQuarantine = () => ({ complete: async () => "{}" });

function fakeActor(credentialFillImpl?: (el: unknown) => Promise<{ ok: boolean; filled: boolean }>) {
  const calls: Array<{ method: string; args: unknown[] }> = [];
  return {
    calls,
    navigate: async (u: string) => { calls.push({ method: "navigate", args: [u] }); TAB_URL = u; },
    click: async (el: unknown) => { calls.push({ method: "click", args: [el] }); return { ok: true }; },
    type: async (t: string, el: unknown) => { calls.push({ method: "type", args: [t, el] }); return { ok: true }; },
    scroll: async (d: string, amount?: number) => { calls.push({ method: "scroll", args: [d, amount] }); return { ok: true }; },
    credentialFill: async (el: unknown) => {
      calls.push({ method: "credentialFill", args: [el] });
      return credentialFillImpl ? credentialFillImpl(el) : { ok: true, filled: true };
    }
  };
}

// The live tab url is origin binding's source of truth (see RunManager.bindLiveOrigin), so the
// fake tab follows the fake actor's navigations exactly as a real browser does.
let TAB_URL: string | undefined;
const fakeBridge = () => ({ read: async () => ({ url: TAB_URL, elements: [] }) });
const fakeAudit = () => { const recs: any[] = []; return { recs, append: (r: any) => recs.push(r) }; };

// Two allowlisted domains so a navigate to "other.com" (used for the origin-mismatch test) is
// itself policy-allowed - only credential_sites authorises "example.com" for a fill.
const basePolicy: Policy = {
  domains_allow: ["example.com", "other.com"],
  actions_allow: ["NAVIGATE", "CREDENTIAL_FILL"],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 },
  credential_sites: ["example.com"]
};

describe("RunManager.credentialFill", () => {
  it("is denied with no approval; actor never called", async () => {
    const dir = freshDir();
    const actor = fakeActor(); const audit = fakeAudit();
    const rm = new RunManager(actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0, fileApprovalStore(dir));
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(actor.calls.some(c => c.method === "credentialFill")).toBe(false);
    expect(audit.recs.at(-1).policy_decision).toBe("deny");
    expect(audit.recs.at(-1).reason).toBe("no valid approval");
    rmSync(dir, { recursive: true, force: true });
  });

  it("is denied when the current page origin does not match the site, even with a valid approval; actor never called", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000);
    const actor = fakeActor(); const audit = fakeAudit();
    const rm = new RunManager(actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0, fileApprovalStore(dir));
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://other.com"); // allowlisted, but not the credential site

    const r = await rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(actor.calls.some(c => c.method === "credentialFill")).toBe(false);
    expect(audit.recs.at(-1).policy_decision).toBe("deny");
    expect(audit.recs.at(-1).reason).toBe("current origin does not match credential site");
    rmSync(dir, { recursive: true, force: true });
  });

  it("allows the full happy path and consumes the approval exactly once", async () => {
    const dir = freshDir();
    const store = fileApprovalStore(dir);
    grantApproval(dir, "example.com", 60_000);
    const actor = fakeActor(); const audit = fakeAudit();
    const rm = new RunManager(actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0, store);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(true);
    expect((r.result as any).filled).toBe(true);
    expect(actor.calls.map(c => c.method)).toEqual(["navigate", "credentialFill"]);
    expect(audit.recs.at(-1).policy_decision).toBe("allow");

    // consumed: the store no longer finds a fresh approval for this site
    expect(store.find("example.com", 0)).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("denies a replay of the same approval after it was already consumed by a successful fill", async () => {
    const dir = freshDir();
    const store = fileApprovalStore(dir);
    grantApproval(dir, "example.com", 60_000);
    const actor = fakeActor(); const audit = fakeAudit();
    const rm = new RunManager(actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0, store);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const first = await rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" });
    expect(first.ok).toBe(true);

    const second = await rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" });
    expect(second.ok).toBe(false);
    expect(audit.recs.at(-1).policy_decision).toBe("deny");
    expect(audit.recs.at(-1).reason).toBe("no valid approval");
    expect(actor.calls.filter(c => c.method === "credentialFill").length).toBe(1);
    rmSync(dir, { recursive: true, force: true });
  });

  it("does NOT consume the approval when the browser-side fill fails to confirm (filled:false)", async () => {
    const dir = freshDir();
    const store = fileApprovalStore(dir);
    grantApproval(dir, "example.com", 60_000);
    const actor = fakeActor(async () => ({ ok: true, filled: false }));
    const audit = fakeAudit();
    const rm = new RunManager(actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0, store);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(true);
    expect((r.result as any).filled).toBe(false);
    // approval is still there - a failed fill did not burn the human's single-use grant
    expect(store.find("example.com", 0)).not.toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("does NOT consume the approval when the actor itself fails (ok:false)", async () => {
    const dir = freshDir();
    const store = fileApprovalStore(dir);
    grantApproval(dir, "example.com", 60_000);
    const actor = fakeActor(async () => ({ ok: false, filled: false }));
    const audit = fakeAudit();
    const rm = new RunManager(actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0, store);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(store.find("example.com", 0)).not.toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("still writes an audit record when the actor throws after all four gates already passed (the audit trail must survive an actor-level failure, e.g. a ghost IPC timeout)", async () => {
    const dir = freshDir();
    const store = fileApprovalStore(dir);
    grantApproval(dir, "example.com", 60_000);
    const actor = fakeActor(async () => { throw new Error("ghost IPC timeout"); });
    const audit = fakeAudit();
    const rm = new RunManager(actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0, store);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");
    expect(audit.recs.length).toBe(1); // just the navigate record so far

    await expect(
      rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" })
    ).rejects.toThrow("ghost IPC timeout");

    // the throw must not have erased the attempt from the tamper-evident log: exactly one new
    // record for this CREDENTIAL_FILL attempt, on top of the earlier navigate record.
    expect(audit.recs.length).toBe(2);
    const rec = audit.recs.at(-1);
    expect(rec.action).toBe("CREDENTIAL_FILL");
    expect(rec.target).toBe("example.com");
    expect(rec.policy_decision).toBe("error");
    // Task 21 red-team fix: the raw actor error message is NEVER interpolated into the audit
    // reason, because Ghost's real element-not-found error echoes the requested locator string
    // verbatim and el.name/el.role are attacker-influenceable. The reason is a fixed,
    // content-free marker instead - "an attempt errored" without becoming a second echo channel.
    expect(rec.reason).not.toContain("ghost IPC timeout");
    expect(rec.reason).toContain("error=actor error");
    // a thrown attempt never confirmed a fill, so the human's single-use approval must survive.
    expect(store.find("example.com", 0)).not.toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("the allow audit record carries the site and the approval id, and no credential value or extra keys", async () => {
    const dir = freshDir();
    const store = fileApprovalStore(dir);
    const granted = grantApproval(dir, "example.com", 60_000);
    const actor = fakeActor(); const audit = fakeAudit();
    const rm = new RunManager(actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0, store);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    await rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" });

    const rec = audit.recs.at(-1);
    expect(rec.target).toBe("example.com");
    expect(rec.reason).toContain(granted.id);
    expect(Object.keys(rec).sort()).toEqual(["action", "actor", "policy_decision", "reason", "run_id", "target", "ts"]);
    expect(JSON.stringify(audit.recs)).not.toMatch(/value/i);
    rmSync(dir, { recursive: true, force: true });
  });

  // Phase 5 Task 26: SUBMIT left policy.DANGEROUS - it is gated only by actions_allow now, same
  // as any other action kind. basePolicy (above) does not list SUBMIT, so this proves a
  // successful, approved CREDENTIAL_FILL does not implicitly unlock it.
  it("SUBMIT is refused by default (not in actions_allow) even on a run with CREDENTIAL_FILL wired and approved", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000);
    const actor = fakeActor(); const audit = fakeAudit();
    const rm = new RunManager(actor as any, fakeBridge() as any, audit as any, fakeQuarantine(), () => 0, fileApprovalStore(dir));
    const { run_id } = rm.begin(basePolicy); // SUBMIT not in actions_allow
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.act(run_id, { kind: "SUBMIT" });

    expect(r.ok).toBe(false);
    expect(audit.recs.at(-1).policy_decision).toBe("deny");
    expect(audit.recs.at(-1).reason).toBe("action SUBMIT not in actions_allow");
    expect(actor.calls.some(c => c.method === "credentialFill" || c.method === "click" || c.method === "type" || c.method === "submit")).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });
});

// MCP-level wiring: comet_session_begin accepts credential_sites and CREDENTIAL_FILL in
// actions_allow; comet_credential_fill dispatches to RunManager.credentialFill.
const fakeDriver = () => ({ ask: async () => ({ answer: "", sources: [] }) });

function fakeRunManager() {
  const calls: { method: string; args: unknown[] }[] = [];
  const rm = {
    begin: (policy: unknown) => { calls.push({ method: "begin", args: [policy] }); return { run_id: "run_1" }; },
    navigate: async (...args: unknown[]) => { calls.push({ method: "navigate", args }); return { ok: true }; },
    read: async (...args: unknown[]) => { calls.push({ method: "read", args }); return { ok: true, result: {} }; },
    act: async (...args: unknown[]) => { calls.push({ method: "act", args }); return { ok: true }; },
    extract: async (...args: unknown[]) => { calls.push({ method: "extract", args }); return { ok: true, result: {} }; },
    credentialFill: async (...args: unknown[]) => {
      calls.push({ method: "credentialFill", args });
      return { ok: true, result: { filled: true } };
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

describe("phase 3 MCP wiring", () => {
  it("lists comet_credential_fill as a tool", async () => {
    const { rm } = fakeRunManager();
    const { client } = await connected(rm);
    const { tools } = await client.listTools();
    expect(tools.map(t => t.name)).toContain("comet_credential_fill");
  });

  it("comet_session_begin's schema accepts credential_sites and passes it through to RunManager.begin", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    await client.callTool({
      name: "comet_session_begin",
      arguments: { domains_allow: ["example.com"], actions_allow: ["NAVIGATE", "CREDENTIAL_FILL"], credential_sites: ["example.com"] }
    });
    const begin = calls.find(c => c.method === "begin");
    expect((begin!.args[0] as any).credential_sites).toEqual(["example.com"]);
  });

  it("comet_session_begin omits credential_sites from the policy when not given", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    await client.callTool({
      name: "comet_session_begin",
      arguments: { domains_allow: ["example.com"], actions_allow: ["NAVIGATE"] }
    });
    const begin = calls.find(c => c.method === "begin");
    expect((begin!.args[0] as any).credential_sites).toBeUndefined();
  });

  // Phase 5 Task 26: SUBMIT is now a valid actions_allow member - opt-in only, gated by the
  // ordinary policy guard, not by the schema. See run_manager.test.ts / policy.test.ts for the
  // "still denied when not opted in" direction.
  it("comet_session_begin's schema now accepts SUBMIT in actions_allow (Phase 5 Task 26 - opt-in, not blanket-denied)", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    await client.callTool({
      name: "comet_session_begin",
      arguments: { domains_allow: ["example.com"], actions_allow: ["NAVIGATE", "SUBMIT"] }
    });
    const begin = calls.find(c => c.method === "begin");
    expect((begin!.args[0] as any).actions_allow).toContain("SUBMIT");
  });

  it("comet_credential_fill dispatches to RunManager.credentialFill with run_id, site, and the element ref", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    const result = await client.callTool({
      name: "comet_credential_fill",
      arguments: { run_id: "run_1", site: "example.com", name: "Password", role: "edit" }
    });
    const fill = calls.find(c => c.method === "credentialFill");
    expect(fill).toBeDefined();
    expect(fill!.args).toEqual(["run_1", "example.com", { name: "Password", role: "edit" }]);
    const content = (result as any).content;
    const parsed = JSON.parse(content[0].text);
    expect(parsed).toEqual({ ok: true, result: { filled: true } });
  });

  it("comet_act's kind enum still rejects CREDENTIAL_FILL - the dedicated tool is the only path", async () => {
    const { rm } = fakeRunManager();
    const { client } = await connected(rm);
    await expect(
      client.callTool({ name: "comet_act", arguments: { run_id: "run_1", kind: "CREDENTIAL_FILL" } })
    ).rejects.toThrow();
  });

  // Phase 5 Task 26: SUBMIT is now a valid comet_act kind, gated by the run's policy, not by the
  // schema - it must parse and reach RunManager.act like CLICK/TYPE/SCROLL.
  it("comet_act's kind enum now accepts SUBMIT (Phase 5 Task 26 - policy-gated, not schema-blocked)", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    await client.callTool({ name: "comet_act", arguments: { run_id: "run_1", kind: "SUBMIT" } });
    const act = calls.find(c => c.method === "act");
    expect(act).toBeDefined();
  });
});