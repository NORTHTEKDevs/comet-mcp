import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { build_mcp_server } from "../src/mcp_server.js";
import { RunManager, type ActorLike, type BridgeReader, type AuditSink } from "../src/run_manager.js";
import { fileApprovalStore, grantApproval } from "../src/approvals.js";
import type { CredentialStore } from "../src/credential_store.js";
import type { Policy } from "../src/policy.js";

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "creduse-"));
}

// Planted sentinel (Task 27-style discipline applied here too): must never appear in a result or
// an audit record, on any path through this file.
const SENTINEL_PASSWORD = "S3ntinel-Do-Not-Leak-9f31";

function fakeActor(typeImpl?: (text: string, el: unknown) => Promise<{ ok: boolean; verified?: boolean }>) {
  const calls: Array<{ method: string; args: unknown[] }> = [];
  const actor: ActorLike = {
    navigate: async (u: string) => { calls.push({ method: "navigate", args: [u] }); return { ok: true }; },
    click: async (el) => { calls.push({ method: "click", args: [el] }); return { ok: true }; },
    type: async (t, el) => {
      calls.push({ method: "type", args: [t, el] });
      return typeImpl ? typeImpl(t, el) : { ok: true, verified: true };
    },
    scroll: async (d, amount) => { calls.push({ method: "scroll", args: [d, amount] }); return { ok: true }; },
    credentialFill: async (el) => { calls.push({ method: "credentialFill", args: [el] }); return { ok: true, filled: true }; }
  };
  return { actor, calls };
}

const fakeBridge = (): BridgeReader => ({ read: async () => ({ elements: [] }) });

function fakeAudit() {
  const recs: Record<string, unknown>[] = [];
  const audit: AuditSink = { append: (r) => recs.push(r as unknown as Record<string, unknown>) };
  return { recs, audit };
}

function fakeCredentialStore(map: Record<string, { username: string; password: string }>): CredentialStore {
  return { read: (origin) => map[origin] ?? null };
}

const basePolicy: Policy = {
  domains_allow: ["example.com", "other.com"],
  actions_allow: ["NAVIGATE", "CREDENTIAL_USE"],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 },
  credential_sites: ["example.com"]
};

describe("RunManager.credentialUse", () => {
  it("happy path: types the real password directly and returns/audits only a boolean", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const { actor, calls } = fakeActor();
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(true);
    expect(r.result).toEqual({ used: true });
    expect(calls.filter(c => c.method === "type")).toEqual([
      { method: "type", args: [SENTINEL_PASSWORD, { name: "Password", role: "edit" }] }
    ]);

    // no-plaintext invariant: the sentinel never appears in the return value or any audit record
    expect(JSON.stringify(r)).not.toContain(SENTINEL_PASSWORD);
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
    expect(recs.at(-1)!.policy_decision).toBe("allow");

    // approval consumed exactly once
    expect(store.find("example.com", 0, "CREDENTIAL_USE")).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("denied when CREDENTIAL_USE is not in the run's actions_allow; actor never called", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const { actor, calls } = fakeActor();
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin({ ...basePolicy, actions_allow: ["NAVIGATE"] });
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(calls.some(c => c.method === "type")).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 1: denied when the site is not in policy.credential_sites; actor never called", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const { actor, calls } = fakeActor();
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin({ ...basePolicy, credential_sites: ["other.com"] });
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(calls.some(c => c.method === "type")).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(recs.at(-1)!.reason).toMatch(/not authorised/);
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 2: denied when the current page origin does not match the site; actor never called", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const { actor, calls } = fakeActor();
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://other.com"); // allowlisted, but not the credential site

    const r = await rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(calls.some(c => c.method === "type")).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(recs.at(-1)!.reason).toMatch(/origin/);
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 3: denied with no approval at all; actor never called", async () => {
    const dir = freshDir(); // no grantApproval call
    const store = fileApprovalStore(dir);
    const { actor, calls } = fakeActor();
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(calls.some(c => c.method === "type")).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(recs.at(-1)!.reason).toBe("no valid approval");
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 3 (approval-type binding): a CREDENTIAL_REVEAL-typed approval does NOT satisfy a use; actor never called", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(dir);
    const { actor, calls } = fakeActor();
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(calls.some(c => c.method === "type")).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(recs.at(-1)!.reason).toBe("no valid approval");
    // the reveal approval must still be there afterwards - a use attempt must never burn it
    expect(store.find("example.com", 0, "CREDENTIAL_REVEAL")).not.toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 5: denied when the vault has no credential for the site, even with a valid approval; actor never called", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const { actor, calls } = fakeActor();
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({}); // vault has nothing for example.com
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(calls.some(c => c.method === "type")).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(recs.at(-1)!.reason).toBe("no stored credential for site");
    // the approval survives an attempt that never reached the actor
    expect(store.find("example.com", 0, "CREDENTIAL_USE")).not.toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("with no credential store wired at all, fails closed the same as an empty vault", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const { actor, calls } = fakeActor();
    const { recs, audit } = fakeAudit();
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store); // no credentialStore arg
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(calls.some(c => c.method === "type")).toBe(false);
    expect(recs.at(-1)!.reason).toBe("no stored credential for site");
    rmSync(dir, { recursive: true, force: true });
  });

  it("a failed type does NOT consume the approval", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const { actor } = fakeActor(async () => ({ ok: false }));
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(store.find("example.com", 0, "CREDENTIAL_USE")).not.toBeNull();
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
    rmSync(dir, { recursive: true, force: true });
  });

  it("resolves a fixed, sanitized denial (never rethrows the actor's raw error) when the actor throws after all gates passed, and the approval survives", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const { actor } = fakeActor(async () => { throw new Error("ghost IPC timeout"); });
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");
    expect(recs.length).toBe(1); // just the navigate record so far

    const r = await rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(r.reason).toBe("credential use failed");
    expect(JSON.stringify(r)).not.toContain("ghost IPC timeout");

    expect(recs.length).toBe(2);
    const rec = recs.at(-1)!;
    expect(rec.action).toBe("CREDENTIAL_USE");
    expect(rec.target).toBe("example.com");
    expect(rec.policy_decision).toBe("error");
    expect(rec.reason).not.toContain("ghost IPC timeout");
    expect(store.find("example.com", 0, "CREDENTIAL_USE")).not.toBeNull();
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
    rmSync(dir, { recursive: true, force: true });
  });

  // Regression test for the blocking review finding on Task 24: unlike credentialFill's actor
  // call (name/role only), credentialUse's actor.type() call is passed the REAL plaintext
  // password as an argument. A real `type` implementation that fails on the password field could
  // echo the value it was asked to type into its thrown error's message - exactly like Ghost's
  // already-observed locator-echoing failures. This fake actor models that: it throws an error
  // whose MESSAGE contains the sentinel password, the same way a real echoing failure would. The
  // fix must ensure the sentinel never reaches the caller via the resolved ActionResult (or, were
  // it to reject, via the rejection) - the whole point of catching instead of letting a bare
  // try/finally rethrow unmodified.
  it("never surfaces the plaintext password even when the actor's own thrown error echoes it back", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const { actor } = fakeActor(async (text) => { throw new Error(`could not set field value to "${text}"`); });
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    let rejectedValue: unknown;
    let r: Awaited<ReturnType<typeof rm.credentialUse>> | undefined;
    try {
      r = await rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" });
    } catch (err) {
      rejectedValue = err;
    }

    // Whichever surface the implementation uses (resolve or reject), the sentinel must not be
    // reachable through it.
    if (rejectedValue !== undefined) {
      expect(String((rejectedValue as Error).message ?? rejectedValue)).not.toContain(SENTINEL_PASSWORD);
    }
    if (r !== undefined) {
      expect(r.ok).toBe(false);
      expect(JSON.stringify(r)).not.toContain(SENTINEL_PASSWORD);
    }
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
    // the approval must survive an attempt that never reached a successful type
    expect(store.find("example.com", 0, "CREDENTIAL_USE")).not.toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("act(kind:'CREDENTIAL_USE') on the generic path is refused, never reaches the actor, and audits an honest deny", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const { actor, calls } = fakeActor();
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.act(run_id, { kind: "CREDENTIAL_USE" as never, name: "Password" });

    expect(r.ok).toBe(false);
    expect(calls.some(c => c.method === "type")).toBe(false);
    const credRecs = recs.filter(rec => rec.action === "CREDENTIAL_USE");
    expect(credRecs).toHaveLength(1);
    expect(credRecs[0]!.policy_decision).toBe("deny");
    rmSync(dir, { recursive: true, force: true });
  });
});

// MCP-level wiring: comet_session_begin accepts CREDENTIAL_USE in actions_allow, comet_act still
// rejects it as a kind, and comet_credential_use dispatches to RunManager.credentialUse.
const fakeDriver = () => ({ ask: async () => ({ answer: "", sources: [] }) });

function fakeRunManager() {
  const calls: { method: string; args: unknown[] }[] = [];
  const rm = {
    begin: (policy: unknown) => { calls.push({ method: "begin", args: [policy] }); return { run_id: "run_1" }; },
    navigate: async (...args: unknown[]) => { calls.push({ method: "navigate", args }); return { ok: true }; },
    read: async (...args: unknown[]) => { calls.push({ method: "read", args }); return { ok: true, result: {} }; },
    act: async (...args: unknown[]) => { calls.push({ method: "act", args }); return { ok: true }; },
    extract: async (...args: unknown[]) => { calls.push({ method: "extract", args }); return { ok: true, result: {} }; },
    credentialFill: async (...args: unknown[]) => { calls.push({ method: "credentialFill", args }); return { ok: true, result: { filled: true } }; },
    credentialUse: async (...args: unknown[]) => { calls.push({ method: "credentialUse", args }); return { ok: true, result: { used: true } }; },
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

describe("phase 5 credential-use MCP wiring", () => {
  it("lists comet_credential_use as a tool", async () => {
    const { rm } = fakeRunManager();
    const { client } = await connected(rm);
    const { tools } = await client.listTools();
    expect(tools.map(t => t.name)).toContain("comet_credential_use");
  });

  it("comet_session_begin's schema accepts CREDENTIAL_USE in actions_allow", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    await client.callTool({
      name: "comet_session_begin",
      arguments: { domains_allow: ["example.com"], actions_allow: ["NAVIGATE", "CREDENTIAL_USE"], credential_sites: ["example.com"] }
    });
    const begin = calls.find(c => c.method === "begin");
    expect((begin!.args[0] as any).actions_allow).toContain("CREDENTIAL_USE");
  });

  it("comet_credential_use dispatches to RunManager.credentialUse with run_id, site, and the element ref", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    const result = await client.callTool({
      name: "comet_credential_use",
      arguments: { run_id: "run_1", site: "example.com", name: "Password", role: "edit" }
    });
    const use = calls.find(c => c.method === "credentialUse");
    expect(use).toBeDefined();
    expect(use!.args).toEqual(["run_1", "example.com", { name: "Password", role: "edit" }]);
    const content = (result as any).content;
    const parsed = JSON.parse(content[0].text);
    expect(parsed).toEqual({ ok: true, result: { used: true } });
  });

  it("comet_act's kind enum still rejects CREDENTIAL_USE - the dedicated tool is the only path", async () => {
    const { rm } = fakeRunManager();
    const { client } = await connected(rm);
    await expect(
      client.callTool({ name: "comet_act", arguments: { run_id: "run_1", kind: "CREDENTIAL_USE" } })
    ).rejects.toThrow();
  });

  // End-to-end regression for the blocking finding: drive comet_credential_use through the REAL
  // RunManager (not the stub above) with an actor whose thrown error echoes the plaintext
  // password, and prove the sentinel never reaches the MCP client - closing the exact path the
  // finding traced through mcp_server.ts's uncaught rejection into the SDK's
  // `message: error.message ?? 'Internal error'` JSON-RPC error response.
  it("comet_credential_use never leaks the plaintext password through the MCP error/response surface, even when the actor's error echoes it", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const { actor } = fakeActor(async (text) => { throw new Error(`could not set field value to "${text}"`); });
    const audit = fakeAudit().audit;
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const { client } = await connected(rm);

    let rejectedMessage: string | undefined;
    let parsedResult: unknown;
    try {
      const result = await client.callTool({
        name: "comet_credential_use",
        arguments: { run_id, site: "example.com", name: "Password", role: "edit" }
      });
      const content = (result as any).content;
      parsedResult = JSON.parse(content[0].text);
    } catch (err) {
      rejectedMessage = (err as Error).message;
    }

    if (rejectedMessage !== undefined) {
      expect(rejectedMessage).not.toContain(SENTINEL_PASSWORD);
    }
    if (parsedResult !== undefined) {
      expect(JSON.stringify(parsedResult)).not.toContain(SENTINEL_PASSWORD);
    }
    rmSync(dir, { recursive: true, force: true });
  });
});
