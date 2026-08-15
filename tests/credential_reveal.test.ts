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
  return mkdtempSync(join(tmpdir(), "credreveal-"));
}

// Planted sentinel (Task 27-style discipline applied here too): must never appear in an audit
// record on any path through this file. It is EXPECTED to appear in the return value of the one
// successful reveal - that is the entire point of the tool - so tests assert its absence from
// `recs` (audit) specifically, not from every `r`.
const SENTINEL_PASSWORD = "R3veal-Do-Not-Leak-7c42";

function fakeActor(): { actor: ActorLike; calls: Array<{ method: string; args: unknown[] }> } {
  const calls: Array<{ method: string; args: unknown[] }> = [];
  const actor: ActorLike = {
    navigate: async (u: string) => { calls.push({ method: "navigate", args: [u] }); return { ok: true }; },
    click: async (el) => { calls.push({ method: "click", args: [el] }); return { ok: true }; },
    type: async (t, el) => { calls.push({ method: "type", args: [t, el] }); return { ok: true, verified: true }; },
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
  actions_allow: ["NAVIGATE", "CREDENTIAL_REVEAL"],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 },
  credential_sites: ["example.com"],
  allow_credential_reveal: true
};

describe("RunManager.credentialReveal", () => {
  it("happy path: returns the plaintext credential to the caller and audits only site+approvalId", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialReveal(run_id, "example.com");

    expect(r.ok).toBe(true);
    expect(r.result).toEqual({ credential: { username: "alice", password: SENTINEL_PASSWORD } });

    // no-plaintext-in-audit invariant: the sentinel never appears in any audit record, even
    // though it is (deliberately) present in the return value above.
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
    const last = recs.at(-1)!;
    expect(last.action).toBe("CREDENTIAL_REVEAL");
    expect(last.policy_decision).toBe("allow");
    expect(last.target).toBe("example.com");
    expect(String(last.reason)).toMatch(/approval=/);

    // approval consumed exactly once
    expect(store.find("example.com", 0, "CREDENTIAL_REVEAL")).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("denied when CREDENTIAL_REVEAL is not in the run's actions_allow; store never read", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    let readCalled = false;
    const credentialStore: CredentialStore = { read: (o) => { readCalled = true; return { username: "alice", password: SENTINEL_PASSWORD }; } };
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin({ ...basePolicy, actions_allow: ["NAVIGATE"] });
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialReveal(run_id, "example.com");

    expect(r.ok).toBe(false);
    expect(readCalled).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(String(recs.at(-1)!.reason)).toMatch(/not in actions_allow/);
    rmSync(dir, { recursive: true, force: true });
  });

  it("denied when allow_credential_reveal is false, even with actions_allow + site + origin + a valid approval all correct", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    let readCalled = false;
    const credentialStore: CredentialStore = { read: () => { readCalled = true; return { username: "alice", password: SENTINEL_PASSWORD }; } };
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin({ ...basePolicy, allow_credential_reveal: false });
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialReveal(run_id, "example.com");

    expect(r.ok).toBe(false);
    expect(readCalled).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(recs.at(-1)!.reason).toBe("credential reveal not enabled for this session");
    // the approval must survive - this attempt never reached the approval gate
    expect(store.find("example.com", 0, "CREDENTIAL_REVEAL")).not.toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("denied when allow_credential_reveal is absent (default false)", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const { allow_credential_reveal, ...policyNoFlag } = basePolicy;
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(policyNoFlag as Policy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialReveal(run_id, "example.com");

    expect(r.ok).toBe(false);
    expect(recs.at(-1)!.reason).toBe("credential reveal not enabled for this session");
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 1: denied when the site is not in policy.credential_sites", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin({ ...basePolicy, credential_sites: ["other.com"] });
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialReveal(run_id, "example.com");

    expect(r.ok).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(recs.at(-1)!.reason).toMatch(/not authorised/);
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 2: denied when the current page origin does not match the site", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://other.com"); // allowlisted, but not the credential site

    const r = await rm.credentialReveal(run_id, "example.com");

    expect(r.ok).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(recs.at(-1)!.reason).toMatch(/origin/);
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 3: denied with no approval at all", async () => {
    const dir = freshDir(); // no grantApproval call
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialReveal(run_id, "example.com");

    expect(r.ok).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(recs.at(-1)!.reason).toBe("no valid approval");
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 3 (approval-type binding): a CREDENTIAL_FILL-typed approval does NOT satisfy a reveal", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_FILL");
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialReveal(run_id, "example.com");

    expect(r.ok).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(recs.at(-1)!.reason).toBe("no valid approval");
    // the fill approval must still be there afterwards - a reveal attempt must never burn it
    expect(store.find("example.com", 0, "CREDENTIAL_FILL")).not.toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 3 (approval-type binding): a CREDENTIAL_USE-typed approval does NOT satisfy a reveal", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialReveal(run_id, "example.com");

    expect(r.ok).toBe(false);
    expect(recs.at(-1)!.reason).toBe("no valid approval");
    expect(store.find("example.com", 0, "CREDENTIAL_USE")).not.toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("denied when the vault has no credential for the site, even with a valid approval", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({}); // vault has nothing for example.com
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialReveal(run_id, "example.com");

    expect(r.ok).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(recs.at(-1)!.reason).toBe("no stored credential for site");
    // the approval survives an attempt that never reached a successful reveal
    expect(store.find("example.com", 0, "CREDENTIAL_REVEAL")).not.toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("with no credential store wired at all, fails closed the same as an empty vault", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store); // no credentialStore arg
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.credentialReveal(run_id, "example.com");

    expect(r.ok).toBe(false);
    expect(recs.at(-1)!.reason).toBe("no stored credential for site");
    rmSync(dir, { recursive: true, force: true });
  });

  it("replay: a second reveal after the approval is consumed is denied", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    const credentialStore = fakeCredentialStore({ "example.com": { username: "alice", password: SENTINEL_PASSWORD } });
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const first = await rm.credentialReveal(run_id, "example.com");
    expect(first.ok).toBe(true);

    const second = await rm.credentialReveal(run_id, "example.com");
    expect(second.ok).toBe(false);
    expect(recs.at(-1)!.policy_decision).toBe("deny");
    expect(recs.at(-1)!.reason).toBe("no valid approval");
    // no plaintext anywhere in the audit trail across both attempts
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
    rmSync(dir, { recursive: true, force: true });
  });

  it("act(kind:'CREDENTIAL_REVEAL') on the generic path is refused, never reaches the store, and audits an honest deny", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(dir);
    const { recs, audit } = fakeAudit();
    let readCalled = false;
    const credentialStore: CredentialStore = { read: () => { readCalled = true; return { username: "alice", password: SENTINEL_PASSWORD }; } };
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const r = await rm.act(run_id, { kind: "CREDENTIAL_REVEAL" as never });

    expect(r.ok).toBe(false);
    expect(readCalled).toBe(false);
    const credRecs = recs.filter(rec => rec.action === "CREDENTIAL_REVEAL");
    expect(credRecs).toHaveLength(1);
    expect(credRecs[0]!.policy_decision).toBe("deny");
    rmSync(dir, { recursive: true, force: true });
  });
});

// MCP-level wiring: comet_session_begin accepts CREDENTIAL_REVEAL + allow_credential_reveal,
// comet_act still rejects CREDENTIAL_REVEAL as a kind, and comet_credential_reveal dispatches to
// RunManager.credentialReveal.
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
    credentialReveal: async (...args: unknown[]) => { calls.push({ method: "credentialReveal", args }); return { ok: true, result: { credential: { username: "alice", password: SENTINEL_PASSWORD } } }; },
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

describe("phase 5 credential-reveal MCP wiring", () => {
  it("lists comet_credential_reveal as a tool", async () => {
    const { rm } = fakeRunManager();
    const { client } = await connected(rm);
    const { tools } = await client.listTools();
    expect(tools.map(t => t.name)).toContain("comet_credential_reveal");
  });

  it("comet_session_begin's schema accepts CREDENTIAL_REVEAL in actions_allow and allow_credential_reveal", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    await client.callTool({
      name: "comet_session_begin",
      arguments: {
        domains_allow: ["example.com"],
        actions_allow: ["NAVIGATE", "CREDENTIAL_REVEAL"],
        credential_sites: ["example.com"],
        allow_credential_reveal: true
      }
    });
    const begin = calls.find(c => c.method === "begin");
    expect((begin!.args[0] as any).actions_allow).toContain("CREDENTIAL_REVEAL");
    expect((begin!.args[0] as any).allow_credential_reveal).toBe(true);
  });

  it("comet_session_begin omits allow_credential_reveal from the policy when not passed (stays absent, not defaulted true)", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    await client.callTool({
      name: "comet_session_begin",
      arguments: { domains_allow: ["example.com"], actions_allow: ["NAVIGATE"] }
    });
    const begin = calls.find(c => c.method === "begin");
    expect((begin!.args[0] as any).allow_credential_reveal).toBeUndefined();
  });

  it("comet_credential_reveal dispatches to RunManager.credentialReveal with run_id and site", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    const result = await client.callTool({
      name: "comet_credential_reveal",
      arguments: { run_id: "run_1", site: "example.com" }
    });
    const reveal = calls.find(c => c.method === "credentialReveal");
    expect(reveal).toBeDefined();
    expect(reveal!.args).toEqual(["run_1", "example.com"]);
    const content = (result as any).content;
    const parsed = JSON.parse(content[0].text);
    expect(parsed).toEqual({ ok: true, result: { credential: { username: "alice", password: SENTINEL_PASSWORD } } });
  });

  it("comet_act's kind enum still rejects CREDENTIAL_REVEAL - the dedicated tool is the only path", async () => {
    const { rm } = fakeRunManager();
    const { client } = await connected(rm);
    await expect(
      client.callTool({ name: "comet_act", arguments: { run_id: "run_1", kind: "CREDENTIAL_REVEAL" } })
    ).rejects.toThrow();
  });

  // End-to-end regression, mirroring the credential_use.test.ts precedent: drive
  // comet_credential_reveal through the REAL RunManager and confirm the injected-instruction
  // scenario from Task 27's spirit is denied cleanly, with no plaintext anywhere except the one
  // successful reveal's own return (not exercised on this deny path at all).
  it("comet_credential_reveal denies cleanly through the real RunManager when allow_credential_reveal is unset, and never touches the store", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(dir);
    let readCalled = false;
    const credentialStore: CredentialStore = { read: () => { readCalled = true; return { username: "alice", password: SENTINEL_PASSWORD }; } };
    const audit = fakeAudit().audit;
    const rm = new RunManager(fakeActor().actor, fakeBridge(), audit, undefined, () => 0, store, credentialStore);
    const { domains_allow, actions_allow, budgets, credential_sites } = basePolicy;
    const { run_id } = rm.begin({ domains_allow, actions_allow, budgets, credential_sites }); // no allow_credential_reveal
    await rm.navigate(run_id, "https://example.com");

    const { client } = await connected(rm);
    const result = await client.callTool({
      name: "comet_credential_reveal",
      arguments: { run_id, site: "example.com" }
    });
    const content = (result as any).content;
    const parsed = JSON.parse(content[0].text);

    expect(parsed.ok).toBe(false);
    expect(readCalled).toBe(false);
    expect(JSON.stringify(parsed)).not.toContain(SENTINEL_PASSWORD);
    rmSync(dir, { recursive: true, force: true });
  });
});
