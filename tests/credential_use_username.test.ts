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

// A real vault can hold SEVERAL logins for one origin (live: accounts.google.com has 3). The
// store's read() fails closed on that ambiguity unless a username disambiguates - but the MCP
// surface never carried one, so a multi-account site was structurally unusable via
// comet_credential_use. These tests thread `username` through tool -> RunManager -> store.

const SENTINEL_PASSWORD = "S3ntinel-Do-Not-Leak-7c22";
const CLIENT_USER = "client-agi@gmail.com";

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "creduser-"));
}

function fakeActor() {
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

// Faithful to CredentialStore.read's contract: several rows for one origin resolve only via
// username; a bare read of an ambiguous origin returns null rather than guessing.
function multiAccountStore(): CredentialStore {
  const rows: Record<string, Array<{ username: string; password: string }>> = {
    "accounts.google.com": [
      { username: "other@gmail.com", password: "pw-other" },
      { username: CLIENT_USER, password: SENTINEL_PASSWORD }
    ]
  };
  return {
    read: (origin: string, username?: string) => {
      const candidates = rows[origin] ?? [];
      if (username !== undefined) return candidates.find((r) => r.username === username) ?? null;
      return candidates.length === 1 ? candidates[0]! : null;
    }
  };
}

const googlePolicy: Policy = {
  domains_allow: ["accounts.google.com"],
  actions_allow: ["NAVIGATE", "CREDENTIAL_USE"],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 },
  credential_sites: ["accounts.google.com"]
};

function wiredRm(dir: string) {
  grantApproval(dir, "accounts.google.com", 60_000, "CREDENTIAL_USE");
  const store = fileApprovalStore(dir);
  const { actor, calls } = fakeActor();
  const { recs, audit } = fakeAudit();
  const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, multiAccountStore());
  return { rm, calls, recs };
}

describe("RunManager.credentialUse with username disambiguation", () => {
  it("resolves a multi-account site when the exact username is given and types that row's password", async () => {
    const dir = freshDir();
    const { rm, calls, recs } = wiredRm(dir);
    const { run_id } = rm.begin(googlePolicy);
    await rm.navigate(run_id, "https://accounts.google.com");

    const r = await rm.credentialUse(run_id, "accounts.google.com", { name: "Password", role: "edit" }, CLIENT_USER);

    expect(r.ok).toBe(true);
    expect(r.result).toEqual({ used: true });
    expect(calls.filter((c) => c.method === "type")).toEqual([
      { method: "type", args: [SENTINEL_PASSWORD, { name: "Password", role: "edit" }] }
    ]);
    // no-plaintext invariant holds with the new parameter in play
    expect(JSON.stringify(r)).not.toContain(SENTINEL_PASSWORD);
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
    rmSync(dir, { recursive: true, force: true });
  });

  it("still fails closed on an ambiguous site when no username is given", async () => {
    const dir = freshDir();
    const { rm, calls } = wiredRm(dir);
    const { run_id } = rm.begin(googlePolicy);
    await rm.navigate(run_id, "https://accounts.google.com");

    const r = await rm.credentialUse(run_id, "accounts.google.com", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(calls.some((c) => c.method === "type")).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("audits WHICH account was used (site + username in the target), never the password", async () => {
    const dir = freshDir();
    const { rm, recs } = wiredRm(dir);
    const { run_id } = rm.begin(googlePolicy);
    await rm.navigate(run_id, "https://accounts.google.com");

    await rm.credentialUse(run_id, "accounts.google.com", { name: "Password" }, CLIENT_USER);

    const credRecs = recs.filter((rec) => rec.action === "CREDENTIAL_USE" && rec.policy_decision === "allow");
    expect(credRecs.length).toBeGreaterThan(0);
    expect(JSON.stringify(credRecs)).toContain(CLIENT_USER);
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("comet_credential_use MCP wiring for username", () => {
  it("forwards username to RunManager.credentialUse", async () => {
    const calls: { method: string; args: unknown[] }[] = [];
    const rm = {
      credentialUse: async (...args: unknown[]) => { calls.push({ method: "credentialUse", args }); return { ok: true, result: { used: true } }; }
    } as unknown as RunManager;
    const server = build_mcp_server({ ask: async () => ({ answer: "", sources: [] }) } as any, rm);
    const client = new Client({ name: "test-client", version: "0.0.1" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    await client.callTool({
      name: "comet_credential_use",
      arguments: { run_id: "run_1", site: "accounts.google.com", name: "Password", role: "edit", username: CLIENT_USER }
    });

    const call = calls.find((c) => c.method === "credentialUse");
    expect(call).toBeDefined();
    expect(call!.args).toEqual(["run_1", "accounts.google.com", { name: "Password", role: "edit" }, CLIENT_USER]);
  });
});
