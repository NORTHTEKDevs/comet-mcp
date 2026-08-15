import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RunManager, type ActorLike, type BridgeReader, type AuditSink } from "../src/run_manager.js";
import { fileApprovalStore, grantApproval } from "../src/approvals.js";
import type { CredentialStore } from "../src/credential_store.js";
import type { Policy } from "../src/policy.js";

// Found live 2026-08-15 driving a real client Google account: origin binding compared `site`
// against run.currentOrigin, which is ONLY assigned by a successful navigate (see navigate()).
// Any click/redirect-driven page change leaves it stale, so the run's belief about where the
// browser is silently diverges from where it actually is.
//
// Observed direction (fail-closed, merely blocking): navigate to myaccount.google.com, click
// through to an accounts.google.com re-auth page, credential_use(accounts.google.com) DENIED
// because the cached origin still said myaccount.
//
// Dangerous direction (fail-OPEN, the reason this is a security fix): navigate to an allowlisted
// site, let a click or redirect carry the tab to an attacker page, and credential_use for the
// allowlisted site would still pass the gate and TYPE THE REAL PASSWORD into whatever page is
// actually loaded. That is credential exfiltration through the one gate meant to prevent it.
//
// Fix under test: the origin gate must consult the LIVE tab url (the extension reports it on
// every read) rather than a cached value, and fail closed when it cannot be determined.

const SENTINEL_PASSWORD = "S3ntinel-Do-Not-Leak-4b81";

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "liveorigin-"));
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

// The real comet-bridge reader returns the tab's live url alongside the element map.
function bridgeOn(url: string | undefined, opts: { throws?: boolean } = {}): BridgeReader {
  return {
    read: async () => {
      if (opts.throws) throw new Error("bridge unreachable");
      return url === undefined ? { elements: [] } : { elements: [], url };
    }
  };
}

function fakeAudit() {
  const recs: Record<string, unknown>[] = [];
  const audit: AuditSink = { append: (r) => recs.push(r as unknown as Record<string, unknown>) };
  return { recs, audit };
}

const credStore = (): CredentialStore => ({
  read: (origin) => (origin === "bank.example.com" ? { username: "alice", password: SENTINEL_PASSWORD } : null)
});

const policy: Policy = {
  domains_allow: ["bank.example.com", "portal.example.com", "evil.example.com"],
  actions_allow: ["NAVIGATE", "CREDENTIAL_USE"],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 },
  credential_sites: ["bank.example.com"]
};

function harness(bridge: BridgeReader) {
  const dir = freshDir();
  grantApproval(dir, "bank.example.com", 60_000, "CREDENTIAL_USE");
  const { actor, calls } = fakeActor();
  const { recs, audit } = fakeAudit();
  const rm = new RunManager(actor, bridge, audit, undefined, () => 0, fileApprovalStore(dir), credStore());
  return { rm, calls, recs, dir };
}

describe("credential origin binding uses the LIVE tab, not the last navigate", () => {
  it("DENIES when the tab has moved off the credential site since the last navigate", async () => {
    // navigate authorises bank.example.com, then a click carries the tab to evil.example.com.
    const { rm, calls, dir } = harness(bridgeOn("https://evil.example.com/login"));
    const { run_id } = rm.begin(policy);
    await rm.navigate(run_id, "https://bank.example.com");

    const r = await rm.credentialUse(run_id, "bank.example.com", { name: "Password" });

    expect(r.ok).toBe(false);
    expect(calls.some((c) => c.method === "type")).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("ALLOWS when the tab IS on the credential site even though the last navigate was elsewhere", async () => {
    // The live mission shape: navigate to portal, click through to the site's own re-auth page.
    const { rm, calls, dir } = harness(bridgeOn("https://bank.example.com/v3/signin/challenge/pwd?x=1"));
    const { run_id } = rm.begin(policy);
    await rm.navigate(run_id, "https://portal.example.com");

    const r = await rm.credentialUse(run_id, "bank.example.com", { name: "Password" });

    expect(r.ok).toBe(true);
    expect(calls.filter((c) => c.method === "type")).toEqual([
      { method: "type", args: [SENTINEL_PASSWORD, { name: "Password" }] }
    ]);
    rmSync(dir, { recursive: true, force: true });
  });

  it("fails closed when the live url cannot be determined", async () => {
    const { rm, calls, dir } = harness(bridgeOn(undefined));
    const { run_id } = rm.begin(policy);
    await rm.navigate(run_id, "https://bank.example.com");

    const r = await rm.credentialUse(run_id, "bank.example.com", { name: "Password" });

    expect(r.ok).toBe(false);
    expect(calls.some((c) => c.method === "type")).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("fails closed when the bridge itself is unreachable", async () => {
    const { rm, calls, dir } = harness(bridgeOn("https://bank.example.com", { throws: true }));
    const { run_id } = rm.begin(policy);
    await rm.navigate(run_id, "https://bank.example.com");

    const r = await rm.credentialUse(run_id, "bank.example.com", { name: "Password" });

    expect(r.ok).toBe(false);
    expect(calls.some((c) => c.method === "type")).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });
});
