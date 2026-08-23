import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RunManager, type ActorLike, type BridgeReader, type AuditSink } from "../src/run_manager.js";
import { fileApprovalStore, grantApproval } from "../src/approvals.js";
import type { CredentialStore } from "../src/credential_store.js";
import type { Policy } from "../src/policy.js";

// Regression tests for the approval single-use race: gate 3's store.find() and the post-success
// store.consume() were separated by an AWAITED actor call, so two concurrent credential ops both
// passed gate 3 on one approval, and the loser's consume() returning false was silently ignored.
// One human approval must authorise EXACTLY one browser-touching op - proven here by launching
// two ops in parallel and requiring exactly one ok:true.

// Planted sentinel: must never leak into a result or audit record on any path below.
const SENTINEL_PASSWORD = "S3ntinel-Concurrent-Do-Not-Leak";

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "concurrent-approval-"));
}

// The live tab url is origin binding's source of truth (RunManager.bindLiveOrigin).
let TAB_URL: string | undefined;
const fakeBridge = (): BridgeReader => ({ read: async () => ({ url: TAB_URL, elements: [] }) });

function fakeAudit() {
  const recs: Record<string, unknown>[] = [];
  const audit: AuditSink = { append: (r) => recs.push(r as unknown as Record<string, unknown>) };
  return { recs, audit };
}

function fakeCredentialStore(): CredentialStore {
  return { read: () => ({ username: "alice", password: SENTINEL_PASSWORD }) };
}

// Actor whose browser-touching call takes a real asynchronous detour (a timer yield), giving a
// deterministic interleaving window wide enough for a second concurrent call to pass every gate
// while the first is still in flight - exactly the shape of the live race.
function slowActor(): ActorLike {
  const calls: string[] = [];
  const slow = () => new Promise<void>((r) => setTimeout(r, 25));
  return {
    navigate: async (u: string) => { TAB_URL = u; return { ok: true }; },
    click: async () => ({ ok: true }),
    scroll: async () => ({ ok: true }),
    submit: async () => ({ ok: true }),
    credentialFill: async () => { calls.push("fill"); await slow(); return { ok: true, filled: true }; },
    type: async () => { calls.push("type"); await slow(); return { ok: true, verified: true }; }
  };
}

const basePolicy: Policy = {
  domains_allow: ["example.com"],
  actions_allow: ["NAVIGATE", "CREDENTIAL_FILL", "CREDENTIAL_USE"],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 },
  credential_sites: ["example.com"]
};

describe("concurrent credential ops share exactly one single-use approval", () => {
  it("two parallel credentialFill calls: exactly one ok:true and one denied", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_FILL");
    const store = fileApprovalStore(dir);
    const rm = new RunManager(slowActor(), fakeBridge(), fakeAudit().audit, undefined, () => Date.now(), store);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const [a, b] = await Promise.all([
      rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" }),
      rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" })
    ]);

    const oks = [a, b].filter((r) => r.ok);
    expect(oks).toHaveLength(1);
    expect(a.ok).toBe(true); // first caller wins; ordering below pins which
    expect(b.ok).toBe(false);
    if (!b.ok) expect(b.reason).toBeDefined();

    // The winner spent the approval; it must not be findable again.
    expect(store.find("example.com", Date.now(), "CREDENTIAL_FILL")).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("two parallel credentialUse calls: exactly one ok:true and one denied", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(dir);
    const rm = new RunManager(
      slowActor(), fakeBridge(), fakeAudit().audit, undefined, () => Date.now(),
      store, fakeCredentialStore()
    );
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const [a, b] = await Promise.all([
      rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" }),
      rm.credentialUse(run_id, "example.com", { name: "Password", role: "edit" })
    ]);

    const oks = [a, b].filter((r) => r.ok);
    expect(oks).toHaveLength(1);
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(false);
    // The plaintext password never reaches any result surface.
    expect(JSON.stringify([a, b])).not.toContain(SENTINEL_PASSWORD);
    expect(store.find("example.com", Date.now(), "CREDENTIAL_USE")).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  // Rollback semantics: a reservation held during an attempt that did NOT reach a successful
  // fill must be released again, so the human's single-use grant survives a failed browser op
  // (the same observable behaviour the pre-reserve code had for failed fills).
  it("a failed fill releases its reservation - a retry can still use the same approval", async () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000, "CREDENTIAL_FILL");
    const store = fileApprovalStore(dir);
    const calls: string[] = [];
    let failFirst = true;
    const flakyActor: ActorLike = {
      navigate: async (u: string) => { TAB_URL = u; return { ok: true }; },
      click: async () => ({ ok: true }),
      scroll: async () => ({ ok: true }),
      submit: async () => ({ ok: true }),
      credentialFill: async () => {
        calls.push("fill");
        await new Promise<void>((r) => setTimeout(r, 10));
        if (failFirst) { failFirst = false; return { ok: false, filled: false }; }
        return { ok: true, filled: true };
      },
      type: async () => ({ ok: true })
    };
    const rm = new RunManager(flakyActor, fakeBridge(), fakeAudit().audit, undefined, () => Date.now(), store);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example.com");

    const first = await rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" });
    expect(first.ok).toBe(false);

    // The approval survived the failed attempt and still authorises the retry.
    const second = await rm.credentialFill(run_id, "example.com", { name: "Password", role: "edit" });
    expect(second.ok).toBe(true);
    expect(calls).toEqual(["fill", "fill"]);
    expect(store.find("example.com", Date.now(), "CREDENTIAL_FILL")).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });
});
