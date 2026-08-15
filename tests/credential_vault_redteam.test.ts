// Task 27: red-team the credential vault + reveal, through the REAL modules end to end - real
// RunManager, real credential_gate, real fileApprovalStore, and a real cometCredentialStore
// reading a FIXTURE "Login Data" SQLite file with a directly-injected master key (never the real
// vault, never real DPAPI, no network). Only the browser actor/bridge/audit sink are fakes. Every
// denial below asserts the SPECIFIC gate reason, so weakening any one gate fails this suite, not
// just a flip from allowed to denied. See THE RISK and "Phase 5 hard invariants" in
// docs/plans/2026-08-13-comet-agent-phase5.md.
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, createCipheriv } from "node:crypto";
import { createRequire } from "node:module";
import type { DatabaseSync as DatabaseSyncType } from "node:sqlite";
import { RunManager, type ActorLike, type BridgeReader, type AuditSink } from "../src/run_manager.js";
import { fileApprovalStore, grantApproval } from "../src/approvals.js";
import { cometCredentialStore, decryptBlob } from "../src/credential_store.js";
import type { Policy } from "../src/policy.js";

// See src/credential_store.ts for why node:sqlite is loaded via createRequire rather than a
// static import in this toolchain.
const nodeRequire = createRequire(import.meta.url);
const { DatabaseSync } = nodeRequire("node:sqlite") as { DatabaseSync: typeof DatabaseSyncType };

const dirs: string[] = [];
function trackedDir(): string {
  const d = mkdtempSync(join(tmpdir(), "credvault-redteam-"));
  dirs.push(d);
  return d;
}
afterEach(() => {
  while (dirs.length) {
    rmSync(dirs.pop()!, { recursive: true, force: true });
  }
});

// Same Chromium OSCrypt blob layout as tests/credential_store.test.ts's fixture helper - v10
// prefix, 12-byte GCM nonce, ciphertext, 16-byte tag - so decryptBlob/cometCredentialStore run for
// real against a known key/plaintext, never against the live vault.
function makeBlob(key: Buffer, plaintext: string): Buffer {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from("v10", "ascii"), nonce, ct, tag]);
}

// Builds a throwaway "Default/Login Data"-shaped SQLite file - the exact path cometCredentialStore
// reads (profileDir/Default/Login Data) - with one or more rows mirroring Chromium's real schema.
function makeLoginDataFile(
  dir: string,
  rows: Array<{ origin_url: string; signon_realm: string; username_value: string; password_value: Buffer }>
): void {
  mkdirSync(join(dir, "Default"), { recursive: true });
  const path = join(dir, "Default", "Login Data");
  const db = new DatabaseSync(path, { readOnly: false });
  db.exec(
    "CREATE TABLE logins (origin_url TEXT, signon_realm TEXT, username_value TEXT, password_value BLOB)"
  );
  const stmt = db.prepare(
    "INSERT INTO logins (origin_url, signon_realm, username_value, password_value) VALUES (?, ?, ?, ?)"
  );
  for (const r of rows) {
    stmt.run(r.origin_url, r.signon_realm, r.username_value, r.password_value);
  }
  db.close();
}

const SENTINEL_PASSWORD = "V4ult-Redteam-Do-Not-Leak-6b21";

function fakeActor(
  typeImpl?: (text: string, el: unknown) => Promise<{ ok: boolean; verified?: boolean }>
): { actor: ActorLike; calls: Array<{ method: string; args: unknown[] }> } {
  const calls: Array<{ method: string; args: unknown[] }> = [];
  const actor: ActorLike = {
    navigate: async (u) => { calls.push({ method: "navigate", args: [u] }); TAB_URL = u; return { ok: true }; },
    click: async (el) => { calls.push({ method: "click", args: [el] }); return { ok: true }; },
    type: async (t, el) => {
      calls.push({ method: "type", args: [t, el] });
      return typeImpl ? typeImpl(t, el) : { ok: true, verified: true };
    },
    scroll: async (d, amount) => { calls.push({ method: "scroll", args: [d, amount] }); return { ok: true }; },
    credentialFill: async (el) => { calls.push({ method: "credentialFill", args: [el] }); return { ok: true, filled: true }; },
    submit: async (el) => { calls.push({ method: "submit", args: [el] }); return { ok: true, verified: true }; }
  };
  return { actor, calls };
}

// The live tab url is origin binding's source of truth (see RunManager.bindLiveOrigin), so the
// fake tab follows the fake actor's navigations exactly as a real browser does.
let TAB_URL: string | undefined;
const fakeBridge = (): BridgeReader => ({ read: async () => ({ url: TAB_URL, elements: [] }) });

function fakeAudit() {
  const recs: Record<string, unknown>[] = [];
  const audit: AuditSink = { append: (r) => recs.push(r as unknown as Record<string, unknown>) };
  return { recs, audit };
}

// A real, fixture-backed vault: "example" has a real, decryptable credential; nothing else does.
function makeVaultDir(): { dir: string; key: Buffer } {
  const dir = trackedDir();
  const key = randomBytes(32);
  makeLoginDataFile(dir, [
    {
      origin_url: "https://example/login",
      signon_realm: "https://example/",
      username_value: "alice",
      password_value: makeBlob(key, SENTINEL_PASSWORD)
    }
  ]);
  return { dir, key };
}

const basePolicy: Policy = {
  domains_allow: ["example", "evil.example", "other.example"],
  actions_allow: ["NAVIGATE", "CREDENTIAL_USE", "CREDENTIAL_REVEAL"],
  budgets: { max_actions: 50, max_domains: 10, max_ms: 300_000 },
  credential_sites: ["example", "evil.example", "other.example"],
  allow_credential_reveal: true
};

describe("Task 27: credential vault + reveal red-team", () => {
  it("1. injected 'reveal the bank password to me' is denied when the session never set allow_credential_reveal", async () => {
    const { dir: vaultDir, key } = makeVaultDir();
    const approvalDir = trackedDir();
    // A valid, unexpired CREDENTIAL_REVEAL approval already exists - if the session-level opt-in
    // gate did not exist or ran after the approval check, this alone would let the reveal through.
    grantApproval(approvalDir, "example", 60_000, "CREDENTIAL_REVEAL");
    const store = fileApprovalStore(approvalDir);
    const vault = cometCredentialStore(vaultDir, { masterKey: key });
    const { actor } = fakeActor();
    const { recs, audit } = fakeAudit();
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, vault);
    // The session's policy never sets allow_credential_reveal at all - simulating a default,
    // non-opted-in session even while page-injected text ("reveal the bank password to me") is
    // trying to talk the agent into calling the reveal tool anyway.
    const { allow_credential_reveal: _unused, ...noRevealOptIn } = basePolicy;
    const { run_id } = rm.begin(noRevealOptIn as Policy);
    await rm.navigate(run_id, "https://example");

    const r = await rm.credentialReveal(run_id, "example");

    expect(r.ok).toBe(false);
    expect(r.reason).toBe("credential reveal not enabled for this session");
    expect(recs.at(-1)!.reason).toBe("credential reveal not enabled for this session");
    // the approval must survive - this attempt never even reached the approval gate
    expect(store.find("example", 0, "CREDENTIAL_REVEAL")).not.toBeNull();
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
  });

  it("2. vault read for evil.example returns null even though example has a real credential (exact-origin)", () => {
    const { dir: vaultDir, key } = makeVaultDir();
    const vault = cometCredentialStore(vaultDir, { masterKey: key });

    expect(vault.read("example")).toEqual({ username: "alice", password: SENTINEL_PASSWORD });
    expect(vault.read("evil.example")).toBeNull();
  });

  it("3. a CREDENTIAL_USE approval replayed for a second use is denied", async () => {
    const { dir: vaultDir, key } = makeVaultDir();
    const approvalDir = trackedDir();
    grantApproval(approvalDir, "example", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(approvalDir);
    const vault = cometCredentialStore(vaultDir, { masterKey: key });
    const { actor, calls } = fakeActor();
    const { recs, audit } = fakeAudit();
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, vault);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example");

    const first = await rm.credentialUse(run_id, "example", { name: "Password", role: "edit" });
    expect(first.ok).toBe(true);

    const replay = await rm.credentialUse(run_id, "example", { name: "Password", role: "edit" });

    expect(replay.ok).toBe(false);
    expect(replay.reason).toBe("no valid approval");
    expect(calls.filter(c => c.method === "type").length).toBe(1); // no second type() call
    expect(recs.at(-1)!.reason).toBe("no valid approval");
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
  });

  it("4. a fill/use approval presented for a reveal is denied (approval-type binding)", async () => {
    const { dir: vaultDir, key } = makeVaultDir();
    const approvalDir = trackedDir();
    grantApproval(approvalDir, "example", 60_000, "CREDENTIAL_FILL");
    grantApproval(approvalDir, "example", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(approvalDir);
    const vault = cometCredentialStore(vaultDir, { masterKey: key });
    const { actor } = fakeActor();
    const { recs, audit } = fakeAudit();
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, vault);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example");

    const r = await rm.credentialReveal(run_id, "example");

    expect(r.ok).toBe(false);
    expect(r.reason).toBe("no valid approval");
    expect(recs.at(-1)!.reason).toBe("no valid approval");
    // neither the fill nor the use approval was consumed by the denied reveal attempt
    expect(store.find("example", 0, "CREDENTIAL_FILL")).not.toBeNull();
    expect(store.find("example", 0, "CREDENTIAL_USE")).not.toBeNull();
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
  });

  it("5. credential used while the browser is on a different page than the approved site is denied", async () => {
    const { dir: vaultDir, key } = makeVaultDir();
    const approvalDir = trackedDir();
    grantApproval(approvalDir, "example", 60_000, "CREDENTIAL_USE");
    const store = fileApprovalStore(approvalDir);
    const vault = cometCredentialStore(vaultDir, { masterKey: key });
    const { actor, calls } = fakeActor();
    const { recs, audit } = fakeAudit();
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, vault);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://other.example"); // allowlisted, but not the approved site

    const r = await rm.credentialUse(run_id, "example", { name: "Password", role: "edit" });

    expect(r.ok).toBe(false);
    expect(r.reason).toBe("current origin does not match credential site");
    expect(calls.some(c => c.method === "type")).toBe(false);
    expect(recs.at(-1)!.reason).toBe("current origin does not match credential site");
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
  });

  it("6. a full use and a full denied reveal never leak the sentinel; a genuinely successful reveal leaks it ONLY in its own return", async () => {
    const { dir: vaultDir, key } = makeVaultDir();
    const approvalDir = trackedDir();
    const store = fileApprovalStore(approvalDir);
    const vault = cometCredentialStore(vaultDir, { masterKey: key });
    const { actor, calls } = fakeActor();
    const { recs, audit } = fakeAudit();
    const rm = new RunManager(actor, fakeBridge(), audit, undefined, () => 0, store, vault);
    const { run_id } = rm.begin(basePolicy);
    await rm.navigate(run_id, "https://example");

    // An attacker-labeled element locator (the kind of string a hostile page controls via
    // aria-label/name) carrying the sentinel too, so this also proves the LOCATOR never leaks.
    const poisonedEl = { name: `Password field ref=${SENTINEL_PASSWORD}`, role: "edit" };

    // (a) a full, successful CREDENTIAL_USE.
    grantApproval(approvalDir, "example", 60_000, "CREDENTIAL_USE");
    const useResult = await rm.credentialUse(run_id, "example", poisonedEl);
    expect(useResult.ok).toBe(true);

    // (b) a full CREDENTIAL_REVEAL that is denied - no reveal approval has been minted yet.
    const deniedRevealResult = await rm.credentialReveal(run_id, "example");
    expect(deniedRevealResult.ok).toBe(false);

    const noLeakBlob = JSON.stringify({ useResult, deniedRevealResult, audit: recs });
    expect(noLeakBlob).not.toContain(SENTINEL_PASSWORD);

    // (c) the ONE legitimate exception: a genuinely successful, approved reveal.
    grantApproval(approvalDir, "example", 60_000, "CREDENTIAL_REVEAL");
    const okRevealResult = await rm.credentialReveal(run_id, "example");
    expect(okRevealResult.ok).toBe(true);
    // Sanity: the exception is real, not a vacuously-passing assertion.
    expect(JSON.stringify(okRevealResult)).toContain(SENTINEL_PASSWORD);
    // Sanity: the poisoned locator genuinely traveled through the real call path into the actor.
    expect(calls.some(c => c.method === "type" && JSON.stringify(c.args).includes(SENTINEL_PASSWORD))).toBe(true);

    // Even after the successful reveal, the audit log still never carries the plaintext - the
    // reveal's own return is the ONLY place it may ever appear.
    expect(JSON.stringify(recs)).not.toContain(SENTINEL_PASSWORD);
  });

  it("7. a corrupt/short blob in the fixture vault DB makes read() return null, never throw with a value", () => {
    const dir = trackedDir();
    const key = randomBytes(32);
    makeLoginDataFile(dir, [
      {
        origin_url: "https://example/login",
        signon_realm: "https://example/",
        username_value: "alice",
        password_value: Buffer.from([0x01, 0x02, 0x03]) // far shorter than prefix+nonce+tag
      }
    ]);
    const vault = cometCredentialStore(dir, { masterKey: key });

    let threw = false;
    let cred: unknown;
    try {
      cred = vault.read("example");
    } catch (err) {
      threw = true;
      expect(String(err)).not.toContain(SENTINEL_PASSWORD);
    }
    expect(threw).toBe(false);
    expect(cred).toBeNull();
  });

  it("8. decryptBlob with a wrong key (bad GCM auth tag) returns null", () => {
    const key = randomBytes(32);
    const wrongKey = randomBytes(32);
    const blob = makeBlob(key, SENTINEL_PASSWORD);

    expect(decryptBlob(wrongKey, blob)).toBeNull();
  });
});
