// Task 23: fixture-only tests. NEVER touch the real Comet vault or invoke real DPAPI - every
// test here builds its own known key/plaintext/blob and its own throwaway SQLite file.
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, readdirSync, statSync, writeFileSync, existsSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, createCipheriv } from "node:crypto";
import { createRequire } from "node:module";
import type { DatabaseSync as DatabaseSyncType } from "node:sqlite";
import { decryptBlob, cometCredentialStore } from "../src/credential_store.js";

// See src/credential_store.ts for why node:sqlite is loaded via createRequire rather than a
// static import in this toolchain.
const nodeRequire = createRequire(import.meta.url);
const { DatabaseSync } = nodeRequire("node:sqlite") as { DatabaseSync: typeof DatabaseSyncType };

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "credstore-"));
}

const dirs: string[] = [];
function trackedDir(): string {
  const d = freshDir();
  dirs.push(d);
  return d;
}

afterEach(() => {
  while (dirs.length) {
    const d = dirs.pop()!;
    rmSync(d, { recursive: true, force: true });
  }
});

// Encrypts plaintext the same way Chromium's OSCrypt does (v10 prefix, 12-byte GCM nonce,
// ciphertext, 16-byte tag) so decryptBlob can be exercised without ever touching real DPAPI.
function makeBlob(key: Buffer, plaintext: string, version: "v10" | "v11" = "v10"): Buffer {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from(version, "ascii"), nonce, ct, tag]);
}

// Builds a throwaway "Login Data"-shaped SQLite file with one or more rows, mirroring the real
// Chromium `logins` table's relevant columns.
function makeLoginDataFile(
  dir: string,
  rows: Array<{ origin_url: string; signon_realm: string; username_value: string; password_value: Buffer }>
): string {
  const path = join(dir, "Login Data");
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
  return path;
}

describe("decryptBlob (pure)", () => {
  it("decrypts a valid v10 blob with the correct key", () => {
    const key = randomBytes(32);
    const blob = makeBlob(key, "hunter2");
    const out = decryptBlob(key, blob);
    expect(out?.toString("utf8")).toBe("hunter2");
  });

  it("decrypts a valid v11 blob with the correct key", () => {
    const key = randomBytes(32);
    const blob = makeBlob(key, "hunter2", "v11");
    const out = decryptBlob(key, blob);
    expect(out?.toString("utf8")).toBe("hunter2");
  });

  it("returns null (never throws) for a truncated blob", () => {
    const key = randomBytes(32);
    const blob = makeBlob(key, "hunter2").subarray(0, 10);
    expect(decryptBlob(key, blob)).toBeNull();
  });

  it("returns null for garbage bytes", () => {
    const key = randomBytes(32);
    expect(decryptBlob(key, randomBytes(40))).toBeNull();
  });

  it("returns null for an unknown version prefix", () => {
    const key = randomBytes(32);
    const blob = makeBlob(key, "hunter2");
    blob.write("v09", 0, "ascii");
    expect(decryptBlob(key, blob)).toBeNull();
  });

  it("returns null on a bad auth tag (wrong key)", () => {
    const key = randomBytes(32);
    const wrongKey = randomBytes(32);
    const blob = makeBlob(key, "hunter2");
    expect(decryptBlob(wrongKey, blob)).toBeNull();
  });
});

describe("cometCredentialStore.read", () => {
  it("returns the credential for a matching exact origin", () => {
    const dir = trackedDir();
    const key = randomBytes(32);
    mkdirSync(join(dir, "Default"), { recursive: true });
    makeLoginDataFile(join(dir, "Default"), [
      {
        origin_url: "https://example.com/login",
        signon_realm: "https://example.com/",
        username_value: "alice",
        password_value: makeBlob(key, "hunter2")
      }
    ]);
    const store = cometCredentialStore(dir, { masterKey: key });
    const cred = store.read("example.com");
    expect(cred).toEqual({ username: "alice", password: "hunter2" });
  });

  it("returns null for a non-matching origin", () => {
    const dir = trackedDir();
    const key = randomBytes(32);
    mkdirSync(join(dir, "Default"), { recursive: true });
    makeLoginDataFile(join(dir, "Default"), [
      {
        origin_url: "https://example.com/login",
        signon_realm: "https://example.com/",
        username_value: "alice",
        password_value: makeBlob(key, "hunter2")
      }
    ]);
    const store = cometCredentialStore(dir, { masterKey: key });
    expect(store.read("other.com")).toBeNull();
  });

  it("does not let a subdomain match the parent site", () => {
    const dir = trackedDir();
    const key = randomBytes(32);
    mkdirSync(join(dir, "Default"), { recursive: true });
    makeLoginDataFile(join(dir, "Default"), [
      {
        origin_url: "https://example.com/login",
        signon_realm: "https://example.com/",
        username_value: "alice",
        password_value: makeBlob(key, "hunter2")
      }
    ]);
    const store = cometCredentialStore(dir, { masterKey: key });
    expect(store.read("evil.example.com")).toBeNull();
    expect(store.read("sub.example.com")).toBeNull();
  });

  it("does not let the parent match a subdomain-only credential", () => {
    const dir = trackedDir();
    const key = randomBytes(32);
    mkdirSync(join(dir, "Default"), { recursive: true });
    makeLoginDataFile(join(dir, "Default"), [
      {
        origin_url: "https://accounts.example.com/login",
        signon_realm: "https://accounts.example.com/",
        username_value: "alice",
        password_value: makeBlob(key, "hunter2")
      }
    ]);
    const store = cometCredentialStore(dir, { masterKey: key });
    expect(store.read("example.com")).toBeNull();
  });

  it("returns null for a truncated/garbage blob in the DB (never throws)", () => {
    const dir = trackedDir();
    const key = randomBytes(32);
    mkdirSync(join(dir, "Default"), { recursive: true });
    makeLoginDataFile(join(dir, "Default"), [
      {
        origin_url: "https://example.com/login",
        signon_realm: "https://example.com/",
        username_value: "alice",
        password_value: Buffer.from("not a real blob at all")
      }
    ]);
    const store = cometCredentialStore(dir, { masterKey: key });
    expect(store.read("example.com")).toBeNull();
  });

  it("returns null on a wrong-key blob (bad auth tag) without throwing", () => {
    const dir = trackedDir();
    const key = randomBytes(32);
    const wrongKey = randomBytes(32);
    mkdirSync(join(dir, "Default"), { recursive: true });
    makeLoginDataFile(join(dir, "Default"), [
      {
        origin_url: "https://example.com/login",
        signon_realm: "https://example.com/",
        username_value: "alice",
        password_value: makeBlob(wrongKey, "hunter2")
      }
    ]);
    const store = cometCredentialStore(dir, { masterKey: key });
    expect(store.read("example.com")).toBeNull();
  });

  it("returns null and never throws a value-bearing error for a broken/missing DB path", () => {
    const dir = trackedDir();
    const key = randomBytes(32);
    // "Default\\Login Data" deliberately not created.
    const store = cometCredentialStore(dir, { masterKey: key });
    let threw = false;
    let cred: unknown;
    try {
      cred = store.read("example.com");
    } catch (err) {
      threw = true;
      const msg = String(err);
      expect(msg).not.toContain("hunter2");
    }
    expect(threw).toBe(false);
    expect(cred).toBeNull();
  });

  it("cleans up its temp copy of Login Data after a read", async () => {
    const dir = trackedDir();
    const key = randomBytes(32);
    mkdirSync(join(dir, "Default"), { recursive: true });
    makeLoginDataFile(join(dir, "Default"), [
      {
        origin_url: "https://example.com/login",
        signon_realm: "https://example.com/",
        username_value: "alice",
        password_value: makeBlob(key, "hunter2")
      }
    ]);
    const before = new Set(readdirSync(tmpdir()));
    const store = cometCredentialStore(dir, { masterKey: key });
    store.read("example.com");
    // Concurrency-tolerant assertion: the OS tmpdir is SHARED - a sibling suite (this repo keeps
    // a .worktrees copy of this exact file) can hold its own comet-login-data temp copy open
    // while this read runs, and the old strict before/after diff saw that in-flight file as
    // "left behind" by us (a flake, not a leak). Poll briefly for foreign files to disappear;
    // OUR own temp file is unlinked synchronously before read() returns, so it never appears at all.
    const loginShaped = (): string[] => {
      const now = new Set(readdirSync(tmpdir()));
      return [...now].filter(f => !before.has(f)).filter(f => f.toLowerCase().includes("login"));
    };
    let leftovers = loginShaped();
    for (let i = 0; i < 30 && leftovers.length > 0; i++) {
      await new Promise((r) => setTimeout(r, 100));
      leftovers = loginShaped();
    }
    expect(leftovers).toEqual([]);
  });

  // Crashed reads strand full vault copies as %TEMP%/comet-login-data-*.db forever. The store
  // sweeps those stale leftovers (age-gated) on construction.
  it("sweeps a stale comet-login-data temp copy left by a crashed read on construction", () => {
    const stalePath = join(tmpdir(), `comet-login-data-${randomBytes(8).toString("hex")}.db`);
    writeFileSync(stalePath, "stale leftover bytes");
    try {
      // Backdate well past the sweep's staleness threshold so a LIVE sibling read's fresh temp
      // file is never a legitimate sweep target.
      const past = new Date(Date.now() - 2 * 60 * 60 * 1000);
      utimesSync(stalePath, past, past);

      const dir = trackedDir();
      const key = randomBytes(32);
      mkdirSync(join(dir, "Default"), { recursive: true });
      makeLoginDataFile(join(dir, "Default"), [
        {
          origin_url: "https://example.com/login",
          signon_realm: "https://example.com/",
          username_value: "alice",
          password_value: makeBlob(key, "hunter2")
        }
      ]);
      cometCredentialStore(dir, { masterKey: key }); // construction performs the sweep

      expect(existsSync(stalePath)).toBe(false);
    } finally {
      rmSync(stalePath, { force: true });
    }
  });

  it("does NOT sweep a FRESH comet-login-data file that could belong to a live concurrent read", () => {
    const freshPath = join(tmpdir(), `comet-login-data-${randomBytes(8).toString("hex")}.db`);
    writeFileSync(freshPath, "in-flight copy of another process");
    try {
      const dir = trackedDir();
      const key = randomBytes(32);
      mkdirSync(join(dir, "Default"), { recursive: true });
      makeLoginDataFile(join(dir, "Default"), [
        {
          origin_url: "https://example.com/login",
          signon_realm: "https://example.com/",
          username_value: "alice",
          password_value: makeBlob(key, "hunter2")
        }
      ]);
      cometCredentialStore(dir, { masterKey: key });
      // Recent mtime -> plausibly a live concurrent reader's copy -> untouched.
      expect(existsSync(freshPath)).toBe(true);
    } finally {
      rmSync(freshPath, { force: true });
    }
  });

  it("copies Login Data before opening so the original is never mutated", () => {
    const dir = trackedDir();
    const key = randomBytes(32);
    mkdirSync(join(dir, "Default"), { recursive: true });
    const originalPath = makeLoginDataFile(join(dir, "Default"), [
      {
        origin_url: "https://example.com/login",
        signon_realm: "https://example.com/",
        username_value: "alice",
        password_value: makeBlob(key, "hunter2")
      }
    ]);
    const before = statSync(originalPath).mtimeMs;
    const store = cometCredentialStore(dir, { masterKey: key });
    store.read("example.com");
    const after = statSync(originalPath).mtimeMs;
    expect(after).toBe(before);
  });
});
