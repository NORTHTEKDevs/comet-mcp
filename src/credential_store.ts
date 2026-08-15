// Task 23 (Phase 5): reads Comet's real, plaintext credential vault. See THE RISK in
// docs/plans/2026-08-13-comet-agent-phase5.md before touching this file.
//
// decryptBlob is the pure, unit-testable core: given a key and a Chromium OSCrypt blob, decrypt
// or return null. It never throws with the blob or the plaintext in the error - it never throws
// at all; any failure (short/garbage/wrong-version/bad-auth-tag) collapses to null.
//
// unwrapMasterKey and cometCredentialStore are the production wiring: real DPAPI (via a
// PowerShell shell-out) and a real SQLite copy-then-read of "Login Data". Unit tests inject a
// known key directly into cometCredentialStore and never exercise unwrapMasterKey.
import { readFileSync, copyFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, createDecipheriv } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import type { DatabaseSync as DatabaseSyncType } from "node:sqlite";

// node:sqlite is a prefix-only Node builtin (no bare "sqlite" module exists). The Vite/Vitest
// toolchain used to run this project's tests mis-resolves a static `import ... from
// "node:sqlite"` and tries to load a nonexistent bare "sqlite" package. Going through Node's
// real CommonJS require (via createRequire) sidesteps that broken static resolution and always
// gets the actual builtin at runtime, in both the built dist/ output and under vitest.
const nodeRequire = createRequire(import.meta.url);
const { DatabaseSync } = nodeRequire("node:sqlite") as { DatabaseSync: typeof DatabaseSyncType };

export interface Credential {
  username: string;
  password: string;
}

export interface CredentialStore {
  // Returns the credential for the EXACT host `origin` names, or null if there is none. Never
  // matches a subdomain against a parent site or vice versa.
  //
  // Fails closed on AMBIGUITY: if the vault holds more than one login for that host and
  // `username` is not given to disambiguate, this returns null rather than guessing. A vault
  // routinely has several accounts per provider (an agency has many client logins on google.com),
  // and silently picking one would mean authenticating as the wrong client with no error at all.
  read(origin: string, username?: string): Credential | null;
}

const GCM_NONCE_LEN = 12;
const GCM_TAG_LEN = 16;
const PREFIX_LEN = 3;
const MIN_BLOB_LEN = PREFIX_LEN + GCM_NONCE_LEN + GCM_TAG_LEN;

// Pure: no I/O, never throws. Chromium OSCrypt layout: bytes 0-2 = "v10"|"v11", 3-14 = 12-byte
// GCM nonce, 15..len-16 = ciphertext, last 16 bytes = GCM tag.
export function decryptBlob(masterKey: Buffer, blob: Buffer): Buffer | null {
  try {
    if (!Buffer.isBuffer(blob) || blob.length < MIN_BLOB_LEN) return null;
    const version = blob.subarray(0, PREFIX_LEN).toString("ascii");
    if (version !== "v10" && version !== "v11") return null;
    const nonce = blob.subarray(PREFIX_LEN, PREFIX_LEN + GCM_NONCE_LEN);
    const tag = blob.subarray(blob.length - GCM_TAG_LEN);
    const ciphertext = blob.subarray(PREFIX_LEN + GCM_NONCE_LEN, blob.length - GCM_TAG_LEN);
    const decipher = createDecipheriv("aes-256-gcm", masterKey, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    // Malformed blob, wrong key length, or auth-tag mismatch - never surface which, and never
    // include any part of the blob/key in a thrown value. Callers get a clean null.
    return null;
  }
}

// Reads "Local State", strips the "DPAPI" prefix, and shells out to PowerShell to run the
// unwrap through Windows CryptUnprotectData (CurrentUser scope) exactly once per process. The
// wrapped key bytes are passed via stdin, never on the command line, so they never land in a
// process listing.
export function unwrapMasterKey(localStatePath: string): Buffer {
  const raw = readFileSync(localStatePath, "utf8");
  const parsed = JSON.parse(raw) as { os_crypt?: { encrypted_key?: string } };
  const encoded = parsed.os_crypt?.encrypted_key;
  if (!encoded || typeof encoded !== "string") {
    throw new Error("Local State: missing os_crypt.encrypted_key");
  }
  const encryptedKey = Buffer.from(encoded, "base64");
  const dpapiPrefix = encryptedKey.subarray(0, 5).toString("ascii");
  if (dpapiPrefix !== "DPAPI") {
    throw new Error("Local State: unexpected master key prefix");
  }
  const wrapped = encryptedKey.subarray(5);

  const script = [
    // REQUIRED. Windows PowerShell 5.1 does not load System.Security by default, so without this
    // `[System.Security.Cryptography.ProtectedData]` is an unknown type and every unwrap fails.
    // Found only by running against the real vault: all 466 unit tests inject a fixture master key
    // and never execute this function, so the entire credential feature was silently dead in
    // production while the suite stayed green.
    "Add-Type -AssemblyName System.Security",
    "$b64 = [Console]::In.ReadToEnd().Trim()",
    "$bytes = [System.Convert]::FromBase64String($b64)",
    "$unprotected = [System.Security.Cryptography.ProtectedData]::Unprotect(" +
      "$bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
    "[System.Convert]::ToBase64String($unprotected)"
  ].join("; ");

  const out = execFileSync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    { input: wrapped.toString("base64"), encoding: "utf8" }
  );
  const key = Buffer.from(out.trim(), "base64");
  if (key.length !== 32) {
    throw new Error("DPAPI unwrap: unexpected key length");
  }
  return key;
}

// Accepts either a bare hostname ("example.com") or a full absolute URL, mirroring
// src/credential_gate.ts's normalizeHost. Kept local (not shared) so this security-sensitive
// module has no cross-module coupling.
function normalizeHost(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      const host = new URL(trimmed).hostname.toLowerCase();
      return host || undefined;
    } catch {
      return undefined;
    }
  }
  if (trimmed.startsWith("//")) return undefined;
  if (/[/\\?#\s@:]/.test(trimmed)) return undefined;
  return trimmed.toLowerCase();
}

interface LoginRow {
  origin_url: string | null;
  signon_realm: string | null;
  username_value: string | null;
  password_value: Uint8Array | null;
}

// Production wiring. `opts.masterKey`, if given, is used instead of unwrapMasterKey (test-only
// injection point - unit tests must never hit the real DPAPI/PowerShell path).
export function cometCredentialStore(
  profileDir: string,
  opts?: { masterKey?: Buffer }
): CredentialStore {
  const localStatePath = join(profileDir, "Local State");
  const loginDataPath = join(profileDir, "Default", "Login Data");
  let cachedKey: Buffer | undefined = opts?.masterKey;

  // A master-key unwrap failure is a CONFIGURATION fault (missing Local State, wrong profile dir,
  // DPAPI unavailable, wrong Windows user), not "this site has no saved login" - but read()'s
  // deliberate catch-all collapsed both to the same silent null. That is how a totally dead
  // credential feature looked exactly like an empty vault for an entire build. Warn once on
  // stderr (never the audit log, never with key or path CONTENT) so a total failure is visible
  // without breaking server startup for the many features that need no vault at all.
  let keyWarned = false;
  function getKey(): Buffer {
    if (!cachedKey) {
      try {
        cachedKey = unwrapMasterKey(localStatePath);
      } catch (err) {
        if (!keyWarned) {
          keyWarned = true;
          process.stderr.write(
            `[comet-mcp] credential vault unavailable: master key unwrap failed (${(err as Error).name}). ` +
            `Credential tools will deny every request until this is fixed.\n`
          );
        }
        throw err;
      }
    }
    return cachedKey;
  }

  return {
    read(origin: string, username?: string): Credential | null {
      const target = normalizeHost(origin);
      if (!target) return null;

      let tempPath: string | undefined;
      try {
        const key = getKey();
        tempPath = join(tmpdir(), `comet-login-data-${randomBytes(8).toString("hex")}.db`);
        copyFileSync(loginDataPath, tempPath);

        const db = new DatabaseSync(tempPath, { readOnly: true });
        try {
          const rows = db
            .prepare("SELECT origin_url, signon_realm, username_value, password_value FROM logins")
            .all() as unknown as LoginRow[];
          // Collect ALL rows for the target host rather than returning the first. A vault
          // routinely holds several logins for one provider - an agency has multiple CLIENT
          // accounts on google.com, vercel.com and so on - and silently picking whichever row
          // SQLite happened to return first means quietly authenticating as the WRONG CLIENT.
          // That is a confidentiality incident with no error and no signal, so ambiguity fails
          // closed: the caller must disambiguate (see the `username` argument) or get nothing.
          const matches = rows.filter(row => {
            const host = normalizeHost(row.origin_url ?? undefined) ??
              normalizeHost(row.signon_realm ?? undefined);
            return host !== undefined && host === target;
          });

          const candidates = username === undefined
            ? matches
            : matches.filter(row => row.username_value === username);

          if (candidates.length !== 1) return null; // none, or ambiguous -> deny
          const row = candidates[0]!;
          if (!row.password_value || row.username_value === null) return null;
          const plaintext = decryptBlob(key, Buffer.from(row.password_value));
          if (!plaintext) return null;
          return { username: row.username_value, password: plaintext.toString("utf8") };
        } finally {
          db.close();
        }
      } catch {
        // Any failure - missing file, unreadable DB, DPAPI failure - collapses to null. Never
        // rethrow with path/key/row content in the message.
        return null;
      } finally {
        if (tempPath) {
          try {
            unlinkSync(tempPath);
          } catch {
            // best-effort cleanup only
          }
        }
      }
    }
  };
}
