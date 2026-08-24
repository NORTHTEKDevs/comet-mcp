import { appendFileSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash, sign as edSign, verify as edVerify, createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import { execFileSync } from "node:child_process";

export interface AuditRecord {
  ts: number; run_id: string; actor: string; action: string;
  target?: string; provenance?: string; policy_decision: "allow" | "deny" | string;
  reason?: string; observation_hash?: string;
}

interface ChainLine { rec: AuditRecord; prev: string; hash: string; sig: string; }

const GENESIS = "0".repeat(64);

function canon(rec: AuditRecord): string {
  // Stable key order so the hash is deterministic.
  const keys = Object.keys(rec).sort();
  return JSON.stringify(rec, keys);
}

function hashOf(prev: string, rec: AuditRecord): string {
  return createHash("sha256").update(prev).update("|").update(canon(rec)).digest("hex");
}

export class AuditLog {
  private key;
  constructor(private path: string, privatePem: string) {
    this.key = createPrivateKey(privatePem);
  }
  private lastHash(): string {
    if (!existsSync(this.path)) return GENESIS;
    const txt = readFileSync(this.path, "utf8").trimEnd();
    if (!txt) return GENESIS;
    // Walk BACKWARD to the last line that parses as a chain line. A crash mid-append leaves a
    // torn FINAL line whose JSON.parse used to throw here - which made every future append (and
    // therefore the whole control plane, via RunManager's bare append calls) throw forever. A
    // torn tail is a crash artifact, not tampering: tamper detection is hash-based and happens
    // in verifyLog. The new record chains from the last INTACT hash; append() keeps the torn
    // fragment on its own line so it is never silently rewritten.
    const lines = txt.split("\n");
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const parsed = JSON.parse(lines[i]!) as ChainLine;
        if (typeof parsed.hash === "string") return parsed.hash;
      } catch {
        // not a complete line - keep walking backward
      }
    }
    return GENESIS;
  }
  append(rec: AuditRecord): void {
    // Re-reads the last line from disk on every call (rather than caching the tail in memory) so
    // the chain stays correct even if this process is not the only writer to `path` and so a
    // fresh AuditLog instance pointed at an existing file continues the chain instead of
    // restarting it at GENESIS. Phase 1 has exactly one writer (the run manager), so the extra
    // read per append is a deliberate correctness-over-throughput tradeoff, not an oversight.
    const prev = this.lastHash();
    const hash = hashOf(prev, rec);
    const sig = edSign(null, Buffer.from(hash, "hex"), this.key).toString("base64");
    const line: ChainLine = { rec, prev, hash, sig };
    // If the file does not end with a newline it has a torn final line (crash mid-append).
    // Prefix a newline so the new record lands on its OWN line chained from the last intact
    // hash - appending bare would fuse the new JSON into the torn fragment, corrupting both.
    let prefix = "";
    if (existsSync(this.path)) {
      const buf = readFileSync(this.path);
      if (buf.length > 0 && buf[buf.length - 1] !== 0x0a) prefix = "\n";
    }
    appendFileSync(this.path, prefix + JSON.stringify(line) + "\n");
  }
}

export function verifyLog(path: string, publicPem: string): { ok: boolean; count: number; brokenAt?: number } {
  const pub = createPublicKey(publicPem);
  const txt = existsSync(path) ? readFileSync(path, "utf8").trimEnd() : "";
  if (!txt) return { ok: true, count: 0 };
  const lines = txt.split("\n");
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (raw === undefined) return { ok: false, count: lines.length, brokenAt: i };
    // A torn line (crash mid-append) is reported as a break at its index, never thrown: verify
    // must stay able to ANSWER "is this log intact?" - "no, broken at N" is the answer, an
    // exception is not.
    let line: ChainLine;
    try {
      line = JSON.parse(raw) as ChainLine;
    } catch {
      return { ok: false, count: lines.length, brokenAt: i };
    }
    if (line.prev !== prev) return { ok: false, count: lines.length, brokenAt: i };
    if (hashOf(prev, line.rec) !== line.hash) return { ok: false, count: lines.length, brokenAt: i };
    if (!edVerify(null, Buffer.from(line.hash, "hex"), pub, Buffer.from(line.sig, "base64")))
      return { ok: false, count: lines.length, brokenAt: i };
    prev = line.hash;
  }
  return { ok: true, count: lines.length };
}

// Key bootstrap: load from env or a gitignored keyfile pair; generate on first run.
//
// The private key is DPAPI-PROTECTED at rest (Windows CurrentUser scope, the same mechanism the
// Comet vault reader uses): mode 0o600 is largely ignored by Windows ACLs, so a plaintext PEM in
// %USERPROFILE%\\.comet-mcp was readable by any process running as the user - same exposure class
// as the credential vault this codebase already guards. On-disk format is a JSON envelope
// {"v":1,"wrapped":<base64 DPAPI blob>}; a legacy plaintext PEM file is migrated to the envelope
// on first load (best-effort: if DPAPI is unavailable - non-Windows, odd CI - the plaintext file
// is kept and behavior matches the old implementation). Env-var keys are never touched.
export function loadOrCreateKeys(dir: string): { priv: string; pub: string } {
  return loadOrCreateKeysWith(dir, powershellDpapi());
}

export interface DpapiAdapter {
  // null = DPAPI unavailable on this machine; callers fall back to plaintext-at-rest.
  protect(plain: Buffer): Buffer | null;
  unprotect(wrapped: Buffer): Buffer | null;
}

function powershellDpapi(): DpapiAdapter {
  // Key bytes travel via stdin (base64), never the command line, so they never land in a
  // process listing - same pattern as credential_store.unwrapMasterKey.
  const run = (script: string, inputB64: string): string =>
    execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script],
      { input: inputB64, encoding: "utf8" }).trim();
  const protectScript = [
    "Add-Type -AssemblyName System.Security",
    "$b64 = [Console]::In.ReadToEnd().Trim()",
    "$bytes = [System.Convert]::FromBase64String($b64)",
    "$p = [System.Security.Cryptography.ProtectedData]::Protect(" +
      "$bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
    "[System.Convert]::ToBase64String($p)"
  ].join("; ");
  const unprotectScript = [
    "Add-Type -AssemblyName System.Security",
    "$b64 = [Console]::In.ReadToEnd().Trim()",
    "$bytes = [System.Convert]::FromBase64String($b64)",
    "$u = [System.Security.Cryptography.ProtectedData]::Unprotect(" +
      "$bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
    "[System.Convert]::ToBase64String($u)"
  ].join("; ");
  return {
    protect(plain) {
      try { return Buffer.from(run(protectScript, plain.toString("base64")), "base64"); }
      catch { return null; }
    },
    unprotect(wrapped) {
      try { return Buffer.from(run(unprotectScript, wrapped.toString("base64")), "base64"); }
      catch { return null; }
    }
  };
}

export function loadOrCreateKeysWith(dir: string, dpapi: DpapiAdapter): { priv: string; pub: string } {
  const privPath = join(dir, "audit.key");
  const pubPath = join(dir, "audit.pub");
  if (process.env.COMET_AUDIT_KEY && process.env.COMET_AUDIT_PUB)
    return { priv: process.env.COMET_AUDIT_KEY, pub: process.env.COMET_AUDIT_PUB };
  if (existsSync(privPath) && existsSync(pubPath)) {
    const raw = readFileSync(privPath, "utf8");
    if (raw.startsWith("{")) {
      // Envelope format. An unwrap failure here is terminal BY DESIGN: the key is unrecoverable
      // (different Windows user, profile corruption) and silently regenerating would invalidate
      // every existing signature in the audit log - a tamper-evident log whose signer can be
      // quietly swapped is not tamper-evident.
      let plain: Buffer | null = null;
      try {
        const env = JSON.parse(raw) as { v?: number; wrapped?: string };
        if (env.v === 1 && typeof env.wrapped === "string")
          plain = dpapi.unprotect(Buffer.from(env.wrapped, "base64"));
      } catch { /* malformed envelope -> plain stays null */ }
      if (plain === null || !plain.toString("utf8").includes("PRIVATE KEY")) {
        throw new Error("audit private key could not be unwrapped (DPAPI CurrentUser mismatch or corrupted keyfile)");
      }
      return { priv: plain.toString("utf8"), pub: readFileSync(pubPath, "utf8") };
    }
    // Legacy plaintext PEM: return it, then migrate to the envelope best-effort so the
    // plaintext copy stops existing after the first successful load.
    const wrapped = dpapi.protect(Buffer.from(raw, "utf8"));
    if (wrapped !== null) {
      try {
        writeFileSync(privPath, JSON.stringify({ v: 1, wrapped: wrapped.toString("base64") }), { mode: 0o600 });
      } catch { /* keep the legacy file rather than losing the key */ }
    }
    return { priv: raw, pub: readFileSync(pubPath, "utf8") };
  }
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const pub = publicKey.export({ type: "spki", format: "pem" }).toString();
  const wrapped = dpapi.protect(Buffer.from(priv, "utf8"));
  if (wrapped !== null) {
    writeFileSync(privPath, JSON.stringify({ v: 1, wrapped: wrapped.toString("base64") }), { mode: 0o600 });
  } else {
    writeFileSync(privPath, priv, { mode: 0o600 });
  }
  writeFileSync(pubPath, pub);
  return { priv, pub };
}
