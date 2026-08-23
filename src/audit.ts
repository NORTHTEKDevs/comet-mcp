import { appendFileSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash, sign as edSign, verify as edVerify, createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";

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
export function loadOrCreateKeys(dir: string): { priv: string; pub: string } {
  const privPath = join(dir, "audit.key");
  const pubPath = join(dir, "audit.pub");
  if (process.env.COMET_AUDIT_KEY && process.env.COMET_AUDIT_PUB)
    return { priv: process.env.COMET_AUDIT_KEY, pub: process.env.COMET_AUDIT_PUB };
  if (existsSync(privPath) && existsSync(pubPath))
    return { priv: readFileSync(privPath, "utf8"), pub: readFileSync(pubPath, "utf8") };
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const pub = publicKey.export({ type: "spki", format: "pem" }).toString();
  writeFileSync(privPath, priv, { mode: 0o600 });
  writeFileSync(pubPath, pub);
  return { priv, pub };
}
