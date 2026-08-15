import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog, verifyLog } from "../src/audit.js";

function keys() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    pub: publicKey.export({ type: "spki", format: "pem" }).toString()
  };
}

describe("audit", () => {
  it("appends records and the chain verifies", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const path = join(dir, "audit.jsonl");
    const { priv, pub } = keys();
    const log = new AuditLog(path, priv);
    log.append({ ts: 1, run_id: "r1", actor: "agent", action: "NAVIGATE", policy_decision: "allow", target: "https://x" });
    log.append({ ts: 2, run_id: "r1", actor: "agent", action: "READ", policy_decision: "allow" });
    const v = verifyLog(path, pub);
    expect(v.ok).toBe(true);
    expect(v.count).toBe(2);
    rmSync(dir, { recursive: true, force: true });
  });

  it("detects tampering", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const path = join(dir, "audit.jsonl");
    const { priv, pub } = keys();
    const log = new AuditLog(path, priv);
    log.append({ ts: 1, run_id: "r1", actor: "agent", action: "NAVIGATE", policy_decision: "allow" });
    const lines = readFileSync(path, "utf8").trimEnd().split("\n");
    const obj = JSON.parse(lines[0]);
    obj.rec.action = "SUBMIT"; // tamper
    writeFileSync(path, JSON.stringify(obj) + "\n");
    const v = verifyLog(path, pub);
    expect(v.ok).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });
});
