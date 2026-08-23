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

  // Torn-tail resilience: a crash mid-append leaves a partial final line. verifyLog used to
  // throw SyntaxError on it, and AuditLog.lastHash's bare JSON.parse threw too - bricking every
  // future append and turning a crash artifact into a control-plane DoS.
  it("reports a torn final line as ok:false instead of throwing, and append recovers", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const path = join(dir, "audit.jsonl");
    const { priv, pub } = keys();
    const log = new AuditLog(path, priv);
    log.append({ ts: 1, run_id: "r1", actor: "agent", action: "NAVIGATE", policy_decision: "allow" });
    log.append({ ts: 2, run_id: "r1", actor: "agent", action: "READ", policy_decision: "allow" });
    const good = readFileSync(path, "utf8");

    // Tear the file mid-last-line: keep record 1 intact, chop record 2 in half.
    const firstNewline = good.indexOf("\n");
    const torn = good.slice(0, firstNewline + 1) + good.slice(firstNewline + 1, firstNewline + 40);
    writeFileSync(path, torn);

    // verifyLog must fail closed WITHOUT throwing...
    const v = verifyLog(path, pub);
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toBe(1);

    // ...and a FRESH logger pointed at the same file must be able to append again. The torn
    // tail stays flagged (it is never silently rewritten), but the new record lands on its own
    // line and chains from the last INTACT record, so the chain is verifiable up to the tear
    // and from the repair point onward.
    const recovered = new AuditLog(path, priv);
    expect(() => recovered.append({ ts: 3, run_id: "r1", actor: "agent", action: "CLICK", policy_decision: "allow" })).not.toThrow();

    const linesAfter = readFileSync(path, "utf8").trimEnd().split("\n");
    expect(linesAfter).toHaveLength(3); // torn fragment, then the repaired record on its own line

    const v2 = verifyLog(path, pub);
    expect(v2.ok).toBe(false);       // the torn artifact itself stays broken - honest status
    expect(v2.brokenAt).toBe(1);     // broken at exactly the torn line, nowhere else
    expect(v2.count).toBe(3);

    // The appended record itself verifies against the last INTACT hash (record 1's).
    const appended = JSON.parse(linesAfter[2]!);
    const intact = JSON.parse(linesAfter[0]!);
    expect(appended.prev).toBe(intact.hash);

    rmSync(dir, { recursive: true, force: true });
  });
});
