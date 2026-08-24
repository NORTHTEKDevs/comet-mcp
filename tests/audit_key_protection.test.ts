import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadOrCreateKeysWith, type DpapiAdapter, AuditLog, verifyLog } from "../src/audit.js";

// Fixture-only. NEVER invokes real DPAPI/PowerShell - the adapter is injected (the same seam
// rule as credential_store's fixture master key).

const PRIV_PEM = [
  "-----BEGIN PRIVATE KEY-----",
  "MC4CAQAwBQYDK2VwBCIEIJiM1Z0f8SidTqSEtzZDFTWJUcvJVOzja9AIfSPBMRFa",
  "-----END PRIVATE KEY-----",
  ""
].join("\n");
const PUB_PEM = [
  "-----BEGIN PUBLIC KEY-----",
  "MCowBQYDK2VwAyEAgvd+5JfU6QopTIvN0j+J0hR6txUnCXWFOHrWGHdJao0=",
  "-----END PUBLIC KEY-----",
  ""
].join("\n");

function fakeDpapi(overrides: Partial<DpapiAdapter> = {}): DpapiAdapter & { protected: number } {
  const state = { protected: 0 };
  return {
    protected: state.protected,
    get protectedCount() { return state.protected; },
    protect(plain) { state.protected++; return Buffer.concat([Buffer.from("WRAPPED:"), plain]); },
    unprotect(wrapped) {
      const s = wrapped.toString("utf8");
      return s.startsWith("WRAPPED:") ? Buffer.from(s.slice(8), "utf8") : null;
    },
    ...overrides
  } as DpapiAdapter & { protected: number };
}

describe("loadOrCreateKeys DPAPI envelope", () => {
  it("generates a NEW key wrapped in the DPAPI envelope, not plaintext", () => {
    const dir = mkdtempSync(join(tmpdir(), "auditkey-"));
    try {
      const dpapi = fakeDpapi();
      const { priv } = loadOrCreateKeysWith(dir, dpapi);
      expect(priv).toContain("PRIVATE KEY");
      const onDisk = readFileSync(join(dir, "audit.key"), "utf8");
      expect(onDisk.startsWith("{")).toBe(true);
      expect(JSON.parse(onDisk).v).toBe(1);
      expect(onDisk).not.toContain("PRIVATE KEY"); // plaintext never at rest
      // Round-trips: a second load unwraps the SAME key.
      const second = loadOrCreateKeysWith(dir, fakeDpapi());
      expect(second.priv).toBe(priv);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("migrates a legacy plaintext keyfile to the envelope on first load", () => {
    const dir = mkdtempSync(join(tmpdir(), "auditkey-"));
    try {
      writeFileSync(join(dir, "audit.key"), PRIV_PEM, { mode: 0o600 });
      writeFileSync(join(dir, "audit.pub"), PUB_PEM);
      const dpapi = fakeDpapi();
      const first = loadOrCreateKeysWith(dir, dpapi);
      expect(first.priv).toBe(PRIV_PEM); // same key returned
      const onDisk = readFileSync(join(dir, "audit.key"), "utf8");
      expect(onDisk).not.toContain("BEGIN PRIVATE KEY"); // migrated off plaintext
      const second = loadOrCreateKeysWith(dir, fakeDpapi());
      expect(second.priv).toBe(PRIV_PEM); // unwrap returns the original
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("falls back to plaintext-at-rest when DPAPI is unavailable (non-Windows)", () => {
    const dir = mkdtempSync(join(tmpdir(), "auditkey-"));
    try {
      const unavailable: DpapiAdapter = { protect: () => null, unprotect: () => null };
      const { priv } = loadOrCreateKeysWith(dir, unavailable);
      expect(priv).toContain("PRIVATE KEY");
      expect(readFileSync(join(dir, "audit.key"), "utf8")).toBe(priv); // legacy behavior preserved
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("fails CLOSED with a fixed error when an envelope cannot be unwrapped", () => {
    const dir = mkdtempSync(join(tmpdir(), "auditkey-"));
    try {
      writeFileSync(join(dir, "audit.key"), JSON.stringify({ v: 1, wrapped: "Tk9UX1JFQUxMQVk=" }), { mode: 0o600 });
      writeFileSync(join(dir, "audit.pub"), PUB_PEM);
      expect(() => loadOrCreateKeysWith(dir, fakeDpapi())).toThrow(/could not be unwrapped/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("env-var keys bypass the envelope entirely", () => {
    const prevK = process.env.COMET_AUDIT_KEY;
    const prevP = process.env.COMET_AUDIT_PUB;
    try {
      process.env.COMET_AUDIT_KEY = PRIV_PEM;
      process.env.COMET_AUDIT_PUB = PUB_PEM;
      const dir = mkdtempSync(join(tmpdir(), "auditkey-"));
      const dpapi = fakeDpapi();
      const { priv } = loadOrCreateKeysWith(dir, dpapi);
      expect(priv).toBe(PRIV_PEM);
      expect(existsSyncNo(dir)).toBe(false); // no files written
      rmSync(dir, { recursive: true, force: true });
    } finally {
      if (prevK === undefined) delete process.env.COMET_AUDIT_KEY; else process.env.COMET_AUDIT_KEY = prevK;
      if (prevP === undefined) delete process.env.COMET_AUDIT_PUB; else process.env.COMET_AUDIT_PUB = prevP;
    }
  });

  it("an unwrapped env/envelope key still produces a verifiable audit chain", () => {
    const dir = mkdtempSync(join(tmpdir(), "auditkey-"));
    try {
      const { priv, pub } = loadOrCreateKeysWith(dir, fakeDpapi());
      const logPath = join(dir, "run.audit.jsonl");
      const log = new AuditLog(logPath, priv);
      log.append({ ts: 1, run_id: "r", actor: "agent", action: "NAVIGATE", policy_decision: "allow" });
      log.append({ ts: 2, run_id: "r", actor: "agent", action: "READ", policy_decision: "allow" });
      expect(verifyLog(logPath, pub)).toMatchObject({ ok: true, count: 2 });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

function existsSyncNo(dir: string): boolean {
  // local import avoided at top to keep the test file's fs surface explicit
  return require("node:fs").existsSync(join(dir, "audit.key"));
}
