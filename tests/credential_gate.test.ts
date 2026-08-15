import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkCredentialFill, type CredentialContext } from "../src/credential_gate.js";
import { fileApprovalStore, grantApproval, type ApprovalStore } from "../src/approvals.js";
import type { Policy } from "../src/policy.js";

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "credgate-"));
}

const basePolicy: Policy = {
  domains_allow: ["example.com"],
  actions_allow: ["NAVIGATE", "READ", "CREDENTIAL_FILL"],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 },
  credential_sites: ["example.com"]
};

// Builds a fully-valid context (all four checks satisfied) so each denial test can flip
// exactly one field and prove that gate, and only that gate, causes the denial.
function validContext(dir: string, now: number, store?: ApprovalStore): CredentialContext {
  grantApproval(dir, "example.com", 60_000);
  return {
    policy: basePolicy,
    site: "example.com",
    currentOrigin: "example.com",
    store: store ?? fileApprovalStore(dir),
    nowMs: now
  };
}

describe("checkCredentialFill", () => {
  it("allows the happy path when all four gates pass", () => {
    const dir = freshDir();
    const now = Date.now();
    const ctx = validContext(dir, now);
    const decision = checkCredentialFill(ctx);
    expect(decision.allowed).toBe(true);
    expect(decision.approvalId).toBeDefined();
    expect(typeof decision.approvalId).toBe("string");
    rmSync(dir, { recursive: true, force: true });
  });

  it("denies an empty site", () => {
    const dir = freshDir();
    const now = Date.now();
    const ctx = { ...validContext(dir, now), site: "" };
    const decision = checkCredentialFill(ctx);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("site unparseable or empty");
    rmSync(dir, { recursive: true, force: true });
  });

  it("denies a malformed (non-hostname) site", () => {
    const dir = freshDir();
    const now = Date.now();
    const ctx = { ...validContext(dir, now), site: "//evil.com/phish" };
    const decision = checkCredentialFill(ctx);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("site unparseable or empty");
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 1 - denies when the site is not in policy.credential_sites", () => {
    const dir = freshDir();
    const now = Date.now();
    const ctx: CredentialContext = {
      ...validContext(dir, now),
      policy: { ...basePolicy, credential_sites: ["other.com"] }
    };
    const decision = checkCredentialFill(ctx);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("site not authorised for credential fill");
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 1 - denies when policy.credential_sites is absent entirely", () => {
    const dir = freshDir();
    const now = Date.now();
    const { credential_sites, ...noSites } = basePolicy;
    const ctx: CredentialContext = { ...validContext(dir, now), policy: noSites as Policy };
    const decision = checkCredentialFill(ctx);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("site not authorised for credential fill");
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 2 - denies when currentOrigin is undefined", () => {
    const dir = freshDir();
    const now = Date.now();
    const ctx: CredentialContext = { ...validContext(dir, now), currentOrigin: undefined };
    const decision = checkCredentialFill(ctx);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("current origin does not match credential site");
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 2 - denies when the site is listed but the current origin is a different host", () => {
    const dir = freshDir();
    const now = Date.now();
    const ctx: CredentialContext = { ...validContext(dir, now), currentOrigin: "attacker.com" };
    const decision = checkCredentialFill(ctx);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("current origin does not match credential site");
    rmSync(dir, { recursive: true, force: true });
  });

  it("gate 3 - denies when there is no fresh approval", () => {
    const dir = freshDir(); // no grantApproval call - store is empty
    const now = Date.now();
    const ctx: CredentialContext = {
      policy: basePolicy,
      site: "example.com",
      currentOrigin: "example.com",
      store: fileApprovalStore(dir),
      nowMs: now
    };
    const decision = checkCredentialFill(ctx);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("no valid approval");
    rmSync(dir, { recursive: true, force: true });
  });

  it("does not let a subdomain of an authorised site pass (no suffix matching)", () => {
    const dir = freshDir();
    const now = Date.now();
    grantApproval(dir, "evil.example.com", 60_000);
    const ctx: CredentialContext = {
      policy: basePolicy, // credential_sites: ["example.com"]
      site: "evil.example.com",
      currentOrigin: "evil.example.com",
      store: fileApprovalStore(dir),
      nowMs: now
    };
    const decision = checkCredentialFill(ctx);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("site not authorised for credential fill");
    rmSync(dir, { recursive: true, force: true });
  });
});
