import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileApprovalStore, grantApproval } from "../src/approvals.js";

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "approvals-"));
}

describe("approvals", () => {
  it("finds a fresh unused unexpired approval matching the site", () => {
    const dir = freshDir();
    const a = grantApproval(dir, "example.com", 60_000);
    const store = fileApprovalStore(dir);
    const found = store.find("example.com", Date.now());
    expect(found).not.toBeNull();
    expect(found!.id).toBe(a.id);
    expect(found!.site).toBe("example.com");
    expect(found!.used).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("does not find an expired approval", () => {
    const dir = freshDir();
    const now = Date.now();
    grantApproval(dir, "example.com", 1_000);
    const store = fileApprovalStore(dir);
    const found = store.find("example.com", now + 2_000);
    expect(found).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("does not find an already-used approval", () => {
    const dir = freshDir();
    const now = Date.now();
    const a = grantApproval(dir, "example.com", 60_000);
    const store = fileApprovalStore(dir);
    expect(store.consume(a.id, now)).toBe(true);
    const found = store.find("example.com", now);
    expect(found).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("does not find an approval for a different site", () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000);
    const store = fileApprovalStore(dir);
    const found = store.find("other.com", Date.now());
    expect(found).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("does not let a subdomain match its parent site's approval", () => {
    const dir = freshDir();
    grantApproval(dir, "example.com", 60_000);
    const store = fileApprovalStore(dir);
    const found = store.find("evil.example.com", Date.now());
    expect(found).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("consume returns true exactly once, then false on replay", () => {
    const dir = freshDir();
    const now = Date.now();
    const a = grantApproval(dir, "example.com", 60_000);
    const store = fileApprovalStore(dir);
    expect(store.consume(a.id, now)).toBe(true);
    expect(store.consume(a.id, now)).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("consume returns false for an expired approval", () => {
    const dir = freshDir();
    const now = Date.now();
    const a = grantApproval(dir, "example.com", 1_000);
    const store = fileApprovalStore(dir);
    expect(store.consume(a.id, now + 2_000)).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("consume returns false for a missing id", () => {
    const dir = freshDir();
    const store = fileApprovalStore(dir);
    expect(store.consume("no-such-id", Date.now())).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("ignores a malformed/unparseable approval file", () => {
    const dir = freshDir();
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "bad.json"), "{ this is not valid json");
    const store = fileApprovalStore(dir);
    const found = store.find("example.com", Date.now());
    expect(found).toBeNull();
    expect(store.consume("bad", Date.now())).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("ignores an approval file with the wrong shape", () => {
    const dir = freshDir();
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "shape.json"), JSON.stringify({ id: "shape", site: "example.com" }));
    const store = fileApprovalStore(dir);
    const found = store.find("example.com", Date.now());
    expect(found).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("a missing directory yields no approvals rather than throwing", () => {
    const dir = join(tmpdir(), "approvals-does-not-exist-" + Math.random().toString(36).slice(2));
    const store = fileApprovalStore(dir);
    expect(() => store.find("example.com", Date.now())).not.toThrow();
    expect(store.find("example.com", Date.now())).toBeNull();
    expect(() => store.consume("whatever", Date.now())).not.toThrow();
    expect(store.consume("whatever", Date.now())).toBe(false);
  });
});
