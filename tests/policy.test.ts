import { describe, it, expect } from "vitest";
import { check, newState, consume, type Policy } from "../src/policy.js";

const base: Policy = {
  domains_allow: ["mail.google.com", "app.example.com"],
  domains_deny: ["evil.com"],
  actions_allow: ["NAVIGATE", "READ", "CLICK", "TYPE", "SCROLL", "WAIT"],
  budgets: { max_actions: 3, max_domains: 2, max_ms: 60_000 }
};

describe("policy", () => {
  it("allows an allowlisted navigation", () => {
    const s = newState(0);
    const r = check(base, { kind: "NAVIGATE", url: "https://mail.google.com/mail/u/0" }, s, 0);
    expect(r.allowed).toBe(true);
  });

  it("denies a non-allowlisted domain", () => {
    const s = newState(0);
    const r = check(base, { kind: "NAVIGATE", url: "https://other.com" }, s, 0);
    expect(r.allowed).toBe(false);
  });

  it("denies an explicitly denied domain even if suffix-allowed", () => {
    const s = newState(0);
    const r = check(base, { kind: "NAVIGATE", url: "https://evil.com/x" }, s, 0);
    expect(r.allowed).toBe(false);
  });

  it("denies an action not in actions_allow", () => {
    const s = newState(0);
    const r = check(base, { kind: "EXTRACT" }, s, 0);
    expect(r.allowed).toBe(false);
  });

  // Phase 5 Task 26 removed SUBMIT from policy.DANGEROUS. It is no longer blanket-denied at this
  // layer - both directions must hold: opted-in sessions can reach it, default/unlisted sessions
  // still cannot.
  it("no longer blanket-denies SUBMIT when the policy explicitly opts in via actions_allow", () => {
    const wideOpen: Policy = { ...base, actions_allow: ["SUBMIT"] };
    const s = newState(0);
    expect(check(wideOpen, { kind: "SUBMIT" }, s, 0).allowed).toBe(true);
  });

  it("still denies SUBMIT when it is not listed in actions_allow (default posture)", () => {
    const s = newState(0);
    expect(check(base, { kind: "SUBMIT" }, s, 0).allowed).toBe(false);
  });

  // Phase 3: CREDENTIAL_FILL is no longer blanket-denied at this layer. policy.check() only
  // enforces actions_allow/budgets/domain here; the real protection - policy pre-authorisation
  // via credential_sites, origin binding, and a single-use approval - lives in
  // checkCredentialFill (src/credential_gate.ts, tests/credential_gate.test.ts), which every
  // caller must run before a fill is ever attempted.
  it("no longer blanket-denies CREDENTIAL_FILL at this layer (phase 3 - gated in credential_gate.ts instead)", () => {
    const wideOpen: Policy = { ...base, actions_allow: ["CREDENTIAL_FILL"] };
    const s = newState(0);
    expect(check(wideOpen, { kind: "CREDENTIAL_FILL" }, s, 0).allowed).toBe(true);
  });

  it("enforces the action budget", () => {
    let s = newState(0);
    for (let i = 0; i < 3; i++) { s = consume(s, { kind: "READ" }, undefined); }
    expect(check(base, { kind: "READ" }, s, 0).allowed).toBe(false);
  });

  it("enforces the wall-clock budget", () => {
    const s = newState(0);
    expect(check(base, { kind: "READ" }, s, 61_000).allowed).toBe(false);
  });

  it("enforces the distinct-domain budget", () => {
    let s = newState(0);
    s = consume(s, { kind: "NAVIGATE", url: "https://mail.google.com" }, "mail.google.com");
    s = consume(s, { kind: "NAVIGATE", url: "https://app.example.com" }, "app.example.com");
    // third distinct domain would exceed max_domains: 2
    const r = check({ ...base, domains_allow: ["mail.google.com", "app.example.com", "c.example.com"] },
                    { kind: "NAVIGATE", url: "https://c.example.com" }, s, 0);
    expect(r.allowed).toBe(false);
  });

  it("fails closed on a schemeless URL instead of falling through the domain gate", () => {
    const s = newState(0);
    const r = check(base, { kind: "NAVIGATE", url: "evil.com" }, s, 0);
    expect(r.allowed).toBe(false);
  });

  it("fails closed on a file:// URL (empty hostname) instead of falling through the domain gate", () => {
    const s = newState(0);
    const r = check(base, { kind: "NAVIGATE", url: "file:///etc/passwd" }, s, 0);
    expect(r.allowed).toBe(false);
  });

  it("fails closed on a protocol-relative URL instead of falling through the domain gate", () => {
    const s = newState(0);
    const r = check(base, { kind: "NAVIGATE", url: "//evil.com/phish" }, s, 0);
    expect(r.allowed).toBe(false);
  });
});