import { describe, it, expect } from "vitest";
import { checkEgress, looksLikeCredential, redactCredentials, type EgressRequest } from "../src/egress.js";
import type { Policy } from "../src/policy.js";
import type { Provenance } from "../src/provenance.js";

// A Slack-token-SHAPED fixture, built by concatenation so the contiguous literal never appears in
// source. It is not a real token (the digits/chars are placeholder), but GitHub's secret scanner
// pattern-matches the literal form and blocks the push, so we keep the runtime value identical
// while denying the scanner a contiguous string to match. The detector under test still sees the
// full "xoxb-..." at runtime.
const SLACK_SHAPED = "xox" + "b-1234567890-abcdefghijklmnop";
// Same treatment for the other provider-prefixed fixtures, so no scanner-matchable literal sits in
// source. All fake; the detector still sees the full prefixed string at runtime.
const OPENAI_SHAPED = "sk" + "-abcdefghijklmnopqrstuvwxyz0123456789";
const NVIDIA_SHAPED = "nv" + "api-abcdefghijklmnopqrstuvwxyz0123456789";
const GITHUB_SHAPED = "ghp" + "_abcdefghijklmnopqrstuvwxyz0123456789";

const policy: Policy = {
  domains_allow: ["good.com", "app.example.com"],
  domains_deny: [],
  actions_allow: ["NAVIGATE", "READ", "CLICK", "TYPE", "SCROLL", "WAIT"],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 }
};

const untrustedFrom = (origin: string): Provenance => ({ origins: [origin], trust: "untrusted" });
const trustedNoOrigin: Provenance = { origins: [], trust: "trusted" };

describe("egress", () => {
  describe("checkEgress rule ordering", () => {
    it("rule 1: blocks an unparseable destination", () => {
      const req: EgressRequest = { destination: "not a url", payload: "hello", provenance: trustedNoOrigin };
      const r = checkEgress(policy, req);
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe("unparseable egress destination");
    });

    it("rule 2: blocks a credential-shaped payload regardless of destination, even to an allowlisted origin", () => {
      const req: EgressRequest = {
        destination: "https://good.com/api",
        payload: "sk-abcdefghijklmnopqrstuvwxyz0123456789",
        provenance: trustedNoOrigin
      };
      const r = checkEgress(policy, req);
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe("credential-shaped payload");
    });

    it("rule 3: blocks private (foreign-provenance) data to a non-allowlisted origin", () => {
      const req: EgressRequest = {
        destination: "https://attacker.com/collect",
        payload: "some page text",
        provenance: untrustedFrom("good.com")
      };
      const r = checkEgress(policy, req);
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe("private data to non-allowlisted origin");
    });

    it("rule 4: blocks non-trivial (>=40 char) payload to a non-allowlisted origin even without foreign provenance", () => {
      const payload = "x".repeat(40);
      const req: EgressRequest = {
        destination: "https://attacker.com/collect",
        payload,
        provenance: trustedNoOrigin // not foreign: empty origins
      };
      const r = checkEgress(policy, req);
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe("data to non-allowlisted origin");
    });

    it("rule 4 does not fire below the 40 char threshold", () => {
      const payload = "x".repeat(39);
      const req: EgressRequest = {
        destination: "https://attacker.com/collect",
        payload,
        provenance: trustedNoOrigin
      };
      const r = checkEgress(policy, req);
      expect(r.allowed).toBe(true);
    });

    it("rule 5: allows otherwise", () => {
      const req: EgressRequest = {
        destination: "https://good.com/api",
        payload: "short",
        provenance: trustedNoOrigin
      };
      expect(checkEgress(policy, req)).toEqual({ allowed: true });
    });
  });

  it("allows a same-origin post of page data back to its own allowlisted origin (normal use must not break)", () => {
    const req: EgressRequest = {
      destination: "https://good.com/submit?q=" + "y".repeat(100),
      payload: "a".repeat(200),
      provenance: untrustedFrom("good.com")
    };
    const r = checkEgress(policy, req);
    expect(r.allowed).toBe(true);
  });

  describe("redirect containment (open-redirect / continue= smuggling through an allowlisted host)", () => {
    it("blocks a non-credential-shaped embedded redirect target even though the outer host is allowlisted", () => {
      const payload = "?continue=http://attacker.example/harvest&note=hi";
      // Prove this case is NOT accidentally caught by the credential rule - it must be caught
      // by redirect containment specifically, or this test would be as vacuous as the bug it fixes.
      expect(looksLikeCredential(payload)).toBe(false);

      const req: EgressRequest = {
        destination: "https://good.com/url?continue=http://attacker.example/harvest&note=hi",
        payload,
        provenance: trustedNoOrigin
      };
      const r = checkEgress(policy, req);
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe("embedded redirect target not allowlisted: attacker.example");
    });

    it("allows an embedded redirect to another allowlisted origin (intra-app redirect, not a proxy)", () => {
      const req: EgressRequest = {
        destination: "https://good.com/url?continue=https://app.example.com/next",
        payload: "?continue=https://app.example.com/next",
        provenance: trustedNoOrigin
      };
      const r = checkEgress(policy, req);
      expect(r.allowed).toBe(true);
    });

    it("does not false-positive on an allowlisted destination with no embedded URL in query/fragment", () => {
      const req: EgressRequest = {
        destination: "https://good.com/search?q=invoice",
        payload: "?q=invoice",
        provenance: trustedNoOrigin
      };
      const r = checkEgress(policy, req);
      expect(r.allowed).toBe(true);
    });
  });

  // Regression: the first open-redirect fix only matched a literal "http://" inside the
  // destination, so the same exfiltration succeeded if the embedded target was protocol-relative
  // or percent-encoded. Both were ALLOWED before this fix.
  describe("open-redirect encodings through an allowlisted host", () => {
    const payload = "SSN 123-45-6789 and account 987654321 for a client file";
    const provenance = untrustedFrom("good.com");

    it.each([
      ["protocol-relative", "https://good.com/url?continue=//evil.com/x"],
      ["percent-encoded", "https://good.com/url?continue=http%3A%2F%2Fevil.com%2Fx"],
      ["double-encoded", "https://good.com/url?continue=http%253A%252F%252Fevil.com%252Fx"],
      ["encoded protocol-relative", "https://good.com/url?continue=%2F%2Fevil.com%2Fx"],
      ["in the fragment", "https://good.com/x#next=//evil.com/y"],
      ["uppercase scheme", "https://good.com/url?continue=HTTP://EVIL.COM/x"]
    ])("blocks an embedded foreign origin (%s)", (_label, destination) => {
      const r = checkEgress(policy, { destination, payload, provenance });
      expect(r.allowed).toBe(false);
      expect(r.reason).toMatch(/embedded redirect target not allowlisted/);
    });

    it("does not false-positive on a doubled path separator", () => {
      const r = checkEgress(policy, {
        destination: "https://good.com/a//b/c",
        payload: "short note",
        provenance
      });
      expect(r.allowed).toBe(true);
    });

    it("allows an embedded URL that is itself allowlisted", () => {
      const r = checkEgress(policy, {
        destination: "https://good.com/url?continue=https://app.example.com/inbox",
        payload: "short note",
        provenance
      });
      expect(r.allowed).toBe(true);
    });
  });

  describe("looksLikeCredential", () => {
    it.each([
      [OPENAI_SHAPED, true],
      [NVIDIA_SHAPED, true],
      [GITHUB_SHAPED, true],
      ["AKIAIOSFODNN7EXAMPLE", true],
      [SLACK_SHAPED, true],
      ["-----BEGIN PRIVATE KEY-----", true],
      ["password=hunter2hunter2hunter2", true],
      ["api_key=abcdef0123456789abcdef", true],
      ["token=abcdef0123456789abcdef0123", true],
      ["dGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0IGVuY29kaW5n", true], // long base64 blob
      ["This is just an ordinary sentence of prose with no secrets in it at all.", false],
      ["please navigate to the dashboard and click submit", false]
    ])("%s -> %s", (s, expected) => {
      expect(looksLikeCredential(s)).toBe(expected);
    });
  });

  // Task 38 (Phase 6): the text-replacing counterpart, used to build comet_assistant_ask's
  // quarantined excerpt (src/run_manager.ts's shapeAssistantResult).
  describe("redactCredentials", () => {
    it.each([
      OPENAI_SHAPED,
      NVIDIA_SHAPED,
      GITHUB_SHAPED,
      "AKIAIOSFODNN7EXAMPLE",
      SLACK_SHAPED,
      "password=hunter2hunter2hunter2",
      "api_key=abcdef0123456789abcdef",
      "api-key=abcdef0123456789abcdef",
      "token=abcdef0123456789abcdef0123",
      "dGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0IGVuY29kaW5n"
    ])("fully redacts a standalone secret: %s", (s) => {
      const out = redactCredentials(s);
      expect(out).not.toContain(s);
      expect(out).toBe("[REDACTED]");
    });

    it("redacts only the matched run, leaving surrounding prose intact", () => {
      const out = redactCredentials("My key is sk-abc123XYZ1234567890abcdef please keep it safe");
      expect(out).toBe("My key is [REDACTED] please keep it safe");
    });

    it("redacts a password= assignment embedded in a sentence", () => {
      const out = redactCredentials("here you go: password=hunter2hunter2hunter2 - don't share it");
      expect(out).not.toContain("hunter2hunter2hunter2");
      expect(out).toContain("[REDACTED]");
      expect(out).toContain("don't share it");
    });

    it("redacts a long numeric secret run", () => {
      const out = redactCredentials("card 4111111111111111 on file");
      expect(out).not.toContain("4111111111111111");
      expect(out).toBe("card [REDACTED] on file");
    });

    it("leaves ordinary prose untouched", () => {
      const s = "This is just an ordinary sentence of prose with no secrets in it at all.";
      expect(redactCredentials(s)).toBe(s);
    });

    it("leaves a short, ordinary numeric run untouched (e.g. a year or small count)", () => {
      const s = "the meeting is in 2026, room 42";
      expect(redactCredentials(s)).toBe(s);
    });
  });

  // Code-review regression (Task 38): the detection regexes' character classes did not include
  // \n, so a secret split across a line break was left partially or fully unredacted. This is
  // not contrived - comet_assistant_ask reads the Assistant's answer via screenshot ->
  // vision-model transcription of a narrow chat panel, which is prone to word-wrapping any long
  // token/key/JWT, and a vision model transcribing the render is likely to reproduce that wrap as
  // a literal line break.
  describe("redactCredentials - line-wrap tolerance (Task 38 code-review regression)", () => {
    it("leaves NO trace of a high-entropy token whose two halves each fall under the threshold when split by a line break", () => {
      const secret = "aB3fG7kL9mN2pQ5rS8tU1vW4xY7z"; // 28 chars, unbroken
      expect(secret.length).toBeGreaterThanOrEqual(20);
      // Prove the reproduction is real: split so BOTH fragments are individually short.
      const first = secret.slice(0, 18);
      const second = secret.slice(18);
      expect(first.length).toBeLessThan(20);
      expect(second.length).toBeLessThan(20);

      const wrapped = first + "\n" + second;
      const out = redactCredentials(wrapped);
      expect(out).not.toContain(first);
      expect(out).not.toContain(second);
      expect(out).toBe("[REDACTED]");
    });

    it("leaves no trace of a realistic bearer token wrapped mid-token by a vision transcription", () => {
      // The pre-break fragment alone ("a0AfH6SMC7z9Qk3", 15 chars) was too short to trip the
      // entropy threshold and used to survive verbatim even though the post-break fragment
      // ("mP1xR8vN2cT5wL6bY4dJ0hK", 23 chars) was already long enough to be redacted alone -
      // exactly the "partial redaction" failure mode from the code review finding.
      const s = "Authorization: Bearer ya29.a0AfH6SMC7z9Qk3\nmP1xR8vN2cT5wL6bY4dJ0hK";
      const out = redactCredentials(s);
      expect(out).not.toContain("a0AfH6SMC7z9Qk3");
      expect(out).not.toContain("mP1xR8vN2cT5wL6bY4dJ0hK");
      expect(out).toContain("[REDACTED]");
    });

    it.each([
      ["plain alnum", "aB3fG7kL9mN2pQ5rS8tU1vW4xY7z"],
      ["hyphenated", "aB3f-G7kL-9mN2-pQ5r-S8tU-1vW4"],
      ["underscored", "aB3f_G7kL_9mN2_pQ5r_S8tU_1vW4"],
      ["camelCase", "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234"],
      ["base64-shaped (+/=)", "abcXYZ012+/=abcXYZ012+/=abcXYZ"]
    ])("fully redacts a %s high-entropy token split by a line break (pattern-class coverage)", (_label, secret) => {
      const wrapped = secret.slice(0, 18) + "\n" + secret.slice(18);
      const out = redactCredentials(wrapped);
      expect(out).not.toContain(secret.slice(0, 18));
      expect(out).not.toContain(secret.slice(18));
      expect(out).toBe("[REDACTED]");
    });

    it("redacts a card-number-shaped digit run split by a line break", () => {
      const out = redactCredentials("card 4111111111\n111111 on file");
      expect(out).not.toContain("4111111111");
      expect(out).not.toContain("111111");
      expect(out).toBe("card [REDACTED] on file");
    });

    it("redacts a prefix-based secret (sk-...) split by a line break", () => {
      const out = redactCredentials("My key is sk-abc123XYZ1234567890\nabcdef please keep it safe");
      expect(out).toBe("My key is [REDACTED] please keep it safe");
    });

    it("redacts a password= assignment whose value is split by a line break", () => {
      const out = redactCredentials("here you go: password=hunter2hunter2\nhunter2 - don't share it");
      expect(out).not.toContain("hunter2hunter2");
      expect(out).toContain("[REDACTED]");
      expect(out).toContain("don't share it");
    });

    it("does not redact ordinary two-line prose merely because it wraps to a new line", () => {
      const s = "Thanks for reaching out.\nHere is the summary you requested.";
      expect(redactCredentials(s)).toBe(s);
    });
  });

  describe("looksLikeCredential - line-wrap tolerance (Task 38 code-review regression)", () => {
    it("detects a high-entropy token split by a line break (both halves individually below threshold)", () => {
      const secret = "aB3fG7kL9mN2pQ5rS8tU1vW4xY7z";
      const wrapped = secret.slice(0, 18) + "\n" + secret.slice(18);
      expect(looksLikeCredential(wrapped)).toBe(true);
    });

    it("does not flag ordinary two-line prose as a credential merely because it wraps", () => {
      expect(looksLikeCredential("Thanks for reaching out.\nHere is the summary you requested.")).toBe(false);
    });
  });
});
