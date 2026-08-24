import { describe, it, expect } from "vitest";
import { looksLikeCredential, checkEgress, type EgressRequest } from "../src/egress.js";
import type { Policy } from "../src/policy.js";

const policy: Policy = {
  domains_allow: ["good.com"],
  actions_allow: [],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300000 }
};
const trusted = { origins: [], trust: "trusted" as const };

// Generalization-probe finding: percent/JS-escape encoding of the NAME+SEPARATOR evaded all four
// literal detector layers. The egress gate now scans a decoded copy - detection only, so decoded
// text never reaches output.
describe("looksLikeCredential encoded-form layer", () => {
  it.each([
    ["percent-encoded name+separator", "%70assword%3Dhunter2"],
    ["percent-encoded separator only", "password%3Dhunter2-with-more-entropy99"],
    ["double-percent-encoded", "%2570assword%253Dhunter2"],
    ["JS unicode-escape separator", 'password\\u003Dhunter2'],
    ["JS hex-escape separator", 'password\\x3Dhunter2'],
    ["percent-encoded keyword", "%70%61%73%73%77%6F%72%64%3Dhunter2"],
    ["legit secret still caught after decode noise", "junk=%FF&password=correcthorsebattery"]
  ])("catches %s", (_label, input) => {
    expect(looksLikeCredential(input)).toBe(true);
  });

  it.each([
    ["ordinary url with percent-escapes", "https://example.com/a%20b%20c?q=1"],
    ["prose mentioning 100% progress", "upload is 100%25 done today"],
    ["plain short text", "hello world"],
    ["non-string input passes through false", undefined as never]
  ])("does not false-positive on %s", (_label, input) => {
    if (input === undefined) expect(looksLikeCredential(undefined as never)).toBe(false);
    else expect(looksLikeCredential(input as string)).toBe(false);
  });

  it("decoded text never reaches redactCredentials output (detection-only layer)", () => {
    // redactCredentials has no decode layer BY DESIGN (it cannot map decoded positions back);
    // the gate is what must not be fooled. Pin that the GATE blocks what the redactor misses.
    const encoded = "%70assword%3Dhunter2";
    const req: EgressRequest = {
      destination: "https://evil.net/collect",
      payload: encoded,
      provenance: trusted
    };
    expect(checkEgress(policy, req).allowed).toBe(false);
  });
});
