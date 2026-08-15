import { describe, it, expect } from "vitest";
import { redactCredentials, looksLikeCredential } from "../src/egress.js";

// Regression, found by an adversarial probe after the Phase 6 gauntlet (and partly flagged by the
// Task 35 reviewer). The assignment detector was `\b`-anchored, so the keyword had to be a
// STANDALONE word - every compound identifier evaded it, and `secret` was not in the keyword set
// at all. 5 of 6 realistic secret assignments leaked in full against the built module.
//
// Real code names secrets as compounds (`sessionToken`, `apiSecret`, `my_password_field`) far more
// often than as bare words, and page source / JS bundles - the exact thing comet_inspect retrieves
// - are full of them. Same "pattern matches one shape, misses the obvious variants" class as the
// Phase 2 open-redirect (http:// only) and Phase 4 irreversible patterns (literal spaces).

describe("compound secret identifiers are redacted", () => {
  it.each([
    ["keyword as prefix of the identifier", "tokenSecretValue=abcdefghijklmnopqrstuvwxyzabcdefgh"],
    ["keyword as suffix of the identifier", "sessionToken=abcdefghijklmnopqrstuvwxyzABCDEF"],
    ["keyword infix with underscores", "my_password_field=correcthorsebatterystaple"],
    ["camelCase with a keyword not previously listed", "apiSecret=zzzzzzzzzzzzzzzzzzzzzzzzzz"],
    ["secret-bearing compound", "secretKeyMaterial=abcdefghijklmnopqrstuvwxyz"],
    ["JSON/YAML colon form", '"authorization": "Basic YWxhZGRpbjpvcGVuc2VzYW1l"'],
    ["hyphenated identifier", "x-api-key: abcdefghijklmnop"],
    ["bracketed config form", 'config["accessKey"]=abcdefghijklmnopqrst'],
    // The value here is LOW entropy - the NAME is the signal. This is why the assignment rule is
    // not redundant with the high-entropy detector.
    ["low-entropy passphrase value", "userPassword=hunter"]
  ])("redacts %s", (_label, input) => {
    const out = redactCredentials(input);
    expect(out).toContain("[REDACTED]");
    // and the secret VALUE must not survive anywhere in the output
    const value = input.split(/[:=]/).pop()!.trim().replace(/^"|"$/g, "");
    expect(out).not.toContain(value);
    expect(looksLikeCredential(input)).toBe(true);
  });
});

// Broadening a redactor is exactly where normal use breaks, so pin the non-matches too.
describe("ordinary text is not over-redacted", () => {
  it.each([
    ["plain prose mentioning secrets", "This is an ordinary sentence of prose with no secrets in it at all."],
    ["an instruction sentence", "please navigate to the dashboard and click submit"],
    ["a query string with no secret-shaped name", "?q=invoice&page=2"],
    ["a normal url", "https://good.com/url?continue=https://app.example.com/next"]
  ])("leaves %s untouched", (_label, input) => {
    expect(redactCredentials(input)).toBe(input);
  });

  // Load-bearing: the egress redirect-containment tests assert this exact payload is NOT
  // credential-shaped, so that a redirect block is proven to come from redirect containment rather
  // than accidentally from the credential rule. Broadening the keyword set must not break that.
  it("does not treat an open-redirect payload as credential-shaped", () => {
    expect(looksLikeCredential("?continue=http://attacker.example/harvest&note=hi")).toBe(false);
  });
});
