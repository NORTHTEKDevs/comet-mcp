import { describe, it, expect } from "vitest";
import { checkEgress, redactCredentials } from "../src/egress.js";
import type { Policy } from "../src/policy.js";
import type { Provenance } from "../src/provenance.js";

// Regressions for findings from the full certification sweep (2026-08-14), each confirmed by an
// independent verifier with an executable repro before being fixed here.

const policy: Policy = {
  domains_allow: ["good.example"],
  domains_deny: [],
  actions_allow: ["NAVIGATE"],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 }
};
const prov: Provenance = { origins: ["good.example"], trust: "untrusted" };
const payload = "some non-secret prose to exfiltrate that is long enough to matter here";

// FINDING (high): EMBEDDED_HOST_RE captured a host-shaped run and excluded '@', so for
// `//good.example@evil.com/steal` it matched the ALLOWLISTED userinfo and never saw evil.com - the
// host a browser actually navigates to. Fifth instance of "the containment pattern handles one
// shape and misses an alternate encoding". Fixed by handing every embedded candidate to the WHATWG
// URL parser instead of approximating a host with a regex.
describe("open-redirect containment resolves userinfo like a browser does", () => {
  it.each([
    ["plain userinfo", "https://good.example/redirect?next=https://good.example@evil.com/steal"],
    ["percent-encoded userinfo", "https://good.example/redirect?next=https%3A%2F%2Fgood.example%40evil.com%2Fsteal"],
    ["userinfo with password", "https://good.example/r?next=https://good.example:pw@evil.com/x"],
    ["protocol-relative userinfo", "https://good.example/r?next=//good.example@evil.com/x"]
  ])("blocks %s", (_label, destination) => {
    const r = checkEgress(policy, { destination, payload, provenance: prov });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe("embedded redirect target not allowlisted: evil.com");
  });

  it("does not false-positive on a doubled path separator", () => {
    expect(checkEgress(policy, { destination: "https://good.example/a//b/c", payload: "short", provenance: prov }).allowed).toBe(true);
  });

  it("still allows an intra-app redirect to an allowlisted host", () => {
    expect(checkEgress(policy, {
      destination: "https://good.example/url?continue=https://good.example/inbox",
      payload: "short", provenance: prov
    }).allowed).toBe(true);
  });
});

// FINDING (medium): the assignment value was `\S+`, stopping at the first space, so a multi-word
// passphrase leaked all but its first word - while the rule's whole purpose is to redact a
// credential regardless of entropy precisely because "a memorable passphrase is still a credential".
// The fix must NOT swallow trailing prose: an excerpt that eats its own sentence is useless and
// pushes operators toward allow_unredacted_inspect, which is strictly worse.
describe("multi-word secret values are redacted without eating surrounding prose", () => {
  it("redacts an unquoted multi-word passphrase in full", () => {
    const out = redactCredentials("password: correct horse battery staple");
    expect(out).not.toContain("battery staple");
    expect(out).toContain("[REDACTED]");
  });

  it("redacts a quoted multi-word passphrase in full", () => {
    const out = redactCredentials('password="correct horse battery staple"');
    expect(out).not.toContain("correct horse battery staple");
    expect(out).toContain("[REDACTED]");
  });

  it.each([
    ["dash separator", "here you go: password=hunter2hunter2hunter2 - don't share it", "hunter2hunter2hunter2", "don't share it"],
    ["comma separator", "password=hunter2hunter2, do not share", "hunter2hunter2", "do not share"]
  ])("keeps trailing prose after a %s", (_l, input, secret, prose) => {
    const out = redactCredentials(input);
    expect(out).not.toContain(secret);
    expect(out).toContain(prose);
  });
});

// FINDING (medium): the extension's ported prefix regex was \b-anchored while comet-mcp's twin uses
// `includes`, so a word-glued `mysk-...` was caught in one copy and missed in the other. Two copies
// of a pattern table drift; this pins parity from the comet-mcp side.
describe("vendor prefix detection is not word-boundary anchored", () => {
  it("catches a word-glued vendor prefix", () => {
    expect(redactCredentials("mysk-test123abc")).toContain("[REDACTED]");
  });
});
