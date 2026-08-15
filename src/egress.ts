import type { Policy } from "./policy.js";
import { originOf, isForeignTo, type Provenance } from "./provenance.js";

export interface EgressRequest {
  destination: string;        // full url the data would reach, or the origin being typed into
  payload: string;            // the actual data leaving
  provenance: Provenance;     // where the payload came from
}
export interface EgressDecision { allowed: boolean; reason?: string }

const CREDENTIAL_PREFIXES = ["sk-", "nvapi-", "ghp_", "AKIA", "xox", "-----BEGIN"];

// comet_assistant_ask's answer is read via screenshot -> vision-model transcription (see
// redactCredentials below), and a narrow chat-panel render is likely to word-wrap any long
// token/key/JWT, which the vision transcription is likely to reproduce as a line break. That
// splits one contiguous secret into two fragments that can each fall under a detector's own
// length/entropy threshold. wrapTolerant builds a char-class run that also accepts a single
// \r?\n, but ONLY when a character from the SAME charset immediately follows it (the lookahead)
// - so the newline is absorbed into a match only when it sits between two token-shaped
// characters. A match can technically start right at such a newline (when the character before
// it is not itself token-shaped), but that only happens when the content after the break is
// already long/entropic enough to qualify on its own, so this never creates a new false positive
// - it only lets a genuinely wrapped token be recognized as one run instead of two short ones.
function wrapTolerant(charClass: string, quantifier: "+" | "*"): string {
  return `(?:${charClass}|\\r?\\n(?=${charClass}))${quantifier}`;
}

// A `\b`-anchored keyword only matches a STANDALONE word, so every compound identifier evaded it:
// `sessionToken=`, `my_password_field=`, `tokenSecretValue=` all leaked in full (verified against
// the built module 2026-08-14). Real code names secrets as compounds far more often than as bare
// words. So: allow identifier characters on BOTH sides of the keyword, broaden the keyword set
// (`secret` was missing entirely - `apiSecret=` leaked), and accept `:` as well as `=` so JSON/YAML
// blobs embedded in page source are covered.
//
// Once the NAME says "secret", the VALUE is redacted regardless of its entropy - that is the whole
// point of this rule and why it is not redundant with the high-entropy detector: a memorable
// passphrase has low entropy but is still a credential.
const SECRET_WORDS =
  "password|passwd|pwd|secret|token|api[_-]?key|apikey|credential|authorization|private[_-]?key|access[_-]?key";
// Quotes are identifier characters here on purpose: JS/JSON config reads as `config["accessKey"]=`
// and `"authorization": "..."`, and without them the run stops at the quote and the match is lost.
const IDENT_CHAR = "[A-Za-z0-9_.\\[\\]\"'-]";
// The VALUE was `\S+`, which stops at the first space - so a multi-word passphrase
// ("password: correct horse battery staple") had only its first word redacted and the rest leaked.
// A quoted value is captured to its closing quote; an unquoted one captures up to 6 whitespace-
// separated tokens. Bounded deliberately: capturing to end-of-line would nuke an entire minified JS
// line in comet_inspect output, and this redactor has to leave source readable to stay useful.
// Tokens stop at sentence punctuation, which is what separates the two cases: in
// "password=X, don't share it" the comma ends the value and the prose must survive (existing tests
// pin that - a redactor that eats the surrounding sentence makes an excerpt useless), while in
// "password: correct horse battery staple" nothing terminates it and every word is the secret.
// A QUOTED value is captured whole - that is the form a real multi-word secret takes in source
// code (`password="correct horse battery staple"`), and it is the case that actually matters for
// comet_inspect. For an UNQUOTED value, extra words are only absorbed when they look like more of
// the value: a continuation may not START with punctuation, so a `-` or `,` separator ends the
// match and the trailing sentence survives. Multi-word-unquoted is inherently ambiguous between
// "passphrase" and "prose after the secret"; erring toward keeping prose is deliberate, because a
// redactor that eats surrounding text makes an excerpt useless and pushes operators toward
// allow_unredacted_inspect - a worse outcome than this residual gap.
const VALUE_TOKEN = wrapTolerant("[^\\s,;!?]", "+");
const VALUE_MORE = `(?:[ \\t]+[^\\s,;!?-][^\\s,;!?]*){0,5}`;
const SECRET_VALUE = `(?:"[^"\\r\\n]*"|'[^'\\r\\n]*'|${VALUE_TOKEN}${VALUE_MORE})`;
const ASSIGNMENT_RE = new RegExp(
  `${IDENT_CHAR}*(?:${SECRET_WORDS})${IDENT_CHAR}*\\s*[:=]\\s*${SECRET_VALUE}`,
  "i"
);
// Continuous run of base64/hex-charset characters, tolerant of a single wrap-induced line break.
const CANDIDATE_TOKEN_RE = new RegExp(wrapTolerant("[A-Za-z0-9+/=_-]", "+"), "g");

function isHighEntropyToken(tok: string): boolean {
  // Strip any wrap-induced line break absorbed by wrapTolerant before scoring - the newline
  // isn't part of the real secret and shouldn't count toward length or unique-char entropy.
  const clean = tok.replace(/[\r\n]/g, "");
  if (clean.length < 20) return false;
  const hasDigit = /[0-9]/.test(clean);
  const hasAlpha = /[A-Za-z]/.test(clean);
  const uniqueChars = new Set(clean).size;
  // Ordinary prose rarely produces a 20+ char run with no whitespace at all, but guard
  // against low-entropy runs (e.g. a repeated character) so plain long words don't trip it.
  return hasDigit && hasAlpha && uniqueChars >= 8;
}

// Continuous digit runs, tolerant of a single wrap-induced line break. isHighEntropyToken
// requires BOTH a letter and a digit, so a purely numeric secret (card numbers, long session
// ids) used to fall straight through rule 2.
const DIGIT_RUN_RE = new RegExp(wrapTolerant("\\d", "+"), "g");
// A 13-digit run is also an epoch-milliseconds timestamp, so length alone would false-positive on
// perfectly ordinary values. Luhn separates real card numbers from incidental digits precisely;
// beyond 15 digits, a continuous run in an outbound payload is treated as secret-shaped outright.
const NUMERIC_SECRET_MIN_LEN = 15;

function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

function isNumericSecret(run: string): boolean {
  // Strip any wrap-induced line break absorbed by wrapTolerant before scoring (see
  // isHighEntropyToken) - luhnValid assumes a pure digit string.
  const digits = run.replace(/[\r\n]/g, "");
  if (digits.length >= NUMERIC_SECRET_MIN_LEN) return true;
  return digits.length >= 13 && digits.length <= 19 && luhnValid(digits);
}

// Exported so it is independently testable per the task spec.
export function looksLikeCredential(s: string): boolean {
  if (CREDENTIAL_PREFIXES.some(p => s.includes(p))) return true;
  if (ASSIGNMENT_RE.test(s)) return true;
  const candidates = s.match(CANDIDATE_TOKEN_RE);
  if (candidates && candidates.some(isHighEntropyToken)) return true;
  const digitRuns = s.match(DIGIT_RUN_RE);
  if (digitRuns && digitRuns.some(isNumericSecret)) return true;
  return false;
}

// Task 38 (Phase 6): a text-REPLACING counterpart to looksLikeCredential (which only detects),
// reusing the EXACT same detectors so there is one canonical pattern set - the Phase 4
// hyphen/underscore lesson (a second, drifted copy of a pattern table is how coverage gaps get
// introduced) applies to reuse, not just to the patterns themselves. Used server-side to build
// comet_assistant_ask's bounded excerpt under content_mode:"quarantined" (THE RISK rule 1/4 in
// docs/plans/2026-08-14-comet-agent-phase6-inspect-assistant.md) - unlike comet_inspect, whose
// redaction happens in the extension at the browser boundary, the Assistant's answer is produced
// server-side (vision-read from a screenshot), so there is no earlier boundary to redact at.
//
// A CREDENTIAL_PREFIXES hit (sk-, ghp_, AKIA, ...) redacts the matched prefix plus the contiguous
// token-shaped run that follows it, not the whole string, so surrounding prose survives - the
// other three rules already replace exactly the matched run, same shape looksLikeCredential tests
// for. Callers MUST redact the FULL text before any truncation/excerpting, never the other way
// round: truncating first can slice a token in half at the boundary, leaving a partial secret that
// no longer matches any pattern.
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
const PREFIX_TOKEN_RE = new RegExp(
  `(?:${CREDENTIAL_PREFIXES.map(escapeRegExp).join("|")})${wrapTolerant("[A-Za-z0-9+/=_.-]", "*")}`,
  "g"
);
const ASSIGNMENT_RE_G = new RegExp(ASSIGNMENT_RE.source, "gi");

export function redactCredentials(s: string): string {
  let out = s.replace(PREFIX_TOKEN_RE, "[REDACTED]");
  out = out.replace(ASSIGNMENT_RE_G, "[REDACTED]");
  out = out.replace(CANDIDATE_TOKEN_RE, (m) => (isHighEntropyToken(m) ? "[REDACTED]" : m));
  out = out.replace(DIGIT_RUN_RE, (m) => (isNumericSecret(m) ? "[REDACTED]" : m));
  return out;
}

function hostMatches(host: string, entry: string): boolean {
  const e = entry.toLowerCase();
  return host === e || host.endsWith("." + e);
}

// Matches a URL host embedded inside another URL's own path/query/fragment (the open-redirect /
// "continue=" / "url=" pattern). The scheme is OPTIONAL so protocol-relative targets ("//evil.com")
// are caught too - a browser resolves those to a real cross-origin navigation. The host must
// contain a dot and a TLD-ish suffix so an ordinary doubled path separator ("/a//b") is not
// mistaken for a host.
// Captures the whole embedded URL, NOT just a host-shaped run. The previous host-only capture
// excluded `@` from its character class, so for `//good.example@evil.com/steal` it matched
// `good.example` - the ALLOWLISTED userinfo - and never saw `evil.com`, the host a browser actually
// navigates to. Every embedded candidate is now handed to the WHATWG URL parser (the same one
// Chromium uses) so userinfo, ports, IDN and case are resolved exactly as the browser resolves
// them, instead of being approximated by a regex.
const EMBEDDED_URL_RE = /(?:https?:)?\/\/[^\s"'<>&]+/gi;

// An attacker can percent-encode the embedded URL ("http%3A%2F%2Fevil.com") - and double-encode it
// - so the raw string never contains "//" at all. Decode to a fixed point (bounded) before
// scanning. A malformed escape sequence makes decodeURIComponent throw; keep what we have and scan
// that rather than skipping the check entirely.
function decodeRepeatedly(s: string): string {
  let out = s;
  for (let i = 0; i < 3; i++) {
    let next: string;
    try { next = decodeURIComponent(out); } catch { return out; }
    if (next === out) return out;
    out = next;
  }
  return out;
}

// An allowlisted destination's own path/query/fragment can smuggle a second, non-allowlisted
// absolute URL (an open-redirect proxy: "https://allowlisted.example/url?continue=http://attacker...").
// Returns that embedded foreign origin, or null if every embedded URL (if any) resolves to an
// allowlisted origin. Used to stop an allowlisted host from being used as a redirect proxy to
// exfiltrate data that doesn't happen to be credential-shaped.
function embeddedForeignOrigin(destination: string, domainsAllow: string[]): string | null {
  let parsed: URL;
  try { parsed = new URL(destination); } catch { return null; }
  const rest = decodeRepeatedly(`${parsed.pathname}${parsed.search}${parsed.hash}`);
  for (const m of rest.match(EMBEDDED_URL_RE) ?? []) {
    // Protocol-relative targets still navigate cross-origin; give the parser a scheme to work with.
    const candidate = m.startsWith("//") ? `https:${m}` : m;
    let embeddedHost: string;
    try { embeddedHost = new URL(candidate).hostname.toLowerCase(); } catch { continue; }
    // Require a dotted host so an ordinary doubled path separator ("/a//b") is not read as a host.
    if (!embeddedHost || !embeddedHost.includes(".")) continue;
    if (!domainsAllow.some(d => hostMatches(embeddedHost, d))) return embeddedHost;
  }
  return null;
}

export function checkEgress(policy: Policy, req: EgressRequest): EgressDecision {
  // Rule 1: fail closed on an unparseable destination - never pass through.
  const destHost = originOf(req.destination);
  if (!destHost) return { allowed: false, reason: "unparseable egress destination" };

  // Rule 2: credential-shaped payloads are blocked regardless of destination.
  if (looksLikeCredential(req.payload)) {
    return { allowed: false, reason: "credential-shaped payload" };
  }

  const allowlisted = policy.domains_allow.some(d => hostMatches(destHost, d));

  // Redirect containment: an allowlisted host must not be usable as an open-redirect proxy.
  // Rules 3/4 below never fire once `allowlisted` is true, so without this check any allowlisted
  // host with a "continue="/"url="-style parameter is a free pass for non-credential-shaped data
  // (PII, session ids that don't match the entropy/prefix heuristics, arbitrary prose) to reach
  // an attacker origin embedded in that parameter.
  if (allowlisted) {
    const foreignRedirect = embeddedForeignOrigin(req.destination, policy.domains_allow);
    if (foreignRedirect) {
      return { allowed: false, reason: `embedded redirect target not allowlisted: ${foreignRedirect}` };
    }
  }

  // Rule 3: private (foreign-provenance) data may not egress to a non-allowlisted origin.
  if (!allowlisted && isForeignTo(req.provenance, destHost)) {
    return { allowed: false, reason: "private data to non-allowlisted origin" };
  }

  // Rule 4: non-trivial payloads to a non-allowlisted origin are blocked even without
  // foreign provenance (generic exfil-size guard).
  if (!allowlisted && req.payload.length >= 40) {
    return { allowed: false, reason: "data to non-allowlisted origin" };
  }

  // Rule 5: otherwise allow.
  return { allowed: true };
}
