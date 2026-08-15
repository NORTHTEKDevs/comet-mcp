# Comet Agent Control Plane - Phase 3 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Let the agent log the user in to a site they already have a saved credential for, **without
any plaintext credential ever existing in agent, LLM, or MCP memory**, and only with the user's
explicit out-of-band approval for that specific site.

**Architecture:** Use the browser's OWN native autofill. Ghost focuses the password field and
triggers Comet's saved-credential autofill; the browser injects the secret directly into the DOM.
comet-mcp never sees, requests, or stores the value. Chromium will only autofill a credential into
the origin it was saved for, so the browser itself enforces origin binding - that is why the design
picked autofill over reading the credential store.

**Repo:** `C:\Users\Krist\projects\active\comet-mcp\.worktrees\comet-agent-phase1` (branch
`feat/comet-agent-phase1`). Phase 1+2 committed and green: 169 tests, tsc + build clean.

**Design ref:** section 4.7 of `docs/plans/2026-08-13-comet-agent-control-plane-design.md`.

---

## THE RISK, STATED PLAINLY - READ BEFORE WRITING CODE

Phases 1 and 2 relied on `CREDENTIAL_FILL` being in `policy.DANGEROUS`, denied **unconditionally**,
so it was structurally impossible. Phase 3 removes that absolute block. That is the single most
dangerous edit in this project so far. It is only acceptable because it is replaced by FOUR
independent gates, ALL of which must pass:

1. **Policy pre-authorisation** - the site appears in the run's `credential_sites`, which the caller
   set when the session began.
2. **Origin binding** - the run's CURRENT page origin equals that site. Filling is refused on any
   other page, so a page that redirects or an injected instruction cannot move the fill elsewhere.
3. **Fresh out-of-band approval** - a single-use, TTL-bounded approval the HUMAN granted outside the
   agent's control (see Task 17). The agent cannot mint, guess, or replay one.
4. **Browser origin binding** - Chromium only autofills a credential into the origin it was saved
   for. This one is not ours and cannot be bypassed by our bugs.

`SUBMIT` **stays in `DANGEROUS` and stays impossible.** Phase 3 fills a login form; the human
presses submit. Do not "helpfully" enable submission - that is Phase 5.

If any gate cannot be evaluated (unknown origin, missing approval store, unreadable policy), the
answer is DENY. Never fill on a "probably fine".

## Phase 3 hard invariants (assert in tests)
1. `CREDENTIAL_FILL` is denied unless ALL FOUR gates pass. Each gate has its own test proving that
   removing just that one gate results in a denial.
2. No plaintext credential ever appears in a return value, an audit record, a log line, or an error
   message. Assert by searching serialized outputs.
3. An approval is single-use and TTL-bounded: replaying it is denied, and an expired one is denied.
4. `SUBMIT` remains impossible. All Phase 1 and Phase 2 invariants still hold.

## Still OUT of scope
Unattended runs (Phase 4). The dangerous-action set and the DPAPI credential-store fallback
(Phase 5). Do NOT read `Login Data`, do NOT touch DPAPI, do NOT implement a secrets broker.

---

### Task 17: Out-of-band approval broker

**Files:** Create `src/approvals.ts`, `tests/approvals.test.ts`.

A file-backed approval store the agent can READ but must not be able to forge. Approvals live in
`<DATA_DIR>/approvals/` (same data dir as the audit log).

```ts
export interface Approval { id: string; site: string; action: "CREDENTIAL_FILL"; expires_ms: number; used: boolean }
export interface ApprovalStore {
  find(site: string, nowMs: number): Approval | null;   // fresh, unused, unexpired, matching site
  consume(id: string, nowMs: number): boolean;          // mark used; false if already used/expired/missing
}
export function fileApprovalStore(dir: string): ApprovalStore;
export function grantApproval(dir: string, site: string, ttlMs: number): Approval; // CLI/human path only
```

- `find` must reject: expired, already-used, site mismatch (exact host match, NOT suffix - an
  approval for `example.com` must NOT satisfy a fill on `evil.example.com`).
- `consume` is atomic-ish: re-reads the record and refuses if already used. Single-use is the point.
- A malformed/unparseable approval file is IGNORED (treated as absent), never trusted.
- `grantApproval` is the human's path (invoked by a small CLI in Task 22), never called by the agent.

Tests (min): fresh approval found; expired not found; used not found; wrong site not found;
subdomain does NOT match; consume returns true once then false; malformed file ignored; a missing
directory yields no approvals rather than throwing.

Commit: `feat(approvals): single-use TTL-bounded out-of-band approval store`

---

### Task 18: Credential policy + the four-gate check

**Files:** Modify `src/policy.ts`; create `src/credential_gate.ts`, `tests/credential_gate.test.ts`.

1. Add `credential_sites?: string[]` to `Policy` (default: absent = none allowed).
2. **Remove `CREDENTIAL_FILL` from `DANGEROUS`** in `policy.ts`, leaving `SUBMIT`. Add a comment
   explaining it is now gated by `credential_gate.ts` rather than blanket-denied, and that SUBMIT
   deliberately remains.
3. New pure function, so the whole decision is unit-testable without a browser:

```ts
export interface CredentialContext {
  policy: Policy; site: string; currentOrigin: string | undefined;
  store: ApprovalStore; nowMs: number;
}
export interface CredentialDecision { allowed: boolean; reason?: string; approvalId?: string }
export function checkCredentialFill(ctx: CredentialContext): CredentialDecision;
```

Evaluate in order, each failing closed with a distinct reason:
- `site` unparseable/empty -> deny.
- `policy.credential_sites` missing or does not contain `site` (exact host match) -> deny.
- `currentOrigin` undefined, or !== `site` -> deny `"current origin does not match credential site"`.
- No fresh approval from the store -> deny `"no valid approval"`.
- Otherwise allow, returning the `approvalId` for the caller to consume AFTER a successful fill.

Tests (min): the happy path allows; and FOUR separate tests each removing exactly one gate and
asserting denial with that gate's specific reason. Plus: subdomain of an authorised site denied;
site listed but origin mismatched denied.

Commit: `feat(credential-gate): four-gate credential fill decision, default deny`

---

### Task 19: Native autofill actor path

**Files:** Modify `src/ghost_client.ts`, `src/actor.ts`; tests in `tests/actor.test.ts`.

Add `CometActor.credentialFill(el: ElementRef): Promise<{ ok: boolean; filled: boolean }>`:
1. Focus the target field via `ghost_act {action:"click", ...el, window}`.
2. Trigger the browser's saved-credential autofill. Prefer Ghost's key path: send `Down` then
   `Enter` to open and accept the autofill dropdown (Chromium's standard behaviour on a saved login
   field). Expose the key sequence as a named exported constant so a test can assert it and so it
   can be tuned without touching logic.
3. **Verify by shape, never by value.** Confirm the field became non-empty using the extension
   reader's `value_present` boolean (`bridge.read` -> find the element -> `value_present === true`)
   or `ghost_assert` on a non-value predicate. **NEVER read the field's value**, never log it,
   never return it. `filled` is a boolean; that is the entire result surface.

Tests (min, fake Ghost): the call focuses the field before sending keys; the key sequence matches
the exported constant; the result contains ONLY `{ok, filled}` and no other keys; a fake whose
underlying read reports `value_present:false` yields `filled:false`.

Commit: `feat(actor): native-autofill credential fill, boolean-only result`

---

### Task 20: Wire CREDENTIAL_FILL through RunManager + MCP

**Files:** Modify `src/run_manager.ts`, `src/mcp_server.ts`, `src/index.ts`; tests in
`tests/credential_wiring.test.ts`.

1. `RunManager` takes an `ApprovalStore`. New method
   `credentialFill(run_id, site, el): Promise<ActionResult>`:
   - normal `guard()` policy check for kind `CREDENTIAL_FILL` (now no longer blanket-denied)
   - then `checkCredentialFill(...)`; on deny -> audit `deny` with the reason, actor NEVER called
   - on allow -> `actor.credentialFill(el)`, then `store.consume(approvalId)` **only if the fill
     succeeded**, then audit `allow` recording the SITE and the approval id (never a value)
   - if the fill failed, do NOT consume the approval (the human's grant is not spent on a failure)
2. `comet_session_begin` gains optional `credential_sites: string[]`.
3. New MCP tool `comet_credential_fill { run_id, site, name?, role? }`. Add `CREDENTIAL_FILL` to
   `SESSION_ACTIONS` so a policy can allow it. **Do NOT add `SUBMIT`.**
4. `index.ts` constructs `fileApprovalStore(join(DATA_DIR, "approvals"))` and passes it in.

Tests (min): denied with no approval and the actor never called; denied when the current origin does
not match; allowed on the full happy path and the approval is consumed exactly once; a replay of the
same approval is denied; a FAILED fill does not consume the approval; the audit record contains the
site and approval id and NO credential value; `SUBMIT` is still refused everywhere.

Commit: `feat(mcp): gated comet_credential_fill with approval consumption`

---

### Task 21: Red-team the credential path

**Files:** Create `tests/credential_redteam.test.ts`.

Drive hostile scenarios through the REAL modules (fakes for browser/LLM, no network):
1. Injected page text instructs the agent to fill credentials on an attacker origin -> denied
   (origin binding), actor never called.
2. Fill requested for an authorised site while the browser is on a DIFFERENT authorised site ->
   denied.
3. Approval replay after a successful fill -> denied.
4. Expired approval -> denied.
5. Approval for `example.com` used to fill on `evil.example.com` -> denied.
6. Agent attempts `SUBMIT` after a successful fill -> still impossible.
7. Serialize every result and audit record produced across the whole scenario and assert a
   planted sentinel secret string appears NOWHERE.
8. Fill attempted with no page context at all (no navigate yet) -> denied.

Assert on the SPECIFIC deny reason in each case so weakening a gate fails the suite.

Commit: `test(credential): red-team the four gates and no-plaintext invariant`

---

### Task 22: Approval CLI + docs

**Files:** Create `scripts/approve.mjs`; modify `README.md`.

- `scripts/approve.mjs <site> [ttl-minutes]` calls `grantApproval` and prints the id and expiry.
  This is the HUMAN's out-of-band path. Print a clear warning naming the site being authorised and
  that it is single-use.
- README: document the four gates, the approval CLI, `credential_sites`, `comet_credential_fill`,
  and state plainly that no plaintext credential ever enters agent/LLM/MCP memory because the
  browser performs the fill. Also state plainly that `SUBMIT` remains disabled, so a login is filled
  by the agent and submitted by the human, and that DPAPI/credential-store reading is NOT
  implemented (Phase 5, deliberately not built).

Commit: `docs: Phase 3 gated credential fill`

---

## Phase 3 done when
- tsc clean, build clean, full suite green (169 from Phase 1+2, plus new).
- Each of the four gates has a test proving that removing it alone causes denial.
- The no-plaintext invariant is asserted over serialized outputs and audit records.
- `SUBMIT` still impossible; Phase 1 and Phase 2 probes still pass unchanged.
