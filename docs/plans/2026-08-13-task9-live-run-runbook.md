# Task 9 - Live Proof Run Runbook (attended)

## RESULT OF THE 2026-08-13 LIVE RUN (executed against real Comet, PID 9224)

### FINAL: **ALL 8 STEPS PASSED** with the extension loaded.

`comet_read` returned **190 elements** from the real logged-in Gmail inbox
(`url=https://mail.google.com/mail/u/0/#inbox`, `title=Inbox (1,169) - info@northtek.io - Northtek
Mail`), with **no raw `value` key anywhere in the output** - field contents never reach model
context. Audit log verified `{ok:true, count:20}`, and the log provably contains NO page content
(it records actions, not the data read). Extension: **Comet Bridge 0.2.0**, id
`ppdkeminodaeipdnkjpkbfmjfpdjaipb`, loaded unpacked from the worktree `extension/` folder.
The relay must run with `BRIDGE_EXT_ORIGIN=chrome-extension://<that id>` or the browser blocks the
extension's responses on CORS.

The first pass (below) ran BEFORE the extension was loaded and before two live bugs were fixed.

Driven by a real MCP stdio client against `dist/index.js`. First pass: **7 of 8 steps passed live.**

| # | Step | Result |
|---|---|---|
| 1 | `comet_session_begin` | PASS `run_id=run_1` |
| 2 | `comet_navigate` -> mail.google.com | PASS - real browser navigated to the live inbox |
| 3 | `comet_read` | **NOT PROVEN IN-BROWSER** - extension not loaded (see below) |
| 4 | `comet_act SCROLL` | PASS (after the fix below) |
| 5 | `comet_navigate` -> example.org | PASS denied `domain not allowlisted` |
| 6 | `comet_navigate` -> `evil.com` | PASS denied `unparseable or non-http(s) url` |
| 7 | `comet_act SUBMIT` | PASS rejected at the zod schema before RunManager |
| 8 | `comet_status` | PASS `actions_used=2 domains_used=["mail.google.com"]` |
| 9 | audit verify | PASS `{ok:true, count:15}`, records match the run incl. both denies |

**Two real bugs the live run caught (both fixed, commit `79f955f`):**
1. `ghost_scroll` REQUIRES `x`/`y` (or `until_name`/`until_role`); a bare
   `{direction, amount}` failed with `missing param: x`. The actor now anchors off the address bar.
2. **`ghost_wait for=navigate` reported success while the address bar dropped the leading
   character** - asked for `https://mail.google.com/...`, landed on `ttps://mail.google.com/...`.
   Policy authorises the REQUESTED url, so an unverified navigate let the agent believe it was on
   an allowlisted domain while the browser was elsewhere. `navigate` now asserts the address bar
   actually contains the requested host, fails closed, and RunManager audits the mismatch.

**Read path:** proven end-to-end against the LIVE relay with a stand-in for the content script
(real `reader.js`, real `BridgeClient`, real `RunManager`): job dispatched, element map returned,
opaque refs present, and a password field's value (`hunter2-SUPERSECRET`) provably absent from the
serialized output - only `value_present: true`. **The one unproven link is the content script
executing inside Comet**, which needs the extension physically loaded (steps 1-2 below).

**Also observed:** Ghost's `ghost_window op=list` intermittently omits the Comet window (present
when Comet is unfocused, absent when it is foreground), and the extensions page is not exposed to
UIA, so `Load unpacked` could not be automated (VLM grounding also failed; the Ghost log shows
`DXGI capture returned all-black frame`). Loading the extension is a manual 4-click task.


Date prepared: 2026-08-13. Branch: `feat/comet-agent-phase1` (both repos).

This is the ONLY step that proves Phase 1 works outside of unit tests. It drives your real Comet
browser, which holds live client sessions. **Run it with a human present.** Nothing here takes a
dangerous action (they are structurally disabled), but you should watch the first run regardless.

## Environment facts already verified on this machine (2026-08-13)

| Fact | Value | Note |
|---|---|---|
| Comet running | yes, PID 9224 | window title matched `/comet\|perplexity/i` |
| Comet exe | `%LOCALAPPDATA%\Perplexity\Comet\Application\comet.exe` | default in code FIXED to this (`aaa1968`) |
| Ghost binary (registered) | `C:\Users\Krist\.local\bin\ghost-mcp.exe` | default in `index.ts` FIXED to this |
| Ghost wire API | `ghost_window` / `ghost_key` / `ghost_clipboard` / `ghost_act` / `ghost_wait` | all 8 old names were stale, FIXED |
| Relay on :8787 | NOT running | you must start it (step 2) |
| `relay/bridge.token` in worktree | MISSING (gitignored) | create in step 1 |
| `extension/config.js` in worktree | MISSING (gitignored) | create in step 1 |
| Audit log destination | `~\.comet-mcp\run.audit.jsonl` | outside the repo; key auto-created 0600 |

## Prerequisites (one-time, ~5 min)

**Step 1 - bridge token + extension config** (worktree copies are gitignored, so they do not exist yet):
```powershell
$bw = "C:\Users\Krist\projects\active\comet-bridge\.worktrees\comet-agent-phase1"
# reuse the existing token from the main checkout so you don't juggle two secrets
Copy-Item "C:\Users\Krist\projects\active\comet-bridge\relay\bridge.token" "$bw\relay\bridge.token"
Copy-Item "$bw\extension\config.example.js" "$bw\extension\config.js"
# then EDIT $bw\extension\config.js and paste the token value into RELAY_TOKEN
Get-Content "$bw\relay\bridge.token"
```

**Step 2 - load the extension in Comet and start the relay:**
1. Comet -> `chrome://extensions` -> Developer mode ON -> **Load unpacked** -> select
   `...\comet-bridge\.worktrees\comet-agent-phase1\extension`. Copy the extension ID it shows.
   (If a previous Comet Bridge extension is loaded from the non-worktree path, REMOVE it first so
   only one polls the relay.)
2. Start the relay with CORS locked to that ID:
```powershell
cd "C:\Users\Krist\projects\active\comet-bridge\.worktrees\comet-agent-phase1"
$env:BRIDGE_EXT_ORIGIN = "chrome-extension://<THE-ID>"
npm run relay
```
Leave this running. Expect `bridge relay on 127.0.0.1:8787`.

**Step 3 - point Claude Code at the NEW comet-mcp build:**
```powershell
$tok = Get-Content "C:\Users\Krist\projects\active\comet-bridge\.worktrees\comet-agent-phase1\relay\bridge.token"
claude mcp remove comet -s user
claude mcp add comet --scope user `
  --env BRIDGE_URL="http://127.0.0.1:8787" `
  --env BRIDGE_TOKEN="$tok" `
  -- node "C:\Users\Krist\projects\active\comet-mcp\.worktrees\comet-agent-phase1\dist\index.js"
claude mcp get comet   # expect: Status: Connected
```
Note: this repoints the `comet` MCP at the WORKTREE build. After merging to main, re-register
against the main checkout path.

## The run (do these in order, record every result)

Pick a benign site you are already logged into. The runbook uses Gmail; substitute freely.

| # | Call | Expected |
|---|---|---|
| 1 | `comet_session_begin` with `domains_allow:["mail.google.com"]`, `actions_allow:["NAVIGATE","READ","SCROLL"]` | returns a `run_id` |
| 2 | `comet_navigate(run_id, "https://mail.google.com/mail/u/0")` | `{ok:true}`; the REAL Comet window navigates |
| 3 | `comet_read(run_id, "page")` | element-map with real interactive elements + readable inbox text |
| 4 | `comet_act(run_id, {kind:"SCROLL", direction:"down"})` | `{ok:true}`; page scrolls |
| 5 | `comet_navigate(run_id, "https://example.org")` | **DENIED** `{ok:false}` - not allowlisted |
| 6 | `comet_navigate(run_id, "evil.com")` | **DENIED** - schemeless fails closed |
| 7 | `comet_act(run_id, {kind:"SUBMIT"})` | **REJECTED at the schema** - `SUBMIT` is not a valid enum member |
| 8 | `comet_status(run_id)` | actions_used / domains_used reflect only the ALLOWED actions |

**Step 9 - verify the audit trail** (the whole point of the trust plane):
```powershell
cd "C:\Users\Krist\projects\active\comet-mcp\.worktrees\comet-agent-phase1"
node -e "const{verifyLog,loadOrCreateKeys}=require('./dist/audit.js');const os=require('os'),p=require('path');const d=p.join(os.homedir(),'.comet-mcp');const{pub}=loadOrCreateKeys(d);console.log(verifyLog(p.join(d,'run.audit.jsonl'),pub));"
Get-Content "$env:USERPROFILE\.comet-mcp\run.audit.jsonl" -Tail 10
```
Expect `{ ok: true, count: N }` and one record per attempted action, with `policy_decision`
`allow`/`deny` matching the table above.

## Acceptance
- Steps 2-4 visibly succeed against the live browser.
- Steps 5-7 are denied/rejected.
- Step 9 verifies with the expected record count.

Paste the captured tool outputs + the audit tail into the PR description.

## Known limitation to watch for (not a blocker, but be aware)
The audit record is written from the POLICY DECISION, before the actor call resolves. If an allowed
action then throws downstream, the log holds an `allow` record for an action that had no effect.
Not a containment bypass (the browser genuinely was not driven), but it means the trail records
intent, not outcome. Recommended Phase 2 hardening: record the outcome, not just the decision.

## Screenshot policy
Per the global doctrine, prefer text verification (the element-map JSON and the audit tail ARE the
evidence). If you want a visual, capture a cropped region under 1024px, not a full screen.
