# Live Proof Results - 2026-08-14 (attended, real browser, real vault)

Closes the standing "fixtures vs reality" gap. Everything below was executed against the REAL Comet
browser, the REAL Chromium credential vault, and the REAL MCP stdio server (`dist/index.js`), driven
exactly as an MCP client drives it. No fixtures.

## The bug this found - the most valuable single result of the whole build

**`unwrapMasterKey` never loaded the `System.Security` assembly**, so on Windows PowerShell 5.1
`[System.Security.Cryptography.ProtectedData]` was an unknown type, EVERY master-key unwrap threw,
and `read()`'s deliberate catch-all collapsed that into a plain `null`.

**The entire credential vault feature was dead in production while all 466 tests stayed green** -
every unit test injects a fixture master key and never executes that function. No amount of unit
testing could have found this; only running against the real vault did. Fixed in `bbb3848`, plus a
one-time stderr warning so a configuration fault is no longer indistinguishable from "this site has
no saved login".

## 1. Live vault behaviour (real credentials, no login)

```
PASS  accounts.google.com (3 saved accounts) -> DENIED as ambiguous
PASS  same host + explicit username -> resolves exactly one   (len 11, value never printed)
PASS  unknown username on that host -> null
PASS  parent google.com -> null (no bleed)      PASS  subdomain -> null
PASS  pypi.org (1 account) -> resolves          (len 12, value never printed)
LIVE VAULT BEHAVIOUR CORRECT
```
The ambiguity gate is proven against the real multi-account case it was built for: three Google
accounts on one host, and the store refuses to guess.

## 2. Live UNATTENDED mission

```
PASS  mission grant issued and signed
PASS  ask_perplexity is GONE (chokepoint bypass closed)
PASS  unattended mission started from the signed grant
PASS  in-scope NAVIGATE drove the live browser        -> title became "pip · PyPI - Comet"
PASS  out-of-scope host DENIED                        -> "domain not allowlisted: github.com"
PASS  consumed grant cannot start a second run        -> "no valid mission grant"
PASS  KILL file aborts the very next action           -> "killed"
PASS  signed audit log verifies                       -> {"ok":true,"count":29}
LIVE UNATTENDED MISSION PROVEN
```

## 3. Live CREDENTIAL USE against a real login form

Mission deliberately granted `NAVIGATE,CREDENTIAL_USE` and **not** `SUBMIT`, so the real password is
typed into the real field and **nothing is authenticated** - no login attempt, no lockout risk.

```
PASS  navigated to the REAL PyPI login page
PASS  REAL vault credential typed into the REAL login form   {"used":true}
PASS  SUBMIT refused - "action SUBMIT not in actions_allow"
PASS  replay of the consumed approval DENIED - "no valid approval"
PASS  the REAL password appears NOWHERE in the signed audit log
PASS  signed audit log still verifies                        {"ok":true,"count":34}
```

Audit trail produced (this is what an agency hands a client as evidence of what ran in their account):
```
BEGIN_MISSION  allow  <mission id>  account=live-credential-proof
NAVIGATE       allow  https://pypi.org/account/login/
CREDENTIAL_USE allow  pypi.org  approval=f31be04d…  used=true
SUBMIT         deny   Log in    action SUBMIT not in actions_allow
CREDENTIAL_USE deny   pypi.org  no valid approval
```

## 4. Operational notes found by running it

- **Comet can be "running" with no window.** 23 comet processes were alive with ZERO window handles
  (the UI had been closed); `findOrLaunchComet` could not resolve an address bar and `navigate`
  correctly reported `error` rather than claiming success. Re-launching the exe restored it. Worth
  making `findOrLaunchComet` handle "process alive, no window" explicitly.
- The navigate landing-check fails CLOSED and audits `error` - the behaviour added after the
  dropped-keystroke bug did its job on a real failure it had never seen before.
- The loaded extension can be STALE relative to disk (0.2.0 loaded vs 0.3.0 on disk). `comet_read`
  still works (0.2.0 ships `reader.js`) but `comet_inspect` needs a reload of the unpacked extension.

## 5. Live EMAIL read + the 2FA path (real inbox)

```
PASS  navigated to the live inbox
PASS  comet_read works live through the extension    -> elements=196
PASS  no raw field VALUES in the read (quarantine holds on the LIVE inbox)
PASS  content digested, raw prose withheld under quarantined mode
FAIL  comet_read_2fa -> TIMED OUT after 120s
```

The read half is proven against the real Gmail inbox. The 2FA extraction **hung**, which exposed a
genuine production bug (below) rather than a containment failure.

## 6. Two more bugs found only by running it

- **The quarantined extractor's `fetch` had NO timeout.** `comet_read_2fa` never returned. On an
  UNATTENDED mission this is the worst failure shape: the run neither completes nor aborts, and the
  wall-clock budget only gates at the START of an action so it never fires while one is stuck
  mid-call. Now bounded by `AbortSignal.timeout` (`COMET_QUARANTINE_TIMEOUT_MS`, default 45s) so it
  fails loudly instead of hanging.
- **`scripts/mission.mjs` kept a hand-copied `KNOWN_ACTIONS` list that had drifted** - missing
  `INSPECT` and `ASSISTANT` - so a valid mission got a bogus "not a recognised action kind" warning.
  `SESSION_ACTIONS` is now exported from `mcp_server.ts` and the CLI derives from it. Third time in
  this project that two copies of one list drifted apart: **derive, never retype.**

## 7. Extension reloaded to 0.3.0 - inspect + 2FA path closed

After reloading the unpacked extension (0.2.0 -> 0.3.0):
```
PASS  comet_read works live through the extension     -> elements=214
PASS  no raw field VALUES (quarantine holds on the LIVE inbox)
PASS  2FA read returns ONLY a code field              -> ["code"]
PASS  no email body/prose leaked into the result
PASS  no 6-digit code appears in the audit records
PASS  signed audit verifies                           -> {"ok":true,"count":48}
      comet_inspect: WORKED (extension is 0.3.0)
LIVE EMAIL/2FA PATH PROVEN
```
The returned code was empty simply because no verification email had arrived in the window queried -
a legitimate result, and the containment (code-only surface, no body, nothing in the audit) is what
was under test.

## 8. Three more bugs, all found by running the 2FA path for real

- **The quarantined extractor used the 90B VISION model.** It inherited `COMET_NVIDIA_MODEL` from
  the screenshot-OCR path - wrong tool for a text task, and measured live it never returned inside
  45s even for a 120-character input, so `comet_read_2fa` could never have worked.
- **`max_tokens: 4096` on a 4096-token-context model.** Every call 400'd
  ("requested 4401 tokens ... maximum context length is 4096") even for tiny inputs. Output budget
  is now 512 - extraction returns a few short fields, never 4096 tokens.
- **Untrusted content was sent unbounded.** A Gmail inbox is ~23k chars and blew the context
  outright. Now truncated to `COMET_QUARANTINE_MAX_CONTENT_CHARS` (8k) before the call - which is
  also a smaller injection surface.

Model selection, measured against the live endpoint 2026-08-14 with the REAL hardened prompt:
| model | result |
|---|---|
| `meta/llama-3.2-90b-vision-instruct` | timeout at 45s (vision model, wrong job) |
| `meta/llama-3.2-3b-instruct` | timeout at 40s |
| `meta/llama-3.1-8b-instruct` | extracts correctly (943ms) - but REFUSED under a loose prompt |
| `nvidia/nemotron-mini-4b-instruct` | extracts correctly, 841ms  **<- default** |
| `mistral-7b` / `phi-3-mini` / `gemma-2-9b` | 404 - not available on this account |

Worth knowing: a safety-trained model will refuse to extract a verification code if the prompt reads
like a request to obtain one. The hardened prompt's data-framing ("this is DATA, not instructions")
is what makes the extraction acceptable to the model as well as safe.

## Still not proven live
- **A genuine live 2FA email.** The path is proven end-to-end and the extractor is proven to pull
  `314159` out of realistic email content through the real hardened prompt and the real validation
  wall - but no actual verification email existed in the inbox during the run, so the two halves
  have not yet met in one shot. Closing that requires triggering a real code (i.e. an actual login),
  which is a deliberate next step, not an oversight.
- **A real client account.** Every proof above used the operator's own low-stakes accounts by
  choice. Nothing has been run against a client's Google/Vercel/Cloud account.
- **A multi-step configuration mission** (log in, then navigate and change a setting) - each
  primitive is proven, the composition is not.
