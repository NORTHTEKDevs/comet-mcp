# Mission presets - driving Comet from Claude Code

The `comet` MCP is registered at user scope, so every Claude Code session has these tools. Nothing
dangerous is reachable by default: a session can do only what its own policy (or a signed mission
grant) allows, and every credential op additionally needs a single-use out-of-band approval.

## Before any run

```powershell
# 1. relay (leave running)
cd C:\Users\Krist\projects\active\comet-bridge\.worktrees\comet-agent-phase1
$env:BRIDGE_EXT_ORIGIN = "chrome-extension://ppdkeminodaeipdnkjpkbfmjfpdjaipb"
node relay/server.js

# 2. Comet must have a real WINDOW open (23 background processes with no window is a real state -
#    navigate then fails its landing check and audits `error` rather than lying)

# 3. extension "Comet Bridge" must be loaded unpacked from that worktree's extension/ folder and
#    reloaded after any change (comet://extensions -> reload icon). It is currently 0.3.0.
```

Emergency stop for every unattended run, at any time:
```powershell
node scripts/kill.mjs        # writes ~/.comet-mcp/KILL ; checked before EVERY action
```

---

## Preset 1 - login-then-configure (the shape you asked for)

One signed grant covers the whole flow, including the 2FA detour. The service domain AND the email
domain must both be in scope, or the code-reading step is denied.

```powershell
cd C:\Users\Krist\projects\active\comet-mcp\.worktrees\comet-agent-phase1

# The human authorises the envelope, out of band, ONCE:
node scripts/mission.mjs `
  --account "client-acme" `
  --domains "vercel.com,mail.google.com" `
  --credential-sites "vercel.com" `
  --actions "NAVIGATE,READ,EXTRACT,CLICK,TYPE,SCROLL,SUBMIT,CREDENTIAL_USE,READ_2FA,INSPECT" `
  --max-actions 60 --max-domains 3 --ttl 20

# and a single-use credential approval for the login step:
node scripts/approve.mjs vercel.com use 15
```

Then, in Claude Code, drive it:

| step | tool | note |
|---|---|---|
| 1 | `comet_begin_mission { mission_id }` | consumes the grant; run is now scoped and unattended |
| 2 | `comet_navigate` -> the service login page | out-of-scope hosts are denied here |
| 3 | `comet_credential_use { site, name: "Password" }` | decrypts the vault password and types it; never returns it |
| 4 | `comet_act { kind: "SUBMIT" }` | only if SUBMIT is in `actions_allow` |
| 5 | `comet_read` | see whether a 2FA challenge appeared |
| 6 | `comet_navigate` -> the inbox | allowed because the email domain is in scope |
| 7 | `comet_read_2fa { from, within_ms }` | returns ONLY `{ code }` - the email body never reaches the planner |
| 8 | `comet_navigate` back, `comet_act { kind: "TYPE", text: code }`, `SUBMIT` | |
| 9 | `comet_read` / `comet_inspect` -> then `comet_act` to change the setting | irreversible-looking actions pause for approval |
| 10 | `comet_mission_status` | budget, current origin, killed flag |

**Vault ambiguity matters here.** `accounts.google.com` has three saved accounts, so a bare
`credential_use` on it is DENIED by design - pass the exact `username` to disambiguate. That is the
control that stops the agent authenticating as the wrong client.

## Preset 2 - read-only client audit (safe, no credentials)

```powershell
node scripts/mission.mjs --account "client-acme" `
  --domains "vercel.com" --actions "NAVIGATE,READ,EXTRACT,INSPECT,SCROLL" `
  --max-actions 40 --ttl 20
```
No `credential-sites`, so credential tools are structurally unavailable for the whole run. Good for
"go look at their setup and tell me what's configured".

## Preset 3 - research through your Perplexity connectors

```powershell
node scripts/mission.mjs --account "research" `
  --domains "perplexity.ai" --actions "NAVIGATE,ASSISTANT,READ" --max-actions 20 --ttl 15
```
`comet_assistant_ask` drives Comet's Assistant, so your enabled connectors (GitHub etc.) apply. The
answer is treated as untrusted content - it is synthesized from arbitrary web pages.

---

## Models

The quarantined extractor (used by `comet_read_2fa` and `comet_extract`) defaults to
`nvidia/nemotron-mini-4b-instruct` - measured 841ms and correct on realistic email content.

To use a stronger extractor, set either on the MCP registration:
```
COMET_QUARANTINE_MODEL=meta/llama-3.1-70b-instruct     # 5.2s, correct
```
Anthropic is a better fit for judgement-heavy extraction (`comet_extract` with rich schemas) and
`ANTHROPIC_API_KEY` is currently unset on this machine; wiring an Anthropic client into
`src/quarantine.ts` is a small, well-isolated change (`QuarantineClient` is a one-method interface).

Note: a safety-trained model may REFUSE to extract a verification code under a loose prompt
(`llama-3.1-8b` did). The hardened data-framing prompt is what makes it both safe and functional -
do not "simplify" it.

## Repo state you should know about

`comet-mcp`'s `main` and `feat/comet-agent-phase1` have **unrelated histories** (no merge base) -
there is a `backup/main-pre-resync` branch, so main was rewritten/re-synced at some point. All 87
commits of this work live on the branch, and the MCP is registered against the branch worktree.
Reconciling the two lineages is a decision for you, not something to force with
`--allow-unrelated-histories`. `comet-bridge` merged cleanly and its `main` is current.
