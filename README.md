# comet-mcp

**Give Claude Code - or any MCP client - your Perplexity Comet browser as a tool.**
Research through the Perplexity subscription you already pay for, at **$0 marginal cost**, instead of
per-call Perplexity API billing. The same control plane extends to anything you can do in the
browser: read a page, fill a form, drive an authenticated session - under a policy you set, with a
signed audit of every action.

> Built by [Northtek](https://northtek.io). Apache-2.0. Windows-first (Comet is Chromium; the
> credential and OS-input pieces use Windows APIs).

---

## Why this exists

Perplexity's API is billed per call. But if you already pay for **Perplexity Pro / Comet**, you have
an unmetered research engine sitting in a browser. `comet-mcp` lets an agent drive that browser, so
Claude can ask Perplexity questions and get answers + sources **without touching the paid API**.

That's the headline. Under it is a general, safety-gated control plane for driving Comet:

| Tool | What it does |
|---|---|
| `comet_assistant_ask` | Ask Comet's Perplexity Assistant a question (uses your enabled connectors). Free research for your agent. |
| `comet_navigate` / `comet_read` / `comet_act` | Drive the live browser: navigate, read the page as a sanitized element map, click/type/scroll. |
| `comet_extract` | Pull typed fields out of a page through a quarantined extractor (raw page text never reaches the calling model). |
| `comet_inspect` | DevTools-equivalent: rendered source, script/style sources, network entries, console - with secret redaction on by default. |
| `comet_session_begin` / `comet_status` | Open a scoped session and inspect its budget. |

Every tool call goes through one chokepoint: **policy check → execute → signed audit**. A denied
action never reaches the browser, and every attempt - allowed or denied - is written to a
hash-chained, Ed25519-signed log.

## Quick start (the free-Perplexity path)

```bash
git clone https://github.com/NORTHTEKDevs/comet-mcp
git clone https://github.com/NORTHTEKDevs/comet-bridge   # clone beside it
cd comet-mcp && node scripts/setup.mjs --start-relay
```

`setup.mjs` installs, builds, mints the relay token, writes the extension config, starts the relay,
and prints the exact `claude mcp add …` line with your real paths and token filled in. It is
idempotent - re-run it any time to reprint that command; it never overwrites an existing token.

It then leaves you the two steps only a human can do:

1. **Load the extension** - `comet://extensions` → Developer mode → **Load unpacked** →
   select `comet-bridge/extension`
2. **Paste the `claude mcp add` command** it printed, then restart Claude Code

Then, from Claude: `comet_session_begin` → `comet_assistant_ask`, and you're researching through
your own Perplexity subscription.

<details><summary>Manual setup, if you'd rather</summary>

```bash
npm install && npm run build
node ../comet-bridge/relay/server.js          # leave running
claude mcp add comet --scope user \
  --env BRIDGE_URL="http://127.0.0.1:8787" \
  --env BRIDGE_TOKEN="<contents of comet-bridge/relay/bridge.token>" \
  --env NVIDIA_API_KEY="nvapi-..." \
  -- node "/absolute/path/to/comet-mcp/dist/index.js"
```
</details>

## How it's built

- **Ghost** (OS-level input, undetectable - no CDP, no debug port) is the actor for clicks and
  typing. Navigation and page reads go through a **browser extension** (`comet-bridge`), which needs
  no window focus and leaves no automation fingerprint.
- **Dual-LLM injection containment.** Raw page/email text is only ever seen by a *quarantined*
  extractor whose output is validated to caller-declared fields. The planner (your agent) sees
  structured data, never untrusted prose as instructions.
- **Fail-closed egress gate.** Data with untrusted provenance can't leave to an origin the session
  didn't authorize (open-redirect, userinfo obfuscation, and encoding variants are all covered).
- **Signed audit.** Every action is in a tamper-evident log you can verify and replay.

Design docs and the phase-by-phase build are in [`docs/plans/`](docs/plans/).

## ⚠️ Advanced capability - read [SECURITY.md](SECURITY.md) first

Beyond research, `comet-mcp` can - **strictly on your own machine and only when you explicitly turn
it on per session** - use saved logins and run unattended missions. These are powerful, **opt-in,
gated, and local-only** by design. [SECURITY.md](SECURITY.md) explains exactly what they do, what
they never do, the residual risks, and the authorized-use terms. If you only want the free-Perplexity
research bridge, you never touch any of it.

## Status

Six build phases; 469 unit tests plus a live proof suite against a real browser. The credential and
unattended paths have been exercised live on the author's own low-stakes accounts. Serious tool, not
a toy - and not a substitute for reading SECURITY.md before enabling the advanced features.

## License

Apache-2.0. © Northtek. Use it, fork it, build on it.
