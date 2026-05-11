# comet-mcp

MCP server that lets Claude Code drive Perplexity Comet on Windows. Exposes a single tool `ask_perplexity(query) -> { answer, sources, truncated? }`.

Status: **v0 shipped**, registered in Claude Code at user scope. See `docs/plans/2026-05-10-vision-pivot.md` for the active design (the original `2026-05-10-comet-mcp-design.md` was superseded after the UIA dead end).

## How it works

```
Claude Code → comet-mcp → Ghost MCP (spawned child)
                  │              │
                  │              └── drives Comet via SendInput + clipboard + screenshot
                  │
                  └── vision OCR (NVIDIA Llama Vision OR Anthropic Claude Sonnet)
```

Comet's address bar gets focused (Ctrl+L), the query is pasted, Enter submits. Once the answer-pane screenshot stabilizes (consecutive identical hashes), the screenshot is sent to a vision model that returns `{answer, sources}` as structured JSON.

## Why

Use a Perplexity Pro/Enterprise subscription you already pay for instead of the per-call Perplexity API. ~10s latency per query (vs ~2s direct API), but no per-query cost on the search side. Vision OCR is also free on NVIDIA Build's tier.

## Requirements

- Windows 10/11
- Perplexity Comet installed (`%LOCALAPPDATA%\Comet\`) and signed in
- Ghost MCP exe at `%USERPROFILE%\projects\active\ghost\target\release\ghost-mcp.exe` (or set `GHOST_MCP_EXE`)
- Node 20+
- One of: `NVIDIA_API_KEY` (free at build.nvidia.com) OR `ANTHROPIC_API_KEY`

## Register in Claude Code

```bash
MSYS_NO_PATHCONV=1 claude mcp add comet --scope user \
  --env GHOST_MCP_EXE="C:\\path\\to\\ghost-mcp.exe" \
  --env NVIDIA_API_KEY="nvapi-..." \
  --env COMET_VISION_PROVIDER="nvidia" \
  -- node "C:\\path\\to\\comet-mcp\\dist\\index.js"
```

Verify: `claude mcp get comet` should show `Status: ✓ Connected`.

## Env vars

| Var | Required? | Default |
|---|---|---|
| `GHOST_MCP_EXE` | yes | `C:\Users\Krist\projects\active\ghost\target\release\ghost-mcp.exe` |
| `COMET_VISION_PROVIDER` | no | `anthropic` (set to `nvidia` for free tier) |
| `NVIDIA_API_KEY` | if provider=nvidia | — |
| `ANTHROPIC_API_KEY` | if provider=anthropic | — |
| `ANTHROPIC_AUTH_TOKEN` | (if provider=anthropic and you want subscription auth) | — |
| `COMET_NVIDIA_MODEL` | no | `meta/llama-3.2-90b-vision-instruct` |
| `COMET_VISION_MODEL` | no (Anthropic) | `claude-sonnet-4-6` |
| `COMET_EXE_PATH` | no | `%LOCALAPPDATA%\Comet\Application\Comet.exe` |

## Local dev

```bash
npm install
npm run build
npm test                       # 19 tests, no live deps
node scripts/inspect.mjs       # dump current Comet UIA tree (helper)
node scripts/smoke.mjs         # live e2e (needs Comet open, env vars set)
```

## Limitations (v0)

- Windows-only (Ghost dependency)
- Single in-flight query at a time (Comet UI is single-threaded)
- Citations return titles only, not URLs (vision can't read href attributes; Chromium accessibility tree is too sparse to walk)
- Steals window focus during query (~10s)
- Subscription billing via `ANTHROPIC_AUTH_TOKEN` doesn't work — Anthropic rate-limits OAuth-based direct API calls aggressively. Use NVIDIA free tier or `ANTHROPIC_API_KEY` instead.
