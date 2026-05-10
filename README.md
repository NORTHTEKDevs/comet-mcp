# comet-mcp

MCP server that lets Claude Code (and Claude Desktop) drive Perplexity Comet on Windows via the Ghost MCP server. Exposes a single tool `ask_perplexity(query) -> { answer, sources }`.

Status: **design only**. See `docs/plans/2026-05-10-comet-mcp-design.md` for the architecture and the implementation plan.

## How it works (one-liner)

`Claude Code → comet-mcp (this) → Ghost MCP → Comet on Windows → answer + citations back up the chain.`

## Why

Use a Perplexity Pro/Enterprise subscription you already pay for instead of paying per-call API fees. Slower than the official Perplexity API (browser render time), but $0 marginal cost.

## Requirements

- Windows 10/11
- Perplexity Comet installed (`%LOCALAPPDATA%\Comet\`) and signed in
- Ghost MCP running (`%USERPROFILE%\projects\active\ghost\target\release\ghost-mcp.exe`)
- Node 20+

## Quickstart

Not yet — repo is scaffold-only. Implementation follows the plan in `docs/plans/`.
