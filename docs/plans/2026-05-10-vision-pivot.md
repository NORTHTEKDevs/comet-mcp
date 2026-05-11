# comet-mcp — Vision OCR Pivot

**Date:** 2026-05-10
**Status:** approved, in-progress
**Supersedes (partially):** `2026-05-10-comet-mcp-design.md` Section "Extraction"

## Why the pivot

Live smoke (Task 11) + UIA inspection of Comet revealed Ghost's `describe_screen("Comet")` returns only 3 elements (toolbar + URL bar + tab) — zero page-content elements. Root cause: Chromium-based browsers do not build their accessibility tree by default; UIA only sees window chrome. Without page elements, `walk_citations` and `is_login_wall` are non-functional.

Three pivot options were evaluated. Approved: **screenshot + Claude Vision OCR** via Anthropic API. Rationale: works without browser flags, doesn't need Comet relaunch, citations recoverable as titles. Trade-off accepted: ~$0.005-0.02 per query in Anthropic spend (Sonnet vision); user prefers Anthropic spend over Perplexity API spend.

## What we keep

- Task 1 toolchain (TypeScript, vitest, MCP SDK, zod) — unchanged
- `src/ghost_client.ts` — keep `GhostClient`, `spawn_ghost`, and most of `GhostTools`. Add `screenshot_region()` method. Remove `describe_screen()` (unused now).
- `src/mcp_server.ts` — unchanged
- `src/index.ts` — unchanged shape; will wire one extra dep (Anthropic client)
- `tests/extractor.test.ts` will partially remain: `is_stream_stable` and `parse_clipboard_answer` were UIA-agnostic and could still be useful for clipboard fallback. Keep those tests; delete `walk_citations` + `is_login_wall` tests + fixtures (UIA-dependent).

## What we throw away

- `src/extractor.ts`: delete `walk_citations`, `is_login_wall`, `UiaElement`, `Citation`. Keep `is_stream_stable`, `parse_clipboard_answer` (move to a smaller file if desired, or leave in-place).
- `tests/fixtures/answer-with-citations.json`, `tests/fixtures/login-wall.json`: delete.
- `src/comet_driver.ts`: full rewrite. UIA polling out, screenshot polling + vision extraction in.

## What we add

- New dep: `@anthropic-ai/sdk@^0.40.0`
- `src/vision_extractor.ts`: one function `extract_from_screenshot(png_base64: string, query: string): Promise<{answer, sources}>`. Wraps Anthropic SDK with a fixed prompt that asks Sonnet vision to return strict JSON.
- `src/screenshot_stability.ts`: small helper. Polls `ghost_screenshot` every N ms, hashes via crypto SHA-256, returns when consecutive hashes match (stream done).

## New architecture

```
Claude Code  ──MCP stdio──>  comet-mcp  ──MCP stdio──>  Ghost (spawned child)
                                │                            │
                                │                            └── drives Comet via SendInput + clipboard + screenshot
                                │
                                ├──> Anthropic SDK (vision API)
                                │
                                └── tool: ask_perplexity({query, timeout_ms?})
                                            -> { answer, sources, truncated? }
```

## New `ask()` flow

1. Receive `ask_perplexity({query, timeout_ms = 300_000})`
2. `ghost.list_windows()`, find Comet
3. `ghost.focus_window(name)`; sleep 300
4. `ghost.hotkey(["Ctrl"], "L")`; `ghost.set_clipboard(query)`; `ghost.hotkey(["Ctrl"], "V")`; `ghost.press("Enter")`
5. Sleep 2000 (give Comet time to start streaming)
6. Screenshot-stability poll: every 1000ms take screenshot, compare hash; when 2 consecutive hashes match (or timeout): proceed. Cap polls at `timeout_ms`.
7. Take final screenshot
8. `extract_from_screenshot(png, query)` → returns `{answer, sources}`
9. Return result

## Vision prompt (fixed)

```
You are extracting structured data from a screenshot of Perplexity Comet's answer page.
The user asked: "{query}"

Return STRICT JSON in this exact shape (no prose, no markdown fences):
{
  "answer": "<the main answer text, in plain prose, no citation markers>",
  "sources": [
    {"n": 1, "title": "<visible source title>"},
    ...
  ]
}

If the answer is not yet visible or still loading, return {"answer": "", "sources": []}.
If you can read the answer but no sources are visible, return sources as [].
```

## Failure modes

| Failure | Detection | Response |
|---|---|---|
| Vision returns empty answer twice | extractor returns answer="" two polls in a row | hard fail: "Vision could not read the answer. Comet may not have completed the query." |
| Vision returns invalid JSON | JSON.parse throws | retry once with stricter prompt; then fail |
| Anthropic API error | SDK throws | hard fail with API error message |
| Comet not focused / wrong window | screenshot is of something other than Comet | best-effort: vision will return empty, hits the empty-answer path above |

## Testing

- Keep `is_stream_stable` and `parse_clipboard_answer` unit tests (still useful for clipboard fallback if added later)
- Delete UIA-dependent tests + fixtures
- New small unit test for vision_extractor: mock the Anthropic client, assert prompt structure + JSON parsing
- Live smoke remains the load-bearing E2E test

## Estimated LOC delta

- Delete: ~80 LOC (extractor walk/login + fixtures + their tests)
- Add: `vision_extractor.ts` ~60 LOC, `screenshot_stability.ts` ~30 LOC, vision_extractor tests ~50 LOC
- Modify: `comet_driver.ts` (full rewrite, ~100 LOC), `ghost_client.ts` (+screenshot method, -describe_screen)
- Net: roughly same total LOC, but the dependency graph is now `comet_driver → ghost_client + vision_extractor` instead of `comet_driver → ghost_client + extractor (UIA walkers)`.
