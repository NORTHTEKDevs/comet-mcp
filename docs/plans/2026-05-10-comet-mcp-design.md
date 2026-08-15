# comet-mcp — Design

**Date:** 2026-05-10
**Author:** Kristian (with Claude Code)
**Status:** approved, ready for implementation plan

## Problem

Use a Perplexity Pro/Enterprise subscription via the Comet desktop browser as a research backend for Claude Code, instead of paying per-call API fees on the official Perplexity MCP. The official MCP is already installed; this is the alternative for cost-sensitive usage and large research jobs covered by the desktop subscription.

## Locked decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | Tool surface | Single tool: `ask_perplexity({query, timeout_ms?}) -> { answer, sources }` |
| 2 | Extraction | Hybrid — clipboard for answer body, UIA for citation panel |
| 3 | Comet lifecycle | Find existing window; auto-launch if absent; assume user is signed in |
| 4 | Repo home | Standalone: `~/projects/active/comet-mcp`, GitHub `NORTHTEKDevs/comet-mcp` (private) |
| 5 | Implementation | TypeScript + Anthropic MCP SDK, npx-installable |
| 6 | Default timeout | 300000 ms (5 min); caller may override, no upper cap |
| 7 | Concurrency | Process-level mutex; one in-flight query at a time |

## Architecture

```
Claude Code  ──MCP stdio──>  comet-mcp  ──MCP stdio──>  Ghost (separate process)
                                │                            │
                                │                            └── drives Comet via SendInput + UIA + clipboard
                                │
                                └── tool: ask_perplexity({query, timeout_ms?})
                                            -> { answer, sources, truncated? }
```

**Two MCP hops on purpose.** Ghost stays a generic Windows automation primitive. comet-mcp is a thin Perplexity-specific orchestrator on top. Either side can be swapped without touching the other.

## Modules (TypeScript, single binary)

- `src/index.ts` — bin entry; wires MCP server to ghost client and driver
- `src/mcp_server.ts` — Anthropic MCP SDK server, stdio transport, single tool registration, zod input schema
- `src/ghost_client.ts` — typed wrapper over Ghost MCP tools we use: `list_windows`, `focus_window`, `launch`, `hotkey`, `type`, `get_clipboard`, `describe_screen`
- `src/comet_driver.ts` — orchestration: find-or-launch Comet, focus, type query, submit, poll-for-stable, extract, return
- `src/extractor.ts` — pure functions: `parse_clipboard_answer`, `walk_citations`, `is_login_wall`, `is_stream_stable`

## Data flow (happy path)

1. Receive `ask_perplexity({query, timeout_ms = 300000})`
2. `ghost.list_windows()`; find process `Comet.exe` or title containing `Perplexity`
   - found: `ghost.focus_window(handle)`
   - not found: `ghost.launch(comet_exe_path)`; poll `list_windows` up to 8s
3. Detect login wall via UIA tree → hard fail with actionable message if present
4. `ghost.hotkey("Ctrl+L")` to focus the ask bar
5. `ghost.type(query)`; `ghost.press("Enter")`
6. Poll loop, every 200ms, max `timeout_ms`:
   - `ghost.describe_screen()`
   - break when "Sources" subtree present AND answer text length unchanged across 2 consecutive polls
   - on timeout: continue to step 7, mark `truncated: true`
7. `ghost.hotkey("Ctrl+A")`, `ghost.hotkey("Ctrl+C")`, `answer = ghost.get_clipboard()`
8. `sources = walk_citations(uia_tree_from_step_6)`
9. Return `{ answer, sources, truncated? }`

## Error handling

| Failure | Detection | Response |
|---|---|---|
| Ghost MCP unreachable | first ghost call throws | hard fail (`-32000`): "Ghost MCP not running. Start Ghost first." |
| Comet exe not found | launch path missing | hard fail with detected install paths |
| Comet launches but window never appears | poll exhausts 8s | hard fail; suggest manual launch |
| Login wall / auth modal | UIA detects "Sign in" / "Continue" buttons | hard fail: "Comet needs login. Open it manually and sign in once." |
| Stream never stabilizes within `timeout_ms` | poll hits timeout | soft fail: return current clipboard with `truncated: true` |
| Clipboard empty after copy | `length < 10` | retry copy once; then hard fail if still empty |
| Citations panel absent | UIA walk returns `[]` | return answer with `sources: []` (not a failure) |

**Concurrency:** in-process mutex. Second concurrent `ask_perplexity` call returns `busy` immediately. Comet UI is single-threaded; parallel calls would corrupt state.

## Testing

**Three layers, scaled to risk.**

1. **Unit (vitest, ~15 tests)** — pure functions in `extractor.ts`:
   - `parse_clipboard_answer()` — strip Comet UI noise, handle empty/partial input
   - `walk_citations(uia_tree_fixture)` — extract `[{n, title, url}]`
   - `is_login_wall(uia_tree_fixture)` — detect sign-in modals
   - `is_stream_stable(prev, curr)` — boundary cases
2. **Integration (fixture-replay, ~5 scripts)** — saved real UIA trees + saved clipboard strings:
   - Capture once per Comet UI version via `node scripts/capture-fixture.mjs "<query>"`
   - Replay in tests to assert structured output. UI drift becomes a fixture-update task, not a code-debugging task.
3. **End-to-end (live Comet, 1 smoke)** — `npm run smoke`:
   - Hits real Comet with one canned query
   - Asserts answer length > 200, sources length ≥ 1
   - Local-only, run before each release. Not in CI (no Comet on GitHub Actions).

**No mocking of Ghost MCP.** Hits real Ghost in integration where applicable; fixtures cover the parts that don't need Ghost. Aligns with the project's standing rule on integration testing (mocked-DB lesson).

## Out of scope (v0)

- Multi-turn / follow-up queries
- Deep-research mode toggle
- File upload / attachments
- Concurrent queries (Comet UI can't support them anyway)
- Linux / macOS (Ghost is Windows-only)
- Auto-login / credential management
- Dedicated background Comet profile (`--user-data-dir`) — day-2 polish if focus-stealing becomes a UX problem

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| Perplexity changes Comet's UI/UX | Fixture-replay test layer makes UI drift a low-touch test-data update |
| Comet detects automation and blocks | Ghost uses native SendInput, not CDP — much harder to detect than headless Chromium |
| Slow render dominates per-query latency | Accepted trade-off vs API cost; documented in README |
| Login wall after subscription expires | Hard-fail with actionable error message; user re-authenticates manually |
| Clipboard contention with user typing | Mutex prevents internal contention; user is unlikely to be using clipboard during the 10-30s query window |

## Estimated size

- ~250 LOC core + ~150 LOC tests, single TypeScript package
- One evening to v0; one more evening to fixture-replay tests + smoke
