# comet-mcp Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship v0 of comet-mcp — a Node/TypeScript MCP server that exposes one tool, `ask_perplexity({query, timeout_ms?}) -> { answer, sources, truncated? }`, by spawning Ghost MCP as a child process and orchestrating Perplexity Comet on Windows.

**Architecture:** comet-mcp speaks MCP-stdio to Claude Code. Internally it spawns `ghost-mcp.exe` as a child and speaks MCP-stdio to it (JSON-RPC 2.0). The driver finds (or launches) Comet, types the query, polls UIA until the answer stream stabilizes, then extracts the answer from the clipboard and citations from the UIA tree. See `docs/plans/2026-05-10-comet-mcp-design.md` for the full design.

**Tech Stack:** TypeScript 5.6, Node 20+, `@modelcontextprotocol/sdk`, `zod`, `vitest`. No external runtime deps beyond MCP SDK + zod. Ghost MCP is the only system dependency (already installed at `C:\Users\Krist\projects\active\ghost\target\release\ghost-mcp.exe`).

**Conventions for this build:**
- TDD throughout: failing test → run → implement → run → commit. One commit per task.
- All paths Windows-style with forward slashes inside Node code; bash uses `/c/...` style.
- Pure functions in `extractor.ts` are tested in isolation (no Ghost). Anything that touches Ghost is integration-tested with fixture replay or live smoke.
- Commit messages: `feat:`, `test:`, `chore:`, `fix:` per the existing repo's commit log style.

---

## Prereqs (verify before Task 1)

```bash
node --version    # >= v20
ls "C:/Users/Krist/projects/active/ghost/target/release/ghost-mcp.exe"  # must exist
ls "C:/Users/Krist/AppData/Local/Comet/"                                 # must exist
```

If any check fails, STOP and surface to the user.

---

## Task 1: Install deps + verify build

**Files:**
- Modify: `package.json` (already exists, no change needed)
- Create: `package-lock.json` (npm will create)

**Step 1: Install**

```bash
cd /c/Users/Krist/projects/active/comet-mcp
npm install
```

Expected: `added N packages` with no errors. `node_modules/` and `package-lock.json` appear.

**Step 2: Verify TypeScript builds**

```bash
npx tsc --noEmit
```

Expected: exits 0 with no output. (`src/index.ts` currently throws at runtime but compiles fine.)

**Step 3: Verify vitest runs**

```bash
npx vitest run
```

Expected: "No test files found" — that's correct for now.

**Step 4: Commit**

```bash
git add package.json package-lock.json
git commit -m "chore: install deps (mcp sdk, zod, vitest)"
```

---

## Task 2: extractor.is_stream_stable (TDD)

The simplest pure function: given two consecutive answer-text snapshots, decide if streaming has stabilized.

**Files:**
- Create: `src/extractor.ts`
- Create: `tests/extractor.test.ts`

**Step 1: Write the failing test**

`tests/extractor.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { is_stream_stable } from "../src/extractor.js";

describe("is_stream_stable", () => {
  it("returns false when current is longer than previous", () => {
    expect(is_stream_stable("hello", "hello world")).toBe(false);
  });

  it("returns true when previous and current are identical and non-trivial", () => {
    expect(is_stream_stable("a complete answer", "a complete answer")).toBe(true);
  });

  it("returns false when both are empty", () => {
    expect(is_stream_stable("", "")).toBe(false);
  });

  it("returns false when below minimum length even if equal", () => {
    expect(is_stream_stable("hi", "hi")).toBe(false);
  });

  it("returns true when equal at exactly the minimum length", () => {
    const s = "x".repeat(20);
    expect(is_stream_stable(s, s)).toBe(true);
  });
});
```

**Step 2: Run test, verify it fails**

```bash
npx vitest run tests/extractor.test.ts
```

Expected: FAIL with "Cannot find module '../src/extractor.js'" (or similar import error).

**Step 3: Implement minimal**

`src/extractor.ts`:

```typescript
const MIN_STABLE_LENGTH = 20;

export function is_stream_stable(prev: string, curr: string): boolean {
  if (curr.length < MIN_STABLE_LENGTH) return false;
  return prev === curr;
}
```

**Step 4: Run test, verify pass**

```bash
npx vitest run tests/extractor.test.ts
```

Expected: 5 passed.

**Step 5: Commit**

```bash
git add src/extractor.ts tests/extractor.test.ts
git commit -m "feat(extractor): is_stream_stable pure fn + tests"
```

---

## Task 3: extractor.parse_clipboard_answer (TDD)

Strip Comet's UI cruft (header, "Sources" footer label, citation markers like `[1]` if requested) from a raw clipboard string.

**Files:**
- Modify: `src/extractor.ts`
- Modify: `tests/extractor.test.ts`

**Step 1: Add failing tests**

Append to `tests/extractor.test.ts`:

```typescript
import { parse_clipboard_answer } from "../src/extractor.js";

describe("parse_clipboard_answer", () => {
  it("returns trimmed text unchanged when no UI noise", () => {
    expect(parse_clipboard_answer("  Plain answer.  ")).toBe("Plain answer.");
  });

  it("strips a trailing 'Sources' section if present", () => {
    const raw = "The answer is 42.\n\nSources\n1. example.com\n2. other.com";
    expect(parse_clipboard_answer(raw)).toBe("The answer is 42.");
  });

  it("strips a leading 'Pro Search' / 'Quick Search' header if present", () => {
    const raw = "Pro Search\n\nThe answer is 42.";
    expect(parse_clipboard_answer(raw)).toBe("The answer is 42.");
  });

  it("returns empty string on empty input", () => {
    expect(parse_clipboard_answer("")).toBe("");
  });

  it("returns empty string on whitespace-only input", () => {
    expect(parse_clipboard_answer("   \n\t  ")).toBe("");
  });
});
```

**Step 2: Run test, verify fails**

```bash
npx vitest run tests/extractor.test.ts
```

Expected: FAIL on `parse_clipboard_answer is not exported`.

**Step 3: Implement**

Append to `src/extractor.ts`:

```typescript
const HEADER_PATTERNS = [/^Pro Search\s*\n+/i, /^Quick Search\s*\n+/i];
const SOURCES_FOOTER = /\n+Sources\s*\n[\s\S]*$/i;

export function parse_clipboard_answer(raw: string): string {
  let text = raw.trim();
  if (!text) return "";
  for (const re of HEADER_PATTERNS) text = text.replace(re, "");
  text = text.replace(SOURCES_FOOTER, "");
  return text.trim();
}
```

**Step 4: Run, verify pass**

```bash
npx vitest run tests/extractor.test.ts
```

Expected: 10 passed total.

**Step 5: Commit**

```bash
git add src/extractor.ts tests/extractor.test.ts
git commit -m "feat(extractor): parse_clipboard_answer + tests"
```

---

## Task 4: extractor.walk_citations + is_login_wall (TDD with fixtures)

These two functions consume Ghost's `describe_screen` UIA tree output. We don't have a real fixture yet (need live Comet), so we write tests against a **synthetic minimal fixture** that mirrors Ghost's actual schema. The real-Comet fixture comes in Task 12; tests can be updated there if needed.

**Ghost UIA tree shape (from `crates/ghost-core/src/uia/element.rs`):**

```typescript
type UiaNode = {
  name: string;          // accessible name (button label, text content, etc.)
  role: string;          // e.g. "button", "text", "edit", "list", "hyperlink"
  bounds?: { x: number; y: number; w: number; h: number };
  value?: string;        // for edit/text-with-value
  children?: UiaNode[];
};
```

**Files:**
- Modify: `src/extractor.ts`
- Modify: `tests/extractor.test.ts`
- Create: `tests/fixtures/answer-with-citations.json`
- Create: `tests/fixtures/login-wall.json`

**Step 1: Write synthetic fixtures**

`tests/fixtures/answer-with-citations.json`:

```json
{
  "name": "Comet",
  "role": "window",
  "children": [
    {
      "name": "Answer",
      "role": "group",
      "children": [
        { "name": "The answer body text here.", "role": "text" }
      ]
    },
    {
      "name": "Sources",
      "role": "group",
      "children": [
        { "name": "Example Domain", "role": "hyperlink", "value": "https://example.com" },
        { "name": "Other Domain", "role": "hyperlink", "value": "https://other.com" }
      ]
    }
  ]
}
```

`tests/fixtures/login-wall.json`:

```json
{
  "name": "Comet",
  "role": "window",
  "children": [
    { "name": "Sign in to Perplexity", "role": "text" },
    { "name": "Continue with Google", "role": "button" }
  ]
}
```

**Step 2: Add failing tests**

Append to `tests/extractor.test.ts`:

```typescript
import { walk_citations, is_login_wall } from "../src/extractor.js";
import answer_fixture from "./fixtures/answer-with-citations.json" with { type: "json" };
import login_fixture from "./fixtures/login-wall.json" with { type: "json" };

describe("walk_citations", () => {
  it("extracts {n, title, url} for each citation under Sources", () => {
    const sources = walk_citations(answer_fixture);
    expect(sources).toEqual([
      { n: 1, title: "Example Domain", url: "https://example.com" },
      { n: 2, title: "Other Domain", url: "https://other.com" }
    ]);
  });

  it("returns empty array if no Sources subtree present", () => {
    expect(walk_citations(login_fixture)).toEqual([]);
  });

  it("returns empty array on null/empty tree", () => {
    expect(walk_citations(null as any)).toEqual([]);
    expect(walk_citations({ name: "", role: "window" })).toEqual([]);
  });
});

describe("is_login_wall", () => {
  it("returns true when 'Sign in' text + 'Continue with' button both present", () => {
    expect(is_login_wall(login_fixture)).toBe(true);
  });

  it("returns false on a normal answer page", () => {
    expect(is_login_wall(answer_fixture)).toBe(false);
  });

  it("returns false on null/empty tree", () => {
    expect(is_login_wall(null as any)).toBe(false);
  });
});
```

**Step 3: Run, verify fails**

```bash
npx vitest run tests/extractor.test.ts
```

Expected: FAIL on missing exports.

**Step 4: Implement**

Append to `src/extractor.ts`:

```typescript
export type UiaNode = {
  name: string;
  role: string;
  bounds?: { x: number; y: number; w: number; h: number };
  value?: string;
  children?: UiaNode[];
};

export type Citation = { n: number; title: string; url: string };

function find_subtree(node: UiaNode | null | undefined, predicate: (n: UiaNode) => boolean): UiaNode | null {
  if (!node) return null;
  if (predicate(node)) return node;
  for (const child of node.children ?? []) {
    const hit = find_subtree(child, predicate);
    if (hit) return hit;
  }
  return null;
}

function flatten(node: UiaNode | null | undefined): UiaNode[] {
  if (!node) return [];
  return [node, ...(node.children ?? []).flatMap(flatten)];
}

export function walk_citations(tree: UiaNode | null | undefined): Citation[] {
  if (!tree) return [];
  const sources_node = find_subtree(tree, (n) => /^sources$/i.test(n.name));
  if (!sources_node) return [];
  const links = flatten(sources_node).filter((n) => n.role === "hyperlink" && n.value);
  return links.map((link, i) => ({
    n: i + 1,
    title: link.name,
    url: link.value!
  }));
}

export function is_login_wall(tree: UiaNode | null | undefined): boolean {
  if (!tree) return false;
  const all = flatten(tree);
  const has_sign_in = all.some((n) => /sign in/i.test(n.name));
  const has_continue_button = all.some((n) => n.role === "button" && /continue with/i.test(n.name));
  return has_sign_in && has_continue_button;
}
```

**Step 5: Run, verify pass**

```bash
npx vitest run tests/extractor.test.ts
```

Expected: 16 passed total.

**Step 6: Commit**

```bash
git add src/extractor.ts tests/extractor.test.ts tests/fixtures/
git commit -m "feat(extractor): walk_citations + is_login_wall + synthetic fixtures"
```

---

## Task 5: ghost_client.ts — JSON-RPC over stdio plumbing (TDD)

Spawn `ghost-mcp.exe` as a child, send MCP `initialize` + `tools/call` over stdio, parse responses. We test the JSON framing logic against a mock child process.

**Files:**
- Create: `src/ghost_client.ts`
- Create: `tests/ghost_client.test.ts`

**Step 1: Failing test (mocked child)**

`tests/ghost_client.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { GhostClient } from "../src/ghost_client.js";
import { EventEmitter } from "node:events";
import { Readable, Writable } from "node:stream";

class MockChild extends EventEmitter {
  stdin = new Writable({ write: (chunk, _enc, cb) => { this.written.push(chunk.toString()); cb(); } });
  stdout: Readable;
  stderr = new Readable({ read() {} });
  written: string[] = [];
  private push_cb!: (s: string) => void;

  constructor() {
    super();
    this.stdout = new Readable({
      read: () => {}
    });
    // Capture the push function
    this.push_cb = (s: string) => this.stdout.push(s);
  }

  emit_response(obj: unknown) {
    this.push_cb(JSON.stringify(obj) + "\n");
  }
}

describe("GhostClient", () => {
  it("frames a request as one JSON line and matches response by id", async () => {
    const mock = new MockChild();
    const client = new GhostClient(mock as any);
    const promise = client.call("tools/call", { name: "ghost_list_windows", arguments: {} });
    // Wait a tick so the request is written
    await new Promise((r) => setImmediate(r));
    const sent = JSON.parse(mock.written[0]!.trim());
    expect(sent.method).toBe("tools/call");
    expect(sent.id).toBeTypeOf("number");
    mock.emit_response({ jsonrpc: "2.0", id: sent.id, result: { windows: [] } });
    const result = await promise;
    expect(result).toEqual({ windows: [] });
  });

  it("rejects with error when response contains error field", async () => {
    const mock = new MockChild();
    const client = new GhostClient(mock as any);
    const promise = client.call("tools/call", {});
    await new Promise((r) => setImmediate(r));
    const sent = JSON.parse(mock.written[0]!.trim());
    mock.emit_response({ jsonrpc: "2.0", id: sent.id, error: { code: -1, message: "boom" } });
    await expect(promise).rejects.toThrow("boom");
  });
});
```

**Step 2: Run, verify fails**

```bash
npx vitest run tests/ghost_client.test.ts
```

Expected: FAIL on missing `GhostClient` export.

**Step 3: Implement**

`src/ghost_client.ts`:

```typescript
import type { ChildProcess } from "node:child_process";

type PendingResolver = {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
};

export class GhostClient {
  private next_id = 1;
  private pending = new Map<number, PendingResolver>();
  private buffer = "";

  constructor(private child: ChildProcess) {
    this.child.stdout!.on("data", (chunk: Buffer) => this.on_stdout(chunk));
    this.child.stderr?.on("data", (chunk: Buffer) => process.stderr.write(`[ghost] ${chunk}`));
    this.child.on("exit", (code) => this.on_exit(code));
  }

  call(method: string, params: unknown): Promise<unknown> {
    const id = this.next_id++;
    const payload = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.child.stdin!.write(payload, (err) => {
        if (err) {
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }

  private on_stdout(chunk: Buffer) {
    this.buffer += chunk.toString("utf8");
    let idx;
    while ((idx = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, idx).trim();
      this.buffer = this.buffer.slice(idx + 1);
      if (!line) continue;
      this.dispatch_line(line);
    }
  }

  private dispatch_line(line: string) {
    let msg: any;
    try { msg = JSON.parse(line); } catch { return; }
    if (typeof msg.id !== "number") return;
    const pending = this.pending.get(msg.id);
    if (!pending) return;
    this.pending.delete(msg.id);
    if (msg.error) pending.reject(new Error(msg.error.message ?? "ghost error"));
    else pending.resolve(msg.result);
  }

  private on_exit(code: number | null) {
    for (const { reject } of this.pending.values()) {
      reject(new Error(`ghost-mcp exited (code ${code}) with pending requests`));
    }
    this.pending.clear();
  }
}
```

**Step 4: Run, verify pass**

```bash
npx vitest run tests/ghost_client.test.ts
```

Expected: 2 passed.

**Step 5: Commit**

```bash
git add src/ghost_client.ts tests/ghost_client.test.ts
git commit -m "feat(ghost_client): json-rpc stdio plumbing + tests"
```

---

## Task 6: ghost_client.ts — typed wrapper methods + spawn helper

Add typed methods for the Ghost tools we use, plus a `spawn_ghost()` factory.

**Files:**
- Modify: `src/ghost_client.ts`

**Step 1: Append typed methods**

Append to `src/ghost_client.ts`:

```typescript
import { spawn } from "node:child_process";

export type GhostWindow = { handle: number; title: string; process: string };

export function spawn_ghost(exe_path: string): GhostClient {
  const child = spawn(exe_path, [], { stdio: ["pipe", "pipe", "pipe"] });
  const client = new GhostClient(child);
  return client;
}

// Typed sugar over `tools/call`. Each method matches a Ghost MCP tool.
export class GhostTools {
  constructor(private c: GhostClient) {}

  private async tool<T>(name: string, args: unknown = {}): Promise<T> {
    const result = await this.c.call("tools/call", { name, arguments: args });
    // MCP tools return { content: [{ type: "text", text: "..." }] }; Ghost returns
    // structured JSON inside the text. Parse it.
    const content = (result as any)?.content?.[0]?.text;
    if (typeof content !== "string") return result as T;
    try { return JSON.parse(content) as T; } catch { return content as T; }
  }

  list_windows(): Promise<{ windows: GhostWindow[] }> { return this.tool("ghost_list_windows"); }
  focus_window(handle: number): Promise<unknown> { return this.tool("ghost_focus_window", { handle }); }
  launch(path: string): Promise<unknown> { return this.tool("ghost_launch", { path }); }
  hotkey(combo: string): Promise<unknown> { return this.tool("ghost_hotkey", { combo }); }
  type(text: string): Promise<unknown> { return this.tool("ghost_type", { text }); }
  press(key: string): Promise<unknown> { return this.tool("ghost_press", { key }); }
  get_clipboard(): Promise<{ text: string }> { return this.tool("ghost_get_clipboard"); }
  describe_screen(): Promise<{ tree: unknown }> { return this.tool("ghost_describe_screen"); }
}
```

**Step 2: Verify build**

```bash
npx tsc --noEmit
```

Expected: exits 0.

**Step 3: Commit**

```bash
git add src/ghost_client.ts
git commit -m "feat(ghost_client): spawn_ghost factory + GhostTools typed wrapper"
```

> Note: tool argument names (`combo`, `path`, etc.) are the assumed Ghost MCP names. If they differ, the implementing engineer should `claude mcp get ghost` or read `crates/ghost-session/src/session.rs` to confirm and patch.

---

## Task 7: comet_driver.ts — find-or-launch Comet (with mutex)

**Files:**
- Create: `src/comet_driver.ts`

**Step 1: Implement (no unit test — covered by integration smoke)**

`src/comet_driver.ts`:

```typescript
import type { GhostTools, GhostWindow } from "./ghost_client.js";
import { is_login_wall, parse_clipboard_answer, walk_citations, is_stream_stable, type Citation, type UiaNode } from "./extractor.js";

const COMET_EXE = process.env.COMET_EXE_PATH
  ?? `${process.env.LOCALAPPDATA}\\Comet\\Application\\Comet.exe`;
const LAUNCH_POLL_MS = 500;
const LAUNCH_MAX_MS = 8000;
const STREAM_POLL_MS = 200;
const DEFAULT_TIMEOUT_MS = 300_000;

export type AskResult = {
  answer: string;
  sources: Citation[];
  truncated?: boolean;
};

export class CometDriver {
  private busy = false;

  constructor(private g: GhostTools) {}

  async ask(query: string, timeout_ms = DEFAULT_TIMEOUT_MS): Promise<AskResult> {
    if (this.busy) throw new Error("busy: a query is already in flight");
    this.busy = true;
    try {
      const win = await this.find_or_launch_comet();
      await this.g.focus_window(win.handle);
      await sleep(300);

      const initial_tree = (await this.g.describe_screen()).tree as UiaNode;
      if (is_login_wall(initial_tree)) {
        throw new Error("Comet shows a sign-in wall. Open Comet manually and sign in once, then retry.");
      }

      await this.g.hotkey("Ctrl+L");
      await sleep(150);
      await this.g.type(query);
      await this.g.press("Enter");

      const { final_tree, truncated } = await this.poll_until_stable(timeout_ms);
      await this.g.hotkey("Ctrl+A");
      await sleep(80);
      await this.g.hotkey("Ctrl+C");
      await sleep(120);
      const cb = await this.g.get_clipboard();
      let answer = parse_clipboard_answer(cb.text ?? "");
      if (answer.length < 10) {
        // one retry
        await this.g.hotkey("Ctrl+C");
        await sleep(150);
        const cb2 = await this.g.get_clipboard();
        answer = parse_clipboard_answer(cb2.text ?? "");
        if (answer.length < 10) throw new Error("clipboard empty after answer extraction");
      }
      const sources = walk_citations(final_tree);
      return truncated ? { answer, sources, truncated: true } : { answer, sources };
    } finally {
      this.busy = false;
    }
  }

  private async find_or_launch_comet(): Promise<GhostWindow> {
    const found = await this.find_comet();
    if (found) return found;
    await this.g.launch(COMET_EXE);
    const deadline = Date.now() + LAUNCH_MAX_MS;
    while (Date.now() < deadline) {
      await sleep(LAUNCH_POLL_MS);
      const w = await this.find_comet();
      if (w) return w;
    }
    throw new Error(`Comet did not appear within ${LAUNCH_MAX_MS}ms after launch (${COMET_EXE})`);
  }

  private async find_comet(): Promise<GhostWindow | null> {
    const { windows } = await this.g.list_windows();
    return windows.find((w) =>
      /comet\.exe$/i.test(w.process) || /perplexity|comet/i.test(w.title)
    ) ?? null;
  }

  private async poll_until_stable(timeout_ms: number): Promise<{ final_tree: UiaNode; truncated: boolean }> {
    const deadline = Date.now() + timeout_ms;
    let prev_text = "";
    let last_tree: UiaNode | null = null;
    while (Date.now() < deadline) {
      await sleep(STREAM_POLL_MS);
      const { tree } = await this.g.describe_screen();
      last_tree = tree as UiaNode;
      const sources_present = walk_citations(last_tree).length > 0;
      const curr_text = extract_visible_text(last_tree);
      if (sources_present && is_stream_stable(prev_text, curr_text)) {
        return { final_tree: last_tree, truncated: false };
      }
      prev_text = curr_text;
    }
    if (!last_tree) throw new Error("describe_screen never returned a tree");
    return { final_tree: last_tree, truncated: true };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function extract_visible_text(node: UiaNode | null | undefined): string {
  if (!node) return "";
  const own = node.role === "text" ? node.name : "";
  const child_text = (node.children ?? []).map(extract_visible_text).join(" ");
  return (own + " " + child_text).trim();
}
```

**Step 2: Verify build**

```bash
npx tsc --noEmit
```

Expected: 0 errors.

**Step 3: Commit**

```bash
git add src/comet_driver.ts
git commit -m "feat(comet_driver): ask() orchestration with mutex + polling"
```

---

## Task 8: mcp_server.ts — register `ask_perplexity` tool

**Files:**
- Create: `src/mcp_server.ts`

**Step 1: Implement**

`src/mcp_server.ts`:

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import type { CometDriver } from "./comet_driver.js";

const ASK_INPUT = z.object({
  query: z.string().min(1, "query is required"),
  timeout_ms: z.number().int().positive().optional()
});

export function build_mcp_server(driver: CometDriver) {
  const server = new Server(
    { name: "comet-mcp", version: "0.0.1" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "ask_perplexity",
        description: "Ask Perplexity Comet a question and get the answer + cited sources. Uses your local Comet desktop browser via Ghost MCP. Synchronous; one query in flight at a time.",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string", description: "The question to ask Perplexity." },
            timeout_ms: { type: "number", description: "Max ms to wait for the answer to finish streaming. Default 300000 (5 min)." }
          },
          required: ["query"]
        }
      }
    ]
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    if (req.params.name !== "ask_perplexity") {
      throw new Error(`unknown tool: ${req.params.name}`);
    }
    const args = ASK_INPUT.parse(req.params.arguments);
    const result = await driver.ask(args.query, args.timeout_ms);
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
    };
  });

  return server;
}

export async function run_stdio(server: ReturnType<typeof build_mcp_server>) {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
```

**Step 2: Verify build**

```bash
npx tsc --noEmit
```

Expected: 0 errors.

**Step 3: Commit**

```bash
git add src/mcp_server.ts
git commit -m "feat(mcp_server): register ask_perplexity tool"
```

---

## Task 9: index.ts — wire entrypoint

**Files:**
- Modify: `src/index.ts`

**Step 1: Replace the placeholder**

Replace the entire contents of `src/index.ts`:

```typescript
#!/usr/bin/env node
import { spawn_ghost, GhostTools } from "./ghost_client.js";
import { CometDriver } from "./comet_driver.js";
import { build_mcp_server, run_stdio } from "./mcp_server.js";

const GHOST_EXE = process.env.GHOST_MCP_EXE
  ?? "C:\\Users\\Krist\\projects\\active\\ghost\\target\\release\\ghost-mcp.exe";

async function main() {
  const ghost_client = spawn_ghost(GHOST_EXE);
  // Run MCP initialize handshake on the child once.
  await ghost_client.call("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "comet-mcp", version: "0.0.1" }
  });
  const tools = new GhostTools(ghost_client);
  const driver = new CometDriver(tools);
  const server = build_mcp_server(driver);
  await run_stdio(server);
}

main().catch((err) => {
  process.stderr.write(`comet-mcp fatal: ${err?.stack ?? err}\n`);
  process.exit(1);
});
```

**Step 2: Build to dist/**

```bash
npm run build
```

Expected: `dist/index.js` and friends appear, no errors.

**Step 3: Smoke-launch (no real query yet — just verify it boots)**

```bash
node dist/index.js < /dev/null
```

Expected: process starts, attempts to spawn ghost-mcp, then exits when stdin closes. If ghost exe path is wrong you'll see a clear "ENOENT" stderr line — fix `GHOST_MCP_EXE` env var.

**Step 4: Commit**

```bash
git add src/index.ts
git commit -m "feat(index): wire entrypoint and spawn ghost child"
```

---

## Task 10: scripts/capture-fixture.mjs — record real UIA tree

Lets us replace the synthetic fixtures with real ones once Comet is reachable.

**Files:**
- Create: `scripts/capture-fixture.mjs`

**Step 1: Implement**

`scripts/capture-fixture.mjs`:

```javascript
#!/usr/bin/env node
// Usage: node scripts/capture-fixture.mjs "what is rust" tests/fixtures/rust-answer.json
import { spawn_ghost, GhostTools } from "../dist/ghost_client.js";
import { CometDriver } from "../dist/comet_driver.js";
import { writeFileSync } from "node:fs";

const [, , query, out_path] = process.argv;
if (!query || !out_path) {
  console.error("usage: capture-fixture.mjs <query> <out_json_path>");
  process.exit(2);
}

const ghost = spawn_ghost(process.env.GHOST_MCP_EXE
  ?? "C:\\Users\\Krist\\projects\\active\\ghost\\target\\release\\ghost-mcp.exe");
await ghost.call("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "capture-fixture", version: "0.0.1" }
});
const tools = new GhostTools(ghost);

// Drive Comet manually: focus, type, submit, wait, snapshot.
const driver = new CometDriver(tools);
// Hack: bypass driver.ask() so we can grab the tree mid-flow if we want.
// For now, just run ask() and dump describe_screen at the end.
await driver.ask(query, 300000);
const { tree } = await tools.describe_screen();
writeFileSync(out_path, JSON.stringify(tree, null, 2));
console.log(`wrote ${out_path}`);
process.exit(0);
```

**Step 2: Verify it runs at all (will fail until Comet is reachable, that's fine)**

```bash
npm run build && node scripts/capture-fixture.mjs "test" tests/fixtures/test.local.json
```

Expected: either succeeds (Comet was reachable) or fails with a specific error from `comet_driver`. Either way, the script itself loads.

**Step 3: Commit**

```bash
git add scripts/capture-fixture.mjs
git commit -m "feat(scripts): capture-fixture for recording real UIA trees"
```

---

## Task 11: scripts/smoke.mjs — live end-to-end check

**Files:**
- Create: `scripts/smoke.mjs`

**Step 1: Implement**

`scripts/smoke.mjs`:

```javascript
#!/usr/bin/env node
import { spawn_ghost, GhostTools } from "../dist/ghost_client.js";
import { CometDriver } from "../dist/comet_driver.js";

const ghost = spawn_ghost(process.env.GHOST_MCP_EXE
  ?? "C:\\Users\\Krist\\projects\\active\\ghost\\target\\release\\ghost-mcp.exe");
await ghost.call("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "smoke", version: "0.0.1" }
});
const tools = new GhostTools(ghost);
const driver = new CometDriver(tools);

const t0 = Date.now();
const result = await driver.ask("In one sentence, what is Rust?");
const dt = Date.now() - t0;

console.log(`answer (${result.answer.length} chars, ${dt}ms):`);
console.log(result.answer);
console.log(`\nsources: ${result.sources.length}`);
for (const s of result.sources) console.log(`  [${s.n}] ${s.title} - ${s.url}`);

if (result.answer.length < 50) { console.error("FAIL: answer too short"); process.exit(1); }
if (result.sources.length < 1) { console.error("FAIL: no sources"); process.exit(1); }
console.log("\nSMOKE OK");
process.exit(0);
```

**Step 2: Build + run**

```bash
npm run build && node scripts/smoke.mjs
```

Expected outcomes (any of these is acceptable info, decide what to do):
- "SMOKE OK" — done. Ship it.
- Specific error message (login wall, exe not found, timeout) — fix the env/state and retry.
- Crash with stack — debug. Most likely UIA shape mismatch; capture fixture and update `walk_citations` accordingly.

**Step 3: Commit**

```bash
git add scripts/smoke.mjs
git commit -m "test(smoke): live e2e check against real Comet"
```

---

## Task 12: Register comet-mcp in Claude Code

**Files:** none modified in repo; modifies `C:\Users\Krist\.claude.json` via CLI.

**Step 1: Make the entry executable + linkable**

```bash
cd /c/Users/Krist/projects/active/comet-mcp
npm run build
npm link    # exposes `comet-mcp` on PATH from this checkout
```

**Step 2: Register at user scope**

```bash
MSYS_NO_PATHCONV=1 claude mcp add comet --scope user \
  --env GHOST_MCP_EXE="C:\\Users\\Krist\\projects\\active\\ghost\\target\\release\\ghost-mcp.exe" \
  -- comet-mcp
```

(Note `MSYS_NO_PATHCONV=1` — see `feedback_claude_mcp_add_windows.md`.)

**Step 3: Verify connection**

```bash
claude mcp get comet
```

Expected:
```
comet:
  Scope: User config
  Status: ✓ Connected
  Type: stdio
```

**Step 4: Manual end-to-end from Claude Code**

In a fresh Claude Code session, ask: *"Use the comet `ask_perplexity` tool to find the latest Tauri release version."* — verify a real answer with sources comes back.

**Step 5: Commit (no repo change, but log the registration in README)**

Update README.md "Quickstart" section with the registration command above, then:

```bash
git add README.md
git commit -m "docs: add Claude Code registration command to README"
git push
```

---

## Task 13: Final cleanup + push

**Step 1: Run full test suite**

```bash
npm test
```

Expected: all unit tests pass.

**Step 2: Run typecheck**

```bash
npm run typecheck
```

Expected: 0 errors.

**Step 3: Push everything**

```bash
git push
```

Per the auto-push rule (`feedback_auto_push.md`), every commit must reach the remote.

**Step 4: Update MEMORY.md index entry**

Add to the Active Projects section of `C:\Users\Krist\.claude\projects\C--Users-Krist\memory\MEMORY.md`:

```
### comet-mcp (SHIPPED YYYY-MM-DD — Comet bridge for Claude Code)
- Standalone MCP at NORTHTEKDevs/comet-mcp. TS + @modelcontextprotocol/sdk + zod + vitest. Spawns ghost-mcp.exe child, drives Comet via SendInput + UIA + clipboard. Single tool ask_perplexity({query, timeout_ms?}) -> {answer, sources, truncated?}. Uses Perplexity Pro/Enterprise sub instead of API; $0 marginal cost; ~10-30s/query. Registered in Claude Code at user scope.
```

---

## Implementation order summary

1. Task 1 — install deps
2. Tasks 2-4 — extractor pure functions (TDD)
3. Tasks 5-6 — ghost_client (mocked test + typed wrapper)
4. Task 7 — comet_driver
5. Task 8 — mcp_server
6. Task 9 — index entrypoint
7. Task 10 — capture-fixture script
8. Task 11 — smoke script (first live moment)
9. Task 12 — register in Claude Code
10. Task 13 — push + memory update

**If smoke fails at Task 11**, the most likely root cause is UIA tree shape divergence from the synthetic fixtures. Capture a real fixture (Task 10), inspect it, update `walk_citations` and/or `is_login_wall` selectors, re-run unit tests, re-smoke.

**If smoke fails with login wall**, the user signs in to Comet manually once, then re-runs.

**If `ghost.list_windows()` returns no Comet entries even when Comet is open**, the Ghost UIA tree may not enumerate Chromium windows by default — check Ghost logs and consider a `ghost_focus_window` by title fallback.
