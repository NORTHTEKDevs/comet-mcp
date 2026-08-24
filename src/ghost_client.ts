import { spawn, type ChildProcess } from "node:child_process";

export interface GhostClientOptions {
  // Per-call deadline in ms. A JSON-RPC call to a WEDGED child used to hang forever (no reply,
  // no exit - just a stuck pipe), blocking the calling actor method indefinitely. After this
  // deadline an unanswered call rejects, frees its pending entry, and any LATE reply for that id
  // is discarded safely by dispatch_line. Set to 0 to disable (not recommended).
  default_timeout_ms?: number;
}

const DEFAULT_GHOST_TIMEOUT_MS = 30_000;

// Hard cap on buffered stdout awaiting a newline. A wedged/garbage-spewing child that never
// emits a newline would otherwise grow this buffer without bound (verified by probe: 64MB
// streamed -> 64MB buffer, ~326MB RSS). Past the cap the client declares the child broken:
// every pending call fails and the child is killed - a process flooding us with newline-less
// output is not a functioning JSON-RPC server.
const MAX_BUFFER_BYTES = 8 * 1024 * 1024;

type PendingResolver = {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
  // Cleared when the call resolves/rejects by reply or write-error; fires the deadline rejection.
  timer?: NodeJS.Timeout;
};

export class GhostClient {
  private next_id = 1;
  private pending = new Map<number, PendingResolver>();
  // Raw stdout bytes awaiting a newline framing boundary. NEVER decode incrementally: a chunk
  // boundary can land mid-multi-byte-character, and decoding each chunk in isolation corrupts
  // the character (lead byte -> U+FFFD, orphaned continuation byte) so JSON.parse silently
  // drops the whole line and the call hangs. Decode only complete lines.
  // Typed ArrayBufferLike: Buffer.concat widens to it under newer @types/node and the
  // byte-level ops used here (indexOf/subarray) are identical for either backing.
  private buffer: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  private readonly default_timeout_ms: number;

  constructor(private child: ChildProcess, opts: GhostClientOptions = {}) {
    this.default_timeout_ms = opts.default_timeout_ms ?? DEFAULT_GHOST_TIMEOUT_MS;
    this.child.stdout!.on("data", (chunk: Buffer) => this.on_stdout(chunk));
    this.child.stderr?.on("data", (chunk: Buffer) => process.stderr.write(`[ghost] ${chunk}`));
    this.child.on("exit", (code) => this.on_exit(code));
    // A spawn failure (bad exe path, permissions) emits 'error' WITHOUT 'exit'; unhandled, that
    // is an uncaught exception that kills the MCP server. Fail every pending call instead.
    this.child.on("error", () => this.on_error());
  }

  call(method: string, params: unknown): Promise<unknown> {
    const id = this.next_id++;
    const payload = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";
    return new Promise((resolve, reject) => {
      const entry: PendingResolver = { resolve, reject };
      if (this.default_timeout_ms > 0) {
        entry.timer = setTimeout(() => {
          this.pending.delete(id);
          reject(new Error(`ghost-mcp call "${method}" timed out after ${this.default_timeout_ms}ms`));
        }, this.default_timeout_ms);
      }
      this.pending.set(id, entry);
      this.child.stdin!.write(payload, (err) => {
        if (err) {
          this.clear_pending(id);
          reject(err);
        }
      });
    });
  }

  // Forward a kill to the underlying child (used by index.ts lifecycle teardown).
  kill(): void {
    try { this.child.kill(); } catch { /* already dead */ }
  }

  private clear_pending(id: number): void {
    const p = this.pending.get(id);
    if (!p) return;
    if (p.timer !== undefined) clearTimeout(p.timer);
    this.pending.delete(id);
  }

  private on_stdout(chunk: Buffer) {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > MAX_BUFFER_BYTES) {
      // Newline-less flood: declare the child broken rather than buffering without bound.
      const pending = this.buffer.length;
      this.buffer = Buffer.alloc(0);
      try { this.child.kill(); } catch { /* already dead */ }
      this.fail_all(`ghost-mcp stdout exceeded ${MAX_BUFFER_BYTES} bytes without a newline (${pending} buffered) - child killed`);
      return;
    }
    let idx;
    while ((idx = this.buffer.indexOf(0x0a)) >= 0) {
      const line = this.buffer.subarray(0, idx).toString("utf8").trim();
      this.buffer = this.buffer.subarray(idx + 1);
      if (!line) continue;
      this.dispatch_line(line);
    }
  }

  private dispatch_line(line: string) {
    let msg: any;
    try { msg = JSON.parse(line); } catch { return; }
    if (typeof msg.id !== "number") return;
    const pending = this.pending.get(msg.id);
    if (!pending) return; // unknown or already-timed-out id: late reply, discard safely
    this.clear_pending(msg.id);
    if (msg.error) pending.reject(new Error(msg.error.message ?? "ghost error"));
    else pending.resolve(msg.result);
  }

  private fail_all(message: string): void {
    for (const [id, p] of this.pending.entries()) {
      if (p.timer !== undefined) clearTimeout(p.timer);
      p.reject(new Error(message));
      void id;
    }
    this.pending.clear();
  }

  private on_exit(code: number | null) {
    this.fail_all(`ghost-mcp exited (code ${code}) with pending requests`);
  }

  private on_error() {
    this.fail_all("ghost-mcp process error (spawn failure or IPC error)");
  }
}

export type GhostWindow = { name: string; pid: number; focused: boolean };

export function spawn_ghost(exe_path: string): GhostClient {
  const child = spawn(exe_path, [], { stdio: ["pipe", "pipe", "pipe"] });
  const client = new GhostClient(child);
  return client;
}

export class GhostTools {
  constructor(private c: GhostClient) {}

  private call<T>(method: string, args: unknown = {}): Promise<T> {
    return this.c.call(method, args) as Promise<T>;
  }

  list_windows(): Promise<{ windows: Array<{ name: string; pid: number; focused: boolean }> }> { return this.call("ghost_window", { op: "list" }); }
  focus_window(name: string): Promise<{ ok: true }> { return this.call("ghost_window", { op: "focus", name }); }
  launch(exe: string): Promise<{ ok: true }> { return this.call("ghost_window", { op: "launch", exe }); }
  // REQUIRED before any real-input verb (focus/click/type/press) on ghost >= 0.19: its focus
  // policy defaults to 'background', which REJECTS every input verb with "'focus_window' has no
  // background path and the focus policy is 'background'" - found live 2026-08-23 (unit fakes
  // accepted focus unconditionally, so the suite could not see this). 'prefer_background' lets
  // the server take foreground only when an input verb actually needs it, instead of stealing
  // the user's focus on every call.
  set_focus_policy(policy: "prefer_background" | "foreground"): Promise<{ ok: true }> {
    return this.call("ghost_set_focus_policy", { policy });
  }
  hotkey(modifiers: string[], key: string): Promise<{ ok: true }> { return this.call("ghost_key", { keys: [...modifiers, key].join("+") }); }
  // window is optional so existing callers (comet_driver.ts) are unaffected; passing it scopes
  // the key to a specific window rather than whatever currently owns OS focus (recommended by
  // ghost_key for multi-window flows - see CometActor.credentialFill).
  press(key: string, window?: string): Promise<{ ok: true }> {
    return this.call("ghost_key", window !== undefined ? { keys: key, window } : { keys: key });
  }
  get_clipboard(): Promise<{ text: string }> { return this.call("ghost_clipboard", { op: "get" }); }
  set_clipboard(text: string): Promise<{ ok: true }> { return this.call("ghost_clipboard", { op: "set", text }); }
  // ghost_screenshot returns { jpeg_base64, size_bytes } - NOT png_base64. Verified live against
  // ghost-mcp.exe 2026-08-15 via raw JSON-RPC probe. Fail closed on shape drift rather than letting
  // an undefined field surface later as a crypto/vision TypeError far from the cause.
  async screenshot_region(opts: { rect?: [number, number, number, number]; foreground?: boolean; max_dim?: number }): Promise<{ jpeg_base64: string }> {
    const res = await this.call<Record<string, unknown>>("ghost_screenshot", opts);
    if (typeof res?.jpeg_base64 !== "string") {
      throw new Error(`ghost_screenshot returned no jpeg_base64 (keys: ${Object.keys(res ?? {}).join(", ")})`);
    }
    return { jpeg_base64: res.jpeg_base64 };
  }

  navigate(url: string, window: string): Promise<unknown> {
    return this.call("ghost_wait", { for: "navigate", url, window, timeout_ms: 30000 });
  }
  act(args: { action: "click" | "type"; name?: string; role?: string; text_input?: string; window?: string }): Promise<{ ok: boolean; verified?: boolean }> {
    return this.call("ghost_act", args);
  }
  // ghost_scroll REQUIRES a coordinate (or until_name/until_role) - a bare {direction, amount}
  // errors with "missing param: x". Verified against the live server 2026-08-13.
  scroll(direction: "up" | "down" | "left" | "right", x: number, y: number, amount = 3): Promise<{ ok: true }> {
    return this.call("ghost_scroll", { direction, amount, x, y });
  }
  find(args: { name?: string; role?: string; window?: string }): Promise<{ center: { x: number; y: number } }> {
    return this.call("ghost_find", args);
  }
  // Reads an element's current value (e.g. the address bar) so a caller can confirm where the
  // browser ACTUALLY landed rather than trusting that navigation went where it was asked.
  assert(args: { predicate: string; name?: string; role?: string; text?: string }): Promise<unknown> {
    return this.call("ghost_assert", args);
  }
  snapshot(args: { window?: string; actionable_only?: boolean; limit?: number } = {}): Promise<unknown> {
    return this.call("ghost_snapshot", args);
  }
}