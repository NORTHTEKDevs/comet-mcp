import { spawn, type ChildProcess } from "node:child_process";

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

  list_windows(): Promise<{ windows: GhostWindow[] }> { return this.call("ghost_window", { op: "list" }); }
  focus_window(name: string): Promise<{ ok: true }> { return this.call("ghost_window", { op: "focus", name }); }
  launch(exe: string): Promise<{ ok: true }> { return this.call("ghost_window", { op: "launch", exe }); }
  hotkey(modifiers: string[], key: string): Promise<{ ok: true }> { return this.call("ghost_key", { keys: [...modifiers, key].join("+") }); }
  // window is optional so existing callers (comet_driver.ts) are unaffected; passing it scopes
  // the key to a specific window rather than whatever currently owns OS focus (recommended by
  // ghost_key for multi-window flows - see CometActor.credentialFill).
  press(key: string, window?: string): Promise<{ ok: true }> {
    return this.call("ghost_key", window !== undefined ? { keys: key, window } : { keys: key });
  }
  get_clipboard(): Promise<{ text: string }> { return this.call("ghost_clipboard", { op: "get" }); }
  set_clipboard(text: string): Promise<{ ok: true }> { return this.call("ghost_clipboard", { op: "set", text }); }
  screenshot_region(opts: { rect?: [number, number, number, number]; foreground?: boolean; max_dim?: number }): Promise<{ png_base64: string }> {
    return this.call("ghost_screenshot", opts);
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