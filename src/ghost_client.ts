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

  list_windows(): Promise<{ windows: GhostWindow[] }> { return this.call("ghost_list_windows"); }
  focus_window(name: string): Promise<{ ok: true }> { return this.call("ghost_focus_window", { name }); }
  launch(path: string): Promise<{ ok: true }> { return this.call("ghost_launch", { path }); }
  hotkey(modifiers: string[], key: string): Promise<{ ok: true }> { return this.call("ghost_hotkey", { modifiers, key }); }
  press(key: string): Promise<{ ok: true }> { return this.call("ghost_press", { key }); }
  get_clipboard(): Promise<{ text: string }> { return this.call("ghost_get_clipboard"); }
  set_clipboard(text: string): Promise<{ ok: true }> { return this.call("ghost_set_clipboard", { text }); }
  screenshot_region(opts: { rect?: [number, number, number, number]; foreground?: boolean; max_dim?: number }): Promise<{ png_base64: string }> {
    return this.call("ghost_screenshot_region", opts);
  }
}
