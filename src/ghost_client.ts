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
