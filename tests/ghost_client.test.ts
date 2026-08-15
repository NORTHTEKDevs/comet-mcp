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
