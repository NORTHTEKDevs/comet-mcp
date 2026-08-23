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

  // Raw byte injection for framing tests (multi-byte UTF-8 split across chunk boundaries).
  emit_bytes(b: Buffer) {
    this.stdout.push(b);
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

  // Regression: on_stdout used to do `this.buffer += chunk.toString("utf8")`, decoding EACH
  // chunk in isolation. A multi-byte character (here U+00E9, bytes C3 A9) split across two TCP/
  // pipe chunks decoded as U+FFFD replacement garbage in chunk 1 and a stray continuation byte
  // in chunk 2, corrupting the JSON line so dispatch_line's JSON.parse silently dropped it and
  // the call hung forever. Buffers must be accumulated raw and decoded only at newline framing
  // boundaries.
  it("decodes a multi-byte char split across two stdout chunks correctly", async () => {
    const mock = new MockChild();
    const client = new GhostClient(mock as any);
    const promise = client.call("tools/call", {});
    await new Promise((r) => setImmediate(r));
    const sent = JSON.parse(mock.written[0]!.trim());
    // The answer text contains "café" - the é is the multi-byte char to be split.
    const line = JSON.stringify({ jsonrpc: "2.0", id: sent.id, result: { answer: "café" } }) + "\n";
    const raw = Buffer.from(line, "utf8");
    const splitAt = raw.indexOf(Buffer.from([0xc3])); // cut BETWEEN the surrogate byte pair
    expect(raw[splitAt]).toBe(0xc3);
    expect(raw[splitAt + 1]).toBe(0xa9);
    mock.emit_bytes(raw.subarray(0, splitAt + 1)); // first chunk ends with a LONE lead byte
    mock.emit_bytes(raw.subarray(splitAt + 1));    // second chunk starts with the continuation
    const result = await promise;
    expect(result).toEqual({ answer: "café" });
  });

  // A wedged child used to hang every in-flight call forever. With a per-call deadline the call
  // rejects after the timeout, frees its pending entry, and a LATE reply for that id is then
  // discarded safely instead of resolving a promise nobody is awaiting.
  it("rejects a call after the configured default timeout when the child never replies", async () => {
    const mock = new MockChild();
    const client = new GhostClient(mock as any, { default_timeout_ms: 50 });
    await expect(client.call("tools/call", {})).rejects.toThrow(/timed out after 50ms/);
    // Late reply arrives after the rejection: must be discarded without effect.
    mock.emit_response({ jsonrpc: "2.0", id: 1, result: { late: true } });
    await new Promise((r) => setImmediate(r));
  });

  it("still resolves normally before the default timeout elapses", async () => {
    const mock = new MockChild();
    const client = new GhostClient(mock as any, { default_timeout_ms: 5000 });
    const promise = client.call("tools/call", {});
    await new Promise((r) => setImmediate(r));
    const sent = JSON.parse(mock.written[0]!.trim());
    mock.emit_response({ jsonrpc: "2.0", id: sent.id, result: { ok: 1 } });
    await expect(promise).resolves.toEqual({ ok: 1 });
  });
});
