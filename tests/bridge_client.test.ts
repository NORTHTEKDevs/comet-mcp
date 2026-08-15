import { describe, it, expect } from "vitest";
import http from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { BridgeClient } from "../src/bridge_client.js";

type Handler = (req: IncomingMessage, res: ServerResponse, body: string) => void;

function startStub(handler: Handler): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const srv: Server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => handler(req, res, body));
    });
    srv.listen(0, "127.0.0.1", () => {
      const address = srv.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({ url: `http://127.0.0.1:${port}`, close: () => srv.close() });
    });
  });
}

describe("BridgeClient", () => {
  it("dispatch + poll returns the result", async () => {
    const relay = await startStub((req, res, body) => {
      if (req.method === "POST" && req.url === "/jobs") {
        JSON.parse(body || "{}"); // sanity: valid job payload
        res.writeHead(201, { "content-type": "application/json" });
        return res.end(JSON.stringify({ id: "1" }));
      }
      if (req.method === "GET" && req.url === "/jobs/1") {
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify({ status: "done", result: { url: "https://x", elements: [] } }));
      }
      res.writeHead(404);
      res.end("{}");
    });
    try {
      const c = new BridgeClient(relay.url, "tok");
      const id = await c.dispatch({ kind: "read", payload: { target: "page" } });
      const out = await c.result(id, { timeoutMs: 2000, pollMs: 20 });
      expect(out).toEqual({ url: "https://x", elements: [] });
    } finally {
      relay.close();
    }
  });

  // Task 36: BridgeClient is a generic { kind, payload } dispatcher already - this proves an
  // "inspect" kind round-trips through it with no client-side changes, same as "read" above.
  it(`dispatch + poll round-trips a kind:"inspect" job`, async () => {
    let sentBody: unknown;
    const relay = await startStub((req, res, body) => {
      if (req.method === "POST" && req.url === "/jobs") {
        sentBody = JSON.parse(body || "{}");
        res.writeHead(201, { "content-type": "application/json" });
        return res.end(JSON.stringify({ id: "1" }));
      }
      if (req.method === "GET" && req.url === "/jobs/1") {
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify({ status: "done", result: { source: "redacted html" } }));
      }
      res.writeHead(404);
      res.end("{}");
    });
    try {
      const c = new BridgeClient(relay.url, "tok");
      const id = await c.dispatch({
        kind: "inspect",
        payload: { kinds: ["source"], allowCookies: false, noRedact: false }
      });
      const out = await c.result(id, { timeoutMs: 2000, pollMs: 20 });
      expect(out).toEqual({ source: "redacted html" });
      expect(sentBody).toEqual({
        kind: "inspect",
        payload: { kinds: ["source"], allowCookies: false, noRedact: false }
      });
    } finally {
      relay.close();
    }
  });

  it("dispatch throws with the status and body when the relay rejects the job", async () => {
    const relay = await startStub((_req, res) => {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "bad token" }));
    });
    try {
      const c = new BridgeClient(relay.url, "wrong-tok");
      await expect(c.dispatch({ kind: "read" })).rejects.toThrow(/401/);
      await expect(c.dispatch({ kind: "read" })).rejects.toThrow(/bad token/);
    } finally {
      relay.close();
    }
  });

  it("dispatch throws a clear error when the relay response body is not JSON", async () => {
    const relay = await startStub((_req, res) => {
      res.writeHead(201, { "content-type": "text/plain" });
      res.end("<html>not json</html>");
    });
    try {
      const c = new BridgeClient(relay.url, "tok");
      await expect(c.dispatch({ kind: "read" })).rejects.toThrow(/non-JSON/i);
    } finally {
      relay.close();
    }
  });

  it("dispatch throws when the relay response is missing a job id", async () => {
    const relay = await startStub((_req, res) => {
      res.writeHead(201, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    try {
      const c = new BridgeClient(relay.url, "tok");
      await expect(c.dispatch({ kind: "read" })).rejects.toThrow(/missing job id/i);
    } finally {
      relay.close();
    }
  });

  it("result throws with the job's error message when the bridge job failed", async () => {
    const relay = await startStub((req, res) => {
      if (req.method === "POST" && req.url === "/jobs") {
        res.writeHead(201, { "content-type": "application/json" });
        return res.end(JSON.stringify({ id: "1" }));
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "error", error: "selector not found" }));
    });
    try {
      const c = new BridgeClient(relay.url, "tok");
      const id = await c.dispatch({ kind: "read" });
      await expect(c.result(id, { timeoutMs: 2000, pollMs: 20 })).rejects.toThrow(/selector not found/);
    } finally {
      relay.close();
    }
  });

  it("result throws immediately (not after the full timeout) when the relay returns a non-200 status", async () => {
    const relay = await startStub((req, res) => {
      if (req.method === "POST" && req.url === "/jobs") {
        res.writeHead(201, { "content-type": "application/json" });
        return res.end(JSON.stringify({ id: "1" }));
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "no job" }));
    });
    try {
      const c = new BridgeClient(relay.url, "tok");
      const id = await c.dispatch({ kind: "read" });
      const started = Date.now();
      await expect(c.result(id, { timeoutMs: 5000, pollMs: 20 })).rejects.toThrow(/404/);
      expect(Date.now() - started).toBeLessThan(1000);
    } finally {
      relay.close();
    }
  });

  it("result throws a clear error when a poll response body is not JSON", async () => {
    const relay = await startStub((req, res) => {
      if (req.method === "POST" && req.url === "/jobs") {
        res.writeHead(201, { "content-type": "application/json" });
        return res.end(JSON.stringify({ id: "1" }));
      }
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("not json at all");
    });
    try {
      const c = new BridgeClient(relay.url, "tok");
      const id = await c.dispatch({ kind: "read" });
      await expect(c.result(id, { timeoutMs: 2000, pollMs: 20 })).rejects.toThrow(/non-JSON/i);
    } finally {
      relay.close();
    }
  });

  it("result throws a timeout error when the job never completes, never resolving silently", async () => {
    const relay = await startStub((req, res) => {
      if (req.method === "POST" && req.url === "/jobs") {
        res.writeHead(201, { "content-type": "application/json" });
        return res.end(JSON.stringify({ id: "1" }));
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: "pending" }));
    });
    try {
      const c = new BridgeClient(relay.url, "tok");
      const id = await c.dispatch({ kind: "read" });
      await expect(c.result(id, { timeoutMs: 100, pollMs: 20 })).rejects.toThrow(/timed out/i);
    } finally {
      relay.close();
    }
  });
});