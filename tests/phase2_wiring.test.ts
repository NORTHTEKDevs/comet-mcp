import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { build_mcp_server } from "../src/mcp_server.js";
import type { RunManager } from "../src/run_manager.js";

// Minimal fake driver/RunManager so we can drive the real MCP request/response plumbing
// (via the SDK's InMemoryTransport) without a real Ghost/browser or bridge.
const fakeDriver = () => ({ ask: async () => ({ answer: "", sources: [] }) });

function fakeRunManager() {
  const calls: { method: string; args: unknown[] }[] = [];
  const rm = {
    begin: (policy: unknown) => { calls.push({ method: "begin", args: [policy] }); return { run_id: "run_1" }; },
    navigate: async (...args: unknown[]) => { calls.push({ method: "navigate", args }); return { ok: true }; },
    read: async (...args: unknown[]) => { calls.push({ method: "read", args }); return { ok: true, result: {} }; },
    act: async (...args: unknown[]) => { calls.push({ method: "act", args }); return { ok: true }; },
    extract: async (...args: unknown[]) => {
      calls.push({ method: "extract", args });
      return { ok: true, result: { fields: { sender: "boss@corp.com" }, provenance: { origins: ["mail.google.com"], trust: "untrusted" } } };
    },
    status: (...args: unknown[]) => { calls.push({ method: "status", args }); return null; }
  };
  return { rm: rm as unknown as RunManager, calls };
}

async function connected(rm: RunManager) {
  const server = build_mcp_server(fakeDriver() as any, rm);
  const client = new Client({ name: "test-client", version: "0.0.1" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, server };
}

describe("phase 2 MCP wiring", () => {
  it("lists comet_extract as a tool", async () => {
    const { rm } = fakeRunManager();
    const { client } = await connected(rm);
    const { tools } = await client.listTools();
    expect(tools.map(t => t.name)).toContain("comet_extract");
  });

  it("comet_session_begin's schema accepts content_mode and passes it through to RunManager.begin", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    await client.callTool({
      name: "comet_session_begin",
      arguments: { domains_allow: ["mail.google.com"], actions_allow: ["NAVIGATE"], content_mode: "raw" }
    });
    const begin = calls.find(c => c.method === "begin");
    expect(begin).toBeDefined();
    expect((begin!.args[0] as any).content_mode).toBe("raw");
  });

  it("comet_session_begin omits content_mode from the policy when not given (RunManager applies its own default)", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    await client.callTool({
      name: "comet_session_begin",
      arguments: { domains_allow: ["mail.google.com"], actions_allow: ["NAVIGATE"] }
    });
    const begin = calls.find(c => c.method === "begin");
    expect((begin!.args[0] as any).content_mode).toBeUndefined();
  });

  it("comet_session_begin's actions_allow enum accepts EXTRACT", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    await client.callTool({
      name: "comet_session_begin",
      arguments: { domains_allow: ["mail.google.com"], actions_allow: ["NAVIGATE", "EXTRACT"] }
    });
    const begin = calls.find(c => c.method === "begin");
    expect((begin!.args[0] as any).actions_allow).toEqual(["NAVIGATE", "EXTRACT"]);
  });

  it("comet_extract dispatches to RunManager.extract with run_id and fields, and returns its result", async () => {
    const { rm, calls } = fakeRunManager();
    const { client } = await connected(rm);
    const result = await client.callTool({
      name: "comet_extract",
      arguments: { run_id: "run_1", fields: [{ name: "sender", description: "who sent this" }] }
    });
    const extract = calls.find(c => c.method === "extract");
    expect(extract).toBeDefined();
    expect(extract!.args).toEqual(["run_1", [{ name: "sender", description: "who sent this" }]]);
    const content = (result as any).content;
    const parsed = JSON.parse(content[0].text);
    expect(parsed).toEqual({
      ok: true,
      result: {
        fields: { sender: "boss@corp.com" },
        provenance: { origins: ["mail.google.com"], trust: "untrusted" }
      }
    });
  });

  it("comet_extract rejects a call with no fields", async () => {
    const { rm } = fakeRunManager();
    const { client } = await connected(rm);
    await expect(
      client.callTool({ name: "comet_extract", arguments: { run_id: "run_1", fields: [] } })
    ).rejects.toThrow();
  });
});