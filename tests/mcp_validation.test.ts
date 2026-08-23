import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { build_mcp_server } from "../src/mcp_server.js";
import type { RunManager } from "../src/run_manager.js";

// Input-magnitude caps on every tool schema. The schemas used to accept absurd magnitudes -
// timeout_ms up to ~31 years, max_actions at Number.MAX_SAFE_INTEGER, scroll amounts of 1e9,
// within_ms near 9e15 - all of which flow straight into policy budgets and actor calls. They
// also accepted [""] in domains_allow, which hostMatches can match via its suffix logic.
// Boundary values here pin the exact caps; one-over must be rejected, at-cap accepted.

const fakeDriver = () => ({ ask: async () => ({ answer: "", sources: [] }) });

function fakeRunManager() {
  const rm = {
    begin: () => ({ run_id: "run_1" }),
    navigate: async () => ({ ok: true }),
    read: async () => ({ ok: true, result: {} }),
    act: async () => ({ ok: true }),
    extract: async () => ({ ok: true, result: {} }),
    credentialFill: async () => ({ ok: true, result: { filled: true } }),
    credentialUse: async () => ({ ok: true, result: { used: true } }),
    read2FA: async () => ({ ok: true, result: { code: "" } }),
    assistantAsk: async () => ({ ok: true, result: {} }),
    status: () => null
  };
  return rm as unknown as RunManager;
}

async function connected() {
  const server = build_mcp_server(fakeDriver(), fakeRunManager());
  const client = new Client({ name: "test-client", version: "0.0.1" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client };
}

describe("mcp input magnitude caps", () => {
  describe("comet_session_begin budgets", () => {
    const base = {
      domains_allow: ["example.com"],
      actions_allow: ["NAVIGATE"] as ("NAVIGATE")[]
    };

    it("accepts max_actions exactly at the 10_000 cap and rejects one over", async () => {
      const { client } = await connected();
      await expect(client.callTool({ name: "comet_session_begin", arguments: { ...base, max_actions: 10_000 } })).resolves.toBeDefined();
      await expect(client.callTool({ name: "comet_session_begin", arguments: { ...base, max_actions: 10_001 } })).rejects.toThrow();
    });

    it("accepts max_domains exactly at the 100 cap and rejects one over", async () => {
      const { client } = await connected();
      await expect(client.callTool({ name: "comet_session_begin", arguments: { ...base, max_domains: 100 } })).resolves.toBeDefined();
      await expect(client.callTool({ name: "comet_session_begin", arguments: { ...base, max_domains: 101 } })).rejects.toThrow();
    });

    it("accepts max_ms exactly at the 24h cap and rejects one over", async () => {
      const { client } = await connected();
      await expect(client.callTool({ name: "comet_session_begin", arguments: { ...base, max_ms: 86_400_000 } })).resolves.toBeDefined();
      await expect(client.callTool({ name: "comet_session_begin", arguments: { ...base, max_ms: 86_400_001 } })).rejects.toThrow();
    });

    it("rejects a fractional budget (integers only)", async () => {
      const { client } = await connected();
      await expect(client.callTool({ name: "comet_session_begin", arguments: { ...base, max_actions: 10.5 } })).rejects.toThrow();
    });

    it("rejects empty/whitespace entries in domains_allow, domains_deny, and credential_sites", async () => {
      const { client } = await connected();
      await expect(client.callTool({ name: "comet_session_begin", arguments: { ...base, domains_allow: [""] } })).rejects.toThrow();
      await expect(client.callTool({ name: "comet_session_begin", arguments: { ...base, domains_allow: ["   "] } })).rejects.toThrow();
      await expect(client.callTool({ name: "comet_session_begin", arguments: { ...base, domains_deny: [""] } })).rejects.toThrow();
      await expect(client.callTool({ name: "comet_session_begin", arguments: { ...base, credential_sites: [" "] } })).rejects.toThrow();
      // Real entries still pass.
      await expect(client.callTool({
        name: "comet_session_begin",
        arguments: { ...base, domains_allow: ["example.com"], domains_deny: ["other.com"], credential_sites: ["vault.example.com"] }
      })).resolves.toBeDefined();
    });
  });

  describe("comet_act scroll amount", () => {
    const base = { run_id: "run_1", kind: "SCROLL", direction: "down" as const };

    it("accepts amount exactly at the 100_000 cap and rejects one over", async () => {
      const { client } = await connected();
      await expect(client.callTool({ name: "comet_act", arguments: { ...base, amount: 100_000 } })).resolves.toBeDefined();
      await expect(client.callTool({ name: "comet_act", arguments: { ...base, amount: 100_001 } })).rejects.toThrow();
    });
  });

  describe("comet_assistant_ask timeout_ms", () => {
    it("accepts timeout_ms exactly at the 1h cap and rejects one over", async () => {
      const { client } = await connected();
      const base = { run_id: "run_1", query: "q" };
      await expect(client.callTool({ name: "comet_assistant_ask", arguments: { ...base, timeout_ms: 3_600_000 } })).resolves.toBeDefined();
      await expect(client.callTool({ name: "comet_assistant_ask", arguments: { ...base, timeout_ms: 3_600_001 } })).rejects.toThrow();
    });
  });

  describe("comet_read_2fa within_ms", () => {
    it("accepts within_ms exactly at the 1h cap and rejects one over", async () => {
      const { client } = await connected();
      const base = { run_id: "run_1" };
      await expect(client.callTool({ name: "comet_read_2fa", arguments: { ...base, within_ms: 3_600_000 } })).resolves.toBeDefined();
      await expect(client.callTool({ name: "comet_read_2fa", arguments: { ...base, within_ms: 3_600_001 } })).rejects.toThrow();
    });
  });
});
