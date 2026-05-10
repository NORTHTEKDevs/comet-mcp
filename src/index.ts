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
