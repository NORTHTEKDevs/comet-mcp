#!/usr/bin/env node
// Usage: node scripts/capture-fixture.mjs "what is rust" tests/fixtures/rust-answer.json
import { spawn_ghost, GhostTools } from "../dist/ghost_client.js";
import { CometDriver } from "../dist/comet_driver.js";
import { writeFileSync } from "node:fs";

const [, , query, out_path] = process.argv;
if (!query || !out_path) {
  console.error("usage: capture-fixture.mjs <query> <out_json_path>");
  process.exit(2);
}

const ghost = spawn_ghost(process.env.GHOST_MCP_EXE
  ?? "C:\\Users\\Krist\\projects\\active\\ghost\\target\\release\\ghost-mcp.exe");
await ghost.call("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "capture-fixture", version: "0.0.1" }
});
const tools = new GhostTools(ghost);

// Drive Comet manually: focus, type, submit, wait, snapshot.
const driver = new CometDriver(tools);
// Hack: bypass driver.ask() so we can grab the tree mid-flow if we want.
// For now, just run ask() and dump describe_screen at the end.
await driver.ask(query, 300000);
const { tree } = await tools.describe_screen();
writeFileSync(out_path, JSON.stringify(tree, null, 2));
console.log(`wrote ${out_path}`);
process.exit(0);
