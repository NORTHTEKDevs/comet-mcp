#!/usr/bin/env node
import { spawn_ghost, GhostTools } from "../dist/ghost_client.js";
import { CometDriver } from "../dist/comet_driver.js";

const ghost = spawn_ghost(process.env.GHOST_MCP_EXE
  ?? "C:\\Users\\Krist\\projects\\active\\ghost\\target\\release\\ghost-mcp.exe");
await ghost.call("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "smoke", version: "0.0.1" }
});
const tools = new GhostTools(ghost);
const driver = new CometDriver(tools);

const t0 = Date.now();
const result = await driver.ask("In one sentence, what is Rust?");
const dt = Date.now() - t0;

console.log(`answer (${result.answer.length} chars, ${dt}ms${result.truncated ? ", truncated" : ""}):`);
console.log(result.answer);
console.log(`\nsources: ${result.sources.length}`);
for (const s of result.sources) console.log(`  [${s.n}] ${s.title}`);

if (result.answer.length < 50) { console.error("FAIL: answer too short"); process.exit(1); }
console.log("\nSMOKE OK");
process.exit(0);
