#!/usr/bin/env node
// Usage:
//   1. Open Comet manually, ask a real query (e.g., "what is rust"), wait for the answer to render fully
//   2. node scripts/inspect.mjs            -> dumps current Comet UI to scripts/inspect-output.json
// Captures one snapshot of describe_screen("Comet") so we can see what elements/roles Perplexity actually exposes.
import { spawn_ghost, GhostTools } from "../dist/ghost_client.js";
import { writeFileSync } from "node:fs";

const ghost = spawn_ghost(process.env.GHOST_MCP_EXE
  ?? "C:\\Users\\Krist\\projects\\active\\ghost\\target\\release\\ghost-mcp.exe");
await ghost.call("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "inspect", version: "0.0.1" }
});
const tools = new GhostTools(ghost);

const { windows } = await tools.list_windows();
console.log("Windows visible to Ghost:");
for (const w of windows) console.log(`  ${w.focused ? "*" : " "} [${w.pid}] ${w.name}`);

const comet = windows.find((w) => /comet|perplexity/i.test(w.name));
if (!comet) {
  console.error("No Comet window found in ghost_list_windows. Make sure Comet is open.");
  process.exit(1);
}
console.log(`\nMatched Comet window: "${comet.name}"`);

await tools.focus_window(comet.name);
await new Promise((r) => setTimeout(r, 500));

const { elements } = await tools.describe_screen(comet.name);
console.log(`\nGot ${elements.length} elements. Writing to scripts/inspect-output.json`);
writeFileSync("scripts/inspect-output.json", JSON.stringify({
  window: comet.name,
  count: elements.length,
  elements
}, null, 2));

console.log("\nFirst 30 elements:");
for (const e of elements.slice(0, 30)) {
  console.log(`  [${e.role}] "${e.name}"  (${e.left},${e.top})-(${e.right},${e.bottom})`);
}
console.log(`\n(see scripts/inspect-output.json for the full ${elements.length}-element dump)`);
process.exit(0);
