#!/usr/bin/env node
// One-command setup for comet-mcp.
//
// Turns the six-step manual install (clone x2, build, mint a token, wire the extension config,
// hand-write a `claude mcp add` line) into: `node scripts/setup.mjs`. Idempotent - safe to re-run;
// it never overwrites an existing token, and re-running is the supported way to reprint the
// registration command.
//
// Node builtins only, on purpose: a setup script that needs `npm install` before it can help you
// isn't a setup script.
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const MCP_ROOT = resolve(HERE, "..");
const argv = process.argv.slice(2);
const flag = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? (argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[i + 1] : true) : undefined;
};

const c = {
  b: (s) => `\x1b[1m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`,
  g: (s) => `\x1b[32m${s}\x1b[0m`, y: (s) => `\x1b[33m${s}\x1b[0m`, r: (s) => `\x1b[31m${s}\x1b[0m`,
};
const ok = (s) => console.log(`  ${c.g("✓")} ${s}`);
const warn = (s) => console.log(`  ${c.y("!")} ${s}`);
const die = (s, hint) => { console.error(`\n  ${c.r("✗")} ${s}`); if (hint) console.error(`    ${c.dim(hint)}`); process.exit(1); };

console.log(`\n${c.b("comet-mcp setup")}\n`);

// ---------------------------------------------------------------- 1. runtime
const major = Number(process.versions.node.split(".")[0]);
if (major < 20) die(`Node ${process.versions.node} is too old.`, "Node 20+ required (node:sqlite needs 22+ for the optional credential features).");
ok(`Node ${process.versions.node}`);

// ---------------------------------------------------------------- 2. build comet-mcp
if (!existsSync(join(MCP_ROOT, "node_modules"))) {
  console.log(`  ${c.dim("installing comet-mcp dependencies...")}`);
  execFileSync("npm", ["install"], { cwd: MCP_ROOT, stdio: "inherit", shell: true });
}
const DIST = join(MCP_ROOT, "dist", "index.js");
if (!existsSync(DIST) || flag("rebuild")) {
  console.log(`  ${c.dim("building...")}`);
  execFileSync("npm", ["run", "build"], { cwd: MCP_ROOT, stdio: "inherit", shell: true });
}
if (!existsSync(DIST)) die("build did not produce dist/index.js");
ok(`built  ${c.dim(DIST)}`);

// ---------------------------------------------------------------- 3. locate comet-bridge
const bridgeCandidates = [
  typeof flag("bridge") === "string" ? resolve(flag("bridge")) : null,
  resolve(MCP_ROOT, "..", "comet-bridge"),
  resolve(MCP_ROOT, "..", "comet-bridge-main"),
].filter(Boolean);
const BRIDGE = bridgeCandidates.find((p) => existsSync(join(p, "relay", "server.js")));
if (!BRIDGE) {
  die("could not find comet-bridge (the relay + browser extension).",
      `Clone it beside this repo:\n      git clone https://github.com/NORTHTEKDevs/comet-bridge\n    or pass --bridge <path>`);
}
ok(`bridge  ${c.dim(BRIDGE)}`);

// ---------------------------------------------------------------- 4. relay token (never overwrite)
const TOKEN_PATH = join(BRIDGE, "relay", "bridge.token");
let token;
if (existsSync(TOKEN_PATH)) {
  token = readFileSync(TOKEN_PATH, "utf8").trim();
  ok("relay token (existing, reused)");
} else {
  token = randomBytes(24).toString("hex");
  mkdirSync(dirname(TOKEN_PATH), { recursive: true });
  writeFileSync(TOKEN_PATH, token, { mode: 0o600 });
  ok("relay token generated");
}

// ---------------------------------------------------------------- 5. extension config
const CFG = join(BRIDGE, "extension", "config.js");
const CFG_EXAMPLE = join(BRIDGE, "extension", "config.example.js");
if (!existsSync(CFG)) {
  if (!existsSync(CFG_EXAMPLE)) die(`missing ${CFG_EXAMPLE}`);
  const filled = readFileSync(CFG_EXAMPLE, "utf8").replace("PASTE_TOKEN_FROM_relay/bridge.token", token);
  writeFileSync(CFG, filled);
  ok("extension/config.js written");
} else {
  const cur = readFileSync(CFG, "utf8");
  if (!cur.includes(token)) warn("extension/config.js exists but its token does not match relay/bridge.token - the extension will get 401s. Delete it and re-run to regenerate.");
  else ok("extension/config.js (token matches)");
}

// ---------------------------------------------------------------- 6. Comet present?
const LOCALAPPDATA = process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local");
const COMET_EXE = join(LOCALAPPDATA, "Perplexity", "Comet", "Application", "comet.exe");
if (process.platform === "win32") {
  existsSync(COMET_EXE) ? ok("Comet found") : warn(`Comet not found at ${COMET_EXE} - install Comet, or set COMET_EXE_PATH.`);
} else {
  warn(`platform is ${process.platform}. The Perplexity research bridge works cross-platform; the credential and OS-input features are Windows-only.`);
}

// ---------------------------------------------------------------- 7. optionally start the relay
if (flag("start-relay")) {
  const child = spawn(process.execPath, [join(BRIDGE, "relay", "server.js")], {
    cwd: BRIDGE, detached: true, stdio: "ignore",
    env: { ...process.env, BRIDGE_TOKEN: token },
  });
  child.unref();
  ok(`relay started in the background (pid ${child.pid}) on 127.0.0.1:8787`);
}

// ---------------------------------------------------------------- 8. what's left for a human
const nvidiaKey = process.env.NVIDIA_API_KEY;
const addCmd = [
  `claude mcp add comet --scope user`,
  `  --env BRIDGE_URL="http://127.0.0.1:8787"`,
  `  --env BRIDGE_TOKEN="${token}"`,
  nvidiaKey ? `  --env NVIDIA_API_KEY="${nvidiaKey}"` : `  --env NVIDIA_API_KEY="nvapi-..."   # free at build.nvidia.com`,
  `  -- node "${DIST}"`,
].join(" \\\n");

console.log(`\n${c.b("Two things only a human can do:")}\n`);
console.log(`  ${c.b("1.")} Load the extension in Comet`);
console.log(`     comet://extensions  →  Developer mode ON  →  ${c.b("Load unpacked")}  →  select:`);
console.log(`     ${c.dim(join(BRIDGE, "extension"))}`);
console.log(`     ${c.dim("(re-run this after any extension change: same page → reload icon)")}\n`);
console.log(`  ${c.b("2.")} Register the MCP server${flag("start-relay") ? "" : " (and start the relay)"}`);
if (!flag("start-relay")) {
  console.log(`     ${c.dim(`# relay, leave running:`)}`);
  console.log(`     node "${join(BRIDGE, "relay", "server.js")}"\n`);
}
console.log(`${addCmd}\n`);
console.log(`${c.dim("Then restart Claude Code and run:  comet_session_begin  →  comet_assistant_ask")}`);
console.log(`${c.dim("Advanced (saved logins, unattended missions) are opt-in - read SECURITY.md first.")}\n`);
