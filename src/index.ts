#!/usr/bin/env node
import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawn_ghost, GhostTools } from "./ghost_client.js";
import { CometDriver } from "./comet_driver.js";
import { CometActor } from "./actor.js";
import { BridgeClient } from "./bridge_client.js";
import { AuditLog, loadOrCreateKeys } from "./audit.js";
import { RunManager, type BridgeReader } from "./run_manager.js";
import { build_mcp_server, run_stdio } from "./mcp_server.js";
import { nvidiaClient } from "./quarantine.js";
import { fileApprovalStore } from "./approvals.js";
import { cometCredentialStore } from "./credential_store.js";
import { fileMissionStore } from "./missions.js";

const GHOST_EXE = process.env.GHOST_MCP_EXE
  ?? "%USERPROFILE%\\.local\\bin\\ghost-mcp.exe";

// Every comet_* tool call is checked against policy and written to this signed, hash-chained log
// (see src/audit.ts). Defaults to a per-user data dir outside the repo so keys/log never land in
// git by accident; override with COMET_DATA_DIR for tests or a different machine layout.
const DATA_DIR = process.env.COMET_DATA_DIR ?? join(homedir(), ".comet-mcp");
const BRIDGE_URL = process.env.BRIDGE_URL ?? "http://127.0.0.1:8787";
const BRIDGE_TOKEN = process.env.BRIDGE_TOKEN ?? "";
const BRIDGE_READ_TIMEOUT_MS = 30_000;
const BRIDGE_READ_POLL_MS = 250;

// Phase 5 Task 23/24: Comet's real plaintext credential vault (see THE RISK in
// docs/plans/2026-08-13-comet-agent-phase5.md and src/credential_store.ts). Overridable for a
// non-default Chromium profile layout; never used unless a run's policy opts into
// CREDENTIAL_USE/CREDENTIAL_REVEAL and every gate on that op passes.
const COMET_PROFILE_DIR = process.env.COMET_PROFILE_DIR
  ?? join(process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local"), "Perplexity", "Comet", "User Data");

async function main() {
  const ghost_client = spawn_ghost(GHOST_EXE);
  // Lifecycle teardown: ghost-mcp.exe is a native process holding SendInput/screenshot
  // capability over the desktop - if this server dies it must die too, or an orphaned automation
  // process outlives its controller. 'exit' fires on normal shutdown AND process.exit paths;
  // SIGINT/SIGTERM get an explicit handler because Windows console close does not always run
  // 'exit' handlers for spawned children otherwise.
  const killGhost = () => { try { ghost_client.kill(); } catch { /* already dead */ } };
  process.on("exit", killGhost);
  process.on("SIGINT", () => { killGhost(); process.exit(130); });
  process.on("SIGTERM", () => { killGhost(); process.exit(143); });
  // Run MCP initialize handshake on the child once.
  await ghost_client.call("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "comet-mcp", version: "0.0.1" }
  });
  const tools = new GhostTools(ghost_client);
  // ghost >= 0.19 defaults its focus policy to 'background' and REJECTS every real-input verb
  // until a policy is set (found live 2026-08-23). 'prefer_background' allows input when a verb
  // needs it without stealing the user's focus on every call. Best-effort: an older ghost that
  // lacks the method must not brick startup (the call would reject - swallow it).
  try { await tools.set_focus_policy("prefer_background"); } catch { /* older ghost: no-op */ }
  const driver = new CometDriver(tools);

  mkdirSync(DATA_DIR, { recursive: true });
  const { priv, pub } = loadOrCreateKeys(DATA_DIR);
  const audit = new AuditLog(join(DATA_DIR, "run.audit.jsonl"), priv);

  const bridge = new BridgeClient(BRIDGE_URL, BRIDGE_TOKEN);
  const bridgeReader: BridgeReader = {
    read: (payload) =>
      bridge
        .dispatch({ kind: "read", payload })
        .then((id) => bridge.result(id, { timeoutMs: BRIDGE_READ_TIMEOUT_MS, pollMs: BRIDGE_READ_POLL_MS })),
    // Phase 6 Task 37: comet_inspect dispatches a `kind:"inspect"` job - same relay round-trip as
    // `read`, routed by extension/background.js's handleInspect to the DevTools-equivalent
    // inspection module instead of the page reader.
    inspect: (payload) =>
      bridge
        .dispatch({ kind: "inspect", payload })
        .then((id) => bridge.result(id, { timeoutMs: BRIDGE_READ_TIMEOUT_MS, pollMs: BRIDGE_READ_POLL_MS })),
    // Preferred navigation path (CometActor.navigate falls back to Ghost). Driving the tab through
    // the extension needs no OS foreground and no keystrokes, which is what makes it reliable here:
    // Ghost's omnibox navigation was observed live dropping a leading character, silently no-opping
    // while returning ok:true, and losing foreground to other apps mid-action.
    navigate: (url: string, timeoutMs?: number) =>
      bridge
        .dispatch({ kind: "navigate", payload: { url, timeout_ms: timeoutMs ?? 30_000 } })
        .then((id) => bridge.result(id, { timeoutMs: (timeoutMs ?? 30_000) + 5_000, pollMs: BRIDGE_READ_POLL_MS })) as Promise<{ url?: string; error?: string }>
  };

  // Phase 3: CometActor's credentialFill verifies a fill by shape (value_present) via this same
  // bridge reader - it never reads a value, so reusing bridgeReader here is safe.
  const actor = new CometActor(tools, bridgeReader);

  // Phase 3: single-use TTL-bounded out-of-band approvals live alongside the audit log/keys, in
  // their own subdirectory. grantApproval (the human's CLI path, scripts/approve.mjs) writes here;
  // the agent only ever reads via ApprovalStore.find/consume - it can never mint its own.
  const approvalStore = fileApprovalStore(join(DATA_DIR, "approvals"));

  // Phase 5 Task 23/24: the real DPAPI+AES-GCM+SQLite vault reader. RunManager.credentialUse is
  // the only caller; it never receives this store unless wired here.
  const credentialStore = cometCredentialStore(COMET_PROFILE_DIR);

  // Task 29/34 (Phase 4): signed, scoped, single-use unattended mission grants, reusing the SAME
  // Ed25519 keypair as the audit log (loadOrCreateKeys above) - only the PUBLIC half (`pub`) is
  // ever handed to this running process; grantMission (the human/CLI path, scripts/mission.mjs)
  // is the only caller that ever sees `priv`, so this process can verify a mission but never
  // author one that verifies. Missions live alongside the audit log/approvals, in their own
  // subdirectory.
  const missionStore = fileMissionStore(join(DATA_DIR, "missions"), pub);

  const runManager = new RunManager(
    actor, bridgeReader, audit, nvidiaClient(), () => Date.now(),
    approvalStore, credentialStore, missionStore, DATA_DIR
  );

  const server = build_mcp_server(driver, runManager);
  await run_stdio(server);
}

main().catch((err) => {
  process.stderr.write(`comet-mcp fatal: ${err?.stack ?? err}\n`);
  process.exit(1);
});