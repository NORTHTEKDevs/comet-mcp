#!/usr/bin/env node
// The HUMAN's emergency stop for every unattended run (Phase 4 Task 30/34, see THE RISK invariant
// 5 in docs/plans/2026-08-14-comet-agent-phase4-unattended.md). RunManager checks for
// `<COMET_DATA_DIR>/KILL` at the TOP of every action method on EVERY run, attended or unattended
// (src/kill_switch.ts). This is deliberately a bare file-existence check, not a signed record -
// the human needs an instant, unambiguous stop, not another approval flow to reason about under
// pressure.
//
// Usage:
//   node scripts/kill.mjs           # engage: writes <COMET_DATA_DIR>/KILL, stops every run now
//   node scripts/kill.mjs on        # same as above
//   node scripts/kill.mjs off       # disengage: removes the file, allows NEW runs to start again
//   node scripts/kill.mjs status    # print whether the switch is currently engaged
//
// Engaging does not un-kill a run that already latched `killed` internally (see
// RunManager.checkKillSwitch's doc comment) - a run that observed KILL even once stays dead for
// its own lifetime even after `off`, by design. `off` only lets a NEW comet_begin_mission /
// comet_session_begin proceed again.
import { existsSync, mkdirSync, writeFileSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const DATA_DIR = process.env.COMET_DATA_DIR ?? join(homedir(), ".comet-mcp");
const KILL_PATH = join(DATA_DIR, "KILL");

const mode = (process.argv[2] ?? "on").toLowerCase();

if (mode === "status") {
  console.log(existsSync(KILL_PATH) ? `ENGAGED - ${KILL_PATH} exists` : `not engaged - ${KILL_PATH} absent`);
  process.exit(0);
}

if (mode === "off") {
  if (existsSync(KILL_PATH)) {
    unlinkSync(KILL_PATH);
    console.log(`Kill switch DISENGAGED - removed ${KILL_PATH}`);
    console.log("New comet_begin_mission / comet_session_begin calls may proceed. A run that already");
    console.log("observed the kill file stays killed for its own lifetime regardless.");
  } else {
    console.log(`Kill switch was already off - ${KILL_PATH} does not exist.`);
  }
  process.exit(0);
}

if (mode !== "on") {
  console.error(`Unknown mode: "${mode}" - use "on" (default), "off", or "status".`);
  process.exit(1);
}

mkdirSync(DATA_DIR, { recursive: true });
writeFileSync(KILL_PATH, `killed at ${new Date().toISOString()} via scripts/kill.mjs\n`);
console.log(`Kill switch ENGAGED - wrote ${KILL_PATH}`);
console.log("Every unattended AND attended run will refuse its next action from now on, before the");
console.log("actor or bridge is ever touched. Run `node scripts/kill.mjs off` to allow new runs again.");
