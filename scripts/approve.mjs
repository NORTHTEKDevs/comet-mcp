#!/usr/bin/env node
// Usage: node scripts/approve.mjs <site> <fill|use|reveal> [ttl-minutes]
//
// The HUMAN's out-of-band approval path for every gated credential op (Phase 3 comet_credential_fill,
// Phase 5 comet_credential_use / comet_credential_reveal - see docs/plans/2026-08-13-comet-agent-phase3.md
// Tasks 17/22 and docs/plans/2026-08-13-comet-agent-phase5.md Tasks 24/25/28). This CLI is the ONLY
// place grantApproval is called - the agent never calls it and cannot mint, guess, or replay an
// approval for itself. Run this yourself, outside the agent's control, immediately before asking the
// agent to fill/use/reveal a saved login on the named site, and pick the action type that matches
// EXACTLY what you are about to ask for - an approval minted for one type can never be spent on
// another (see src/approvals.ts, src/credential_gate.ts).
import { homedir } from "node:os";
import { join } from "node:path";
import { grantApproval } from "../dist/approvals.js";

const DATA_DIR = process.env.COMET_DATA_DIR ?? join(homedir(), ".comet-mcp");
const APPROVALS_DIR = join(DATA_DIR, "approvals");

const ACTION_BY_ARG = {
  fill: "CREDENTIAL_FILL",
  use: "CREDENTIAL_USE",
  reveal: "CREDENTIAL_REVEAL"
};

function usage() {
  console.error("Usage: node scripts/approve.mjs <site> <fill|use|reveal> [ttl-minutes]");
  console.error("  e.g.  node scripts/approve.mjs example.com fill 5");
  console.error("  e.g.  node scripts/approve.mjs example.com use");
  console.error("  e.g.  node scripts/approve.mjs example.com reveal 2");
}

const [, , site, actionArg, ttlArg] = process.argv;
if (!site || !actionArg) {
  usage();
  process.exit(1);
}

const action = ACTION_BY_ARG[actionArg.toLowerCase()];
if (!action) {
  console.error(`Invalid action: "${actionArg}" - must be one of: fill, use, reveal.`);
  usage();
  process.exit(1);
}

const ttlMinutes = ttlArg === undefined ? 5 : Number(ttlArg);
if (!Number.isFinite(ttlMinutes) || ttlMinutes <= 0) {
  console.error(`Invalid ttl-minutes: "${ttlArg}" - must be a positive number of minutes.`);
  process.exit(1);
}
const ttlMs = ttlMinutes * 60_000;

const approval = grantApproval(APPROVALS_DIR, site, ttlMs, action);
const expiresAt = new Date(approval.expires_ms).toISOString();

console.log("WARNING: out-of-band credential approval");
console.log(`  site:   ${approval.site}`);
console.log(`  action: ${action}`);
console.log("");
switch (action) {
  case "CREDENTIAL_FILL":
    console.log(`This authorises the agent to autofill a SAVED CREDENTIAL into a login form on`);
    console.log(`"${approval.site}" the next time it asks to - via the browser's own native autofill,`);
    console.log(`comet-mcp never sees the value. ONLY that one time.`);
    break;
  case "CREDENTIAL_USE":
    console.log(`This authorises the agent to TYPE THE REAL, DECRYPTED PASSWORD for "${approval.site}"`);
    console.log(`directly into a field on the live browser - comet-mcp's own process holds the`);
    console.log(`plaintext for the duration of that call. NOT limited to the origin the credential`);
    console.log(`was saved for. ONLY that one time.`);
    break;
  case "CREDENTIAL_REVEAL":
    console.log(`*** THE MOST DANGEROUS APPROVAL IN THIS SYSTEM ***`);
    console.log(`This authorises the agent to receive the PLAINTEXT username AND password for`);
    console.log(`"${approval.site}" back in its own response - not just typed into the browser, handed`);
    console.log(`directly to the caller. ONLY that one time.`);
    break;
}
console.log("");
console.log(`Only run this if you just asked the agent to ${actionArg} a credential on that exact site.`);
console.log("");
console.log(`  id:         ${approval.id}`);
console.log(`  expires:    ${expiresAt} (${ttlMinutes} minute${ttlMinutes === 1 ? "" : "s"} from now)`);
console.log(`  single-use: yes - consumed automatically after one successful ${actionArg}`);