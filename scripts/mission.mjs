#!/usr/bin/env node
// The HUMAN's out-of-band mission-grant path (Phase 4 Task 34, see THE RISK in
// docs/plans/2026-08-14-comet-agent-phase4-unattended.md). This CLI is the ONLY place
// grantMission is called - the agent never calls it and cannot mint, forge, or replay a grant for
// itself; RunManager.beginMission only ever verifies a mission against the PUBLIC half of this
// same keypair (src/index.ts). Run this yourself, outside the agent's control, before asking an
// orchestrating agent to start an UNATTENDED mission run for one client account - the scope you
// print and sign here IS the run's entire policy; the agent can do nothing this grant did not
// authorise.
//
// Usage:
//   node scripts/mission.mjs \
//     --account client-a \
//     --domains clienta.example.com,mail.clienta.example.com \
//     --credential-sites clienta.example.com \
//     --actions NAVIGATE,READ,CLICK,TYPE,READ_2FA,CREDENTIAL_USE \
//     [--preauthorize change-password,delete] \
//     [--allow-credential-reveal] \
//     [--max-actions 100] [--max-ms 1800000] [--max-domains 3] \
//     [--ttl 15]
//
// --account, --domains, --actions are required. Everything else has a conservative default -
// see DEFAULTS below. `--ttl` is minutes until the GRANT itself expires if unused (separate from
// `--max-ms`, the run's own wall-clock budget once it starts).
import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { loadOrCreateKeys } from "../dist/audit.js";
import { grantMission } from "../dist/missions.js";
import { IRREVERSIBLE_PATTERNS } from "../dist/irreversible.js";
import { SESSION_ACTIONS } from "../dist/mcp_server.js";

const DATA_DIR = process.env.COMET_DATA_DIR ?? join(homedir(), ".comet-mcp");
const MISSIONS_DIR = join(DATA_DIR, "missions");

// Kept in sync by hand with SESSION_ACTIONS in src/mcp_server.ts - not imported (that array is
// module-local there) so this is a soft warning for a human typo, not a hard gate; an unrecognised
// action string in a signed mission can only ever narrow what the run can do, never widen it (see
// src/missions.ts's grantMission doc comment on the ActionKind cast).
// Imported from the built server, NOT retyped here. A hand-copied duplicate had already drifted:
// it was missing INSPECT and ASSISTANT, so a perfectly valid mission got a "not a recognised action
// kind - it can never match anything" warning during the live run. KNOWN_IRREVERSIBLE_TAGS below
// already derives from the real table; this now does the same. (Third time in this project that two
// copies of one list drifted apart - derive, never retype.)
const KNOWN_ACTIONS = [...SESSION_ACTIONS];
const KNOWN_IRREVERSIBLE_TAGS = IRREVERSIBLE_PATTERNS.map((p) => p.tag);

const DEFAULTS = {
  maxActions: 50,
  maxMs: 600_000,     // 10 minutes wall clock for the RUN once started
  maxDomains: 5,
  ttlMinutes: 15       // how long the GRANT itself stays usable before it must be started
};

function usage() {
  console.error("Usage: node scripts/mission.mjs --account <label> --domains <a.com,b.com> --actions <NAVIGATE,READ,...> [options]");
  console.error("  Required:");
  console.error("    --account <label>            the single client identity this mission is bound to");
  console.error("    --domains <a.com,b.com>       comma-separated domains_allow (exact host or suffix match)");
  console.error("    --actions <A,B,...>           comma-separated actions_allow, e.g. NAVIGATE,READ,CLICK,TYPE,READ_2FA");
  console.error("  Optional:");
  console.error("    --credential-sites <a.com>    comma-separated exact hosts this mission may fill/use/reveal a credential for");
  console.error("    --preauthorize <tag,tag>      irreversible-action tags this mission pre-approves (change-password|add-oauth|payment|delete|transfer)");
  console.error("    --allow-credential-reveal     opt into comet_credential_reveal for this mission (dangerous - see README)");
  console.error(`    --max-actions <n>             default ${DEFAULTS.maxActions}`);
  console.error(`    --max-ms <n>                  default ${DEFAULTS.maxMs} (run wall-clock budget once started)`);
  console.error(`    --max-domains <n>             default ${DEFAULTS.maxDomains}`);
  console.error(`    --ttl <minutes>               default ${DEFAULTS.ttlMinutes} (grant expiry if never started)`);
}

function parseArgs(argv) {
  const out = { flags: {}, bools: new Set() };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const name = arg.slice(2);
    if (name === "allow-credential-reveal") {
      out.bools.add(name);
      continue;
    }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) {
      console.error(`Missing value for --${name}`);
      usage();
      process.exit(1);
    }
    out.flags[name] = value;
    i++;
  }
  return out;
}

function splitList(v) {
  return (v ?? "").split(",").map((s) => s.trim()).filter((s) => s.length > 0);
}

function parsePositiveInt(v, fallback, flagName) {
  if (v === undefined) return fallback;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) {
    console.error(`Invalid --${flagName}: "${v}" - must be a positive number.`);
    process.exit(1);
  }
  return n;
}

const { flags, bools } = parseArgs(process.argv.slice(2));

if (!flags.account || !flags.domains || !flags.actions) {
  usage();
  process.exit(1);
}

const domains_allow = splitList(flags.domains);
const actions_allow = splitList(flags.actions);
const credential_sites = splitList(flags["credential-sites"]);
const preauthorized_irreversible = splitList(flags.preauthorize);
const allow_credential_reveal = bools.has("allow-credential-reveal");

if (domains_allow.length === 0) {
  console.error("--domains must list at least one domain.");
  process.exit(1);
}
if (actions_allow.length === 0) {
  console.error("--actions must list at least one action.");
  process.exit(1);
}

for (const a of actions_allow) {
  if (!KNOWN_ACTIONS.includes(a)) {
    console.error(`WARNING: "${a}" in --actions is not a recognised action kind - it can never match anything, so it only narrows this mission (see src/mcp_server.ts's SESSION_ACTIONS). Check for a typo.`);
  }
}
for (const t of preauthorized_irreversible) {
  if (!KNOWN_IRREVERSIBLE_TAGS.includes(t)) {
    console.error(`WARNING: "${t}" in --preauthorize is not a recognised irreversible-action tag (known: ${KNOWN_IRREVERSIBLE_TAGS.join(", ")}). Check for a typo - an unrecognised tag can never be matched by classifyAction, so it pre-authorises nothing.`);
  }
}

const max_actions = parsePositiveInt(flags["max-actions"], DEFAULTS.maxActions, "max-actions");
const max_ms = parsePositiveInt(flags["max-ms"], DEFAULTS.maxMs, "max-ms");
const max_domains = parsePositiveInt(flags["max-domains"], DEFAULTS.maxDomains, "max-domains");
const ttlMinutes = parsePositiveInt(flags.ttl, DEFAULTS.ttlMinutes, "ttl");
const expires_ms = Date.now() + ttlMinutes * 60_000;

const scope = {
  domains_allow,
  credential_sites,
  actions_allow,
  account: flags.account,
  ...(allow_credential_reveal ? { allow_credential_reveal: true } : {})
};
const budgets = { max_actions, max_ms, max_domains };

console.log("WARNING: out-of-band UNATTENDED mission grant - no human watches this run once started.");
console.log("");
console.log("This authorises an orchestrating agent to run WITHOUT a human present, scoped EXACTLY");
console.log("to the following - review every line before signing:");
console.log("");
console.log(`  account:                     ${scope.account}`);
console.log(`  domains_allow:                ${domains_allow.join(", ")}`);
console.log(`  credential_sites:             ${credential_sites.length ? credential_sites.join(", ") : "(none)"}`);
console.log(`  actions_allow:                ${actions_allow.join(", ")}`);
console.log(`  allow_credential_reveal:      ${allow_credential_reveal}`);
console.log(`  preauthorized_irreversible:   ${preauthorized_irreversible.length ? preauthorized_irreversible.join(", ") : "(none - any matched irreversible action blocks-and-pauses)"}`);
console.log(`  budgets:                      max_actions=${max_actions} max_ms=${max_ms} max_domains=${max_domains}`);
console.log(`  grant expires:                ${new Date(expires_ms).toISOString()} (${ttlMinutes} minute${ttlMinutes === 1 ? "" : "s"} from now, if not started)`);
console.log("");
console.log("Only run this if you mean to let the agent operate on this ONE client's account, with no");
console.log("human watching each step, within exactly the scope above. Cross-account work needs a");
console.log("SEPARATE grant - see the HONEST LIMITS section in README.md.");
console.log("");

mkdirSync(DATA_DIR, { recursive: true });
const { priv } = loadOrCreateKeys(DATA_DIR);
const mission = grantMission(MISSIONS_DIR, priv, {
  scope,
  budgets,
  preauthorized_irreversible,
  expires_ms
});

console.log(`  mission id:   ${mission.id}`);
console.log("");
console.log("Give this id to comet_begin_mission to start the run. Single-use: consumed the moment");
console.log("the run starts, whether or not it later completes - a crashed/killed run cannot be");
console.log("resumed on this same grant.");
