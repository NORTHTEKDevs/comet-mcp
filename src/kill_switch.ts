// Task 30 (Phase 4). The unattended run controller's emergency stop - see THE RISK (invariant 5)
// in docs/plans/2026-08-14-comet-agent-phase4-unattended.md. A human (or scripts/kill.mjs, Task
// 34) creates `<DATA_DIR>/KILL`; RunManager checks isKilled() at the top of every action method
// and refuses before the actor/bridge is ever touched, on any run (attended or unattended) once a
// data dir is wired in - see THE RISK invariant 5, "kill file checked before every action".
//
// Deliberately just a file-existence check: no signature, no parsing, nothing whose own failure
// mode could flip closed->open on a malformed value. The file's mere PRESENCE is the only signal,
// and existsSync never throws - not even when `dir` itself does not exist - so this can never
// itself become the thing that breaks fail-closed behaviour.
import { existsSync } from "node:fs";
import { join } from "node:path";

export function isKilled(dir: string): boolean {
  return existsSync(join(dir, "KILL"));
}
