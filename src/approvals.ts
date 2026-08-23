import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

// Phase 5 (Tasks 24/25) added CREDENTIAL_USE and CREDENTIAL_REVEAL alongside Phase 3's
// CREDENTIAL_FILL. An approval's action is a hard binding, not a hint: find()'s optional third
// argument lets a caller require an exact action match, so a fill/use approval granted for one
// dangerous op can never be spent to authorise a different one (see THE RISK invariant 3 in
// docs/plans/2026-08-13-comet-agent-phase5.md).
export type ApprovalAction = "CREDENTIAL_FILL" | "CREDENTIAL_USE" | "CREDENTIAL_REVEAL";

export interface Approval {
  id: string;
  site: string;
  action: ApprovalAction;
  expires_ms: number;
  used: boolean;
  // In-flight marker for the reserve-then-confirm discipline (RunManager's credential paths).
  // Optional so every pre-existing approval file on disk stays valid: an absent field reads as
  // "not reserved". A reserved approval is NOT findable - that is the whole point: it closes the
  // window in which two concurrent callers could both pass gate 3 on one single-use grant.
  reserved?: boolean;
}

export interface ApprovalStore {
  // Fresh, unused, unreserved, unexpired, matching site (exact host match, not suffix). When
  // `action` is given, also requires an exact action match - omitting it preserves the
  // pre-Phase-5 behaviour (match any action), which is only safe because every pre-Phase-5
  // approval on disk is CREDENTIAL_FILL; every Phase 5 caller MUST pass its own action explicitly.
  find(site: string, nowMs: number, action?: ApprovalAction): Approval | null;
  // Atomically claims a specific approval for one in-flight op: unused -> reserved in ONE
  // synchronous read-modify-write, so of N concurrent callers exactly one reserve() wins and the
  // rest get false (they must deny WITHOUT touching the browser). Returns false if already used,
  // expired, missing, or already reserved.
  reserve(id: string, nowMs: number): boolean;
  // Marks used; false if already used/expired/missing. Re-reads from disk so it stays
  // correct even if this process is not the only reader/writer of the approvals dir. The caller
  // MUST check this return value after a successful actor call and deny when it is false -
  // ignoring it is what let the second racing caller through before the reserve step existed.
  consume(id: string, nowMs: number): boolean;
  // Rolls a reservation back (best-effort) when the reserved op did NOT complete - actor threw,
  // or reported failure. The grant returns to the findable pool, preserving the long-standing
  // behaviour that a failed attempt never burns the human's single-use approval. A reservation
  // stranded by a process crash simply stays unfindable until TTL expiry: fail-closed, and the
  // human re-approves.
  release(id: string): void;
}

function pathFor(dir: string, id: string): string {
  return join(dir, `${id}.json`);
}

const VALID_ACTIONS: ReadonlySet<string> = new Set(["CREDENTIAL_FILL", "CREDENTIAL_USE", "CREDENTIAL_REVEAL"]);

function isApprovalShape(obj: unknown): obj is Approval {
  if (typeof obj !== "object" || obj === null) return false;
  const a = obj as Record<string, unknown>;
  return (
    typeof a.id === "string" &&
    typeof a.site === "string" &&
    typeof a.action === "string" && VALID_ACTIONS.has(a.action) &&
    typeof a.expires_ms === "number" &&
    typeof a.used === "boolean"
  );
}

// A malformed/unparseable approval file is treated as absent, never trusted.
function readApproval(dir: string, id: string): Approval | null {
  const p = pathFor(dir, id);
  if (!existsSync(p)) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
  if (!isApprovalShape(parsed)) return null;
  return parsed;
}

function isFresh(a: Approval, nowMs: number): boolean {
  return !a.used && !a.reserved && a.expires_ms > nowMs;
}

function normalizeSite(site: string): string {
  return site.toLowerCase();
}

export function fileApprovalStore(dir: string): ApprovalStore {
  return {
    find(site, nowMs, action) {
      const target = normalizeSite(site);
      let files: string[];
      try {
        files = readdirSync(dir);
      } catch {
        return null; // missing directory -> no approvals, never throw
      }
      for (const f of files) {
        if (!f.endsWith(".json")) continue;
        const id = f.slice(0, -".json".length);
        const a = readApproval(dir, id);
        if (!a) continue;
        if (!isFresh(a, nowMs)) continue;
        if (normalizeSite(a.site) !== target) continue; // exact host match, not suffix
        if (action !== undefined && a.action !== action) continue; // exact action-type binding
        return a;
      }
      return null;
    },
    consume(id, nowMs) {
      const a = readApproval(dir, id);
      if (!a) return false;
      // consume is the CONFIRM step of reserve-then-confirm: it requires unused+unexpired, but
      // deliberately NOT "unreserved" - the caller that reserved this id is exactly who is
      // confirming. The reserved flag is cleared on use.
      if (a.used || a.expires_ms <= nowMs) return false;
      const updated: Approval = { ...a, used: true, reserved: false };
      writeFileSync(pathFor(dir, id), JSON.stringify(updated));
      return true;
    },
    reserve(id, nowMs) {
      const a = readApproval(dir, id);
      if (!a || !isFresh(a, nowMs)) return false; // isFresh also excludes already-reserved
      writeFileSync(pathFor(dir, id), JSON.stringify({ ...a, reserved: true }));
      return true;
    },
    release(id) {
      let a: Approval | null = null;
      try { a = readApproval(dir, id); } catch { return; }
      if (!a || !a.reserved || a.used) return;
      try {
        writeFileSync(pathFor(dir, id), JSON.stringify({ ...a, reserved: false }));
      } catch {
        // best-effort rollback only - see the interface comment
      }
    }
  };
}

// Human/CLI path only (Task 22). The agent must never call this. `action` defaults to
// CREDENTIAL_FILL so every pre-Phase-5 call site (scripts/approve.mjs, existing tests) keeps
// compiling and behaving identically; Phase 5 call sites pass CREDENTIAL_USE/CREDENTIAL_REVEAL
// explicitly.
export function grantApproval(dir: string, site: string, ttlMs: number, action: ApprovalAction = "CREDENTIAL_FILL"): Approval {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const approval: Approval = {
    id: randomBytes(16).toString("hex"),
    site: normalizeSite(site),
    action,
    expires_ms: Date.now() + ttlMs,
    used: false
  };
  writeFileSync(pathFor(dir, approval.id), JSON.stringify(approval));
  return approval;
}
