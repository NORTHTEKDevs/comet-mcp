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
}

export interface ApprovalStore {
  // Fresh, unused, unexpired, matching site (exact host match, not suffix). When `action` is
  // given, also requires an exact action match - omitting it preserves the pre-Phase-5 behaviour
  // (match any action), which is only safe because every pre-Phase-5 approval on disk is
  // CREDENTIAL_FILL; every Phase 5 caller MUST pass its own action explicitly.
  find(site: string, nowMs: number, action?: ApprovalAction): Approval | null;
  // Marks used; false if already used/expired/missing. Re-reads from disk so it stays
  // correct even if this process is not the only reader/writer of the approvals dir.
  consume(id: string, nowMs: number): boolean;
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
  return !a.used && a.expires_ms > nowMs;
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
      if (!isFresh(a, nowMs)) return false;
      const updated: Approval = { ...a, used: true };
      writeFileSync(pathFor(dir, id), JSON.stringify(updated));
      return true;
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
