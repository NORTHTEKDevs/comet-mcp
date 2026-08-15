// Task 29 (Phase 4). See THE RISK in
// docs/plans/2026-08-14-comet-agent-phase4-unattended.md before touching this file.
//
// A mission grant is the backstop that replaces the human watching every unattended step: no
// unattended run may start without one, and the run's policy IS the grant's scope. That only
// holds if the agent cannot mint, forge, or replay a grant itself, so every mission is
// Ed25519-signed with the audit keypair (reuse via loadOrCreateKeys in src/audit.ts). Only
// grantMission (the human/CLI path, given the PRIVATE key) can produce a valid signature;
// fileMissionStore only ever holds the PUBLIC key, so the running agent process - even if fully
// compromised - can read/verify missions but never author one that verifies.
//
// A tampered mission (any byte of scope, budgets, expiry, or the pre-authorised-irreversible
// list flipped after signing) must fail verification and collapse to null, exactly like a
// malformed or missing file - never partially trusted, never thrown.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { randomBytes, sign as edSign, verify as edVerify, createPrivateKey, createPublicKey } from "node:crypto";

export interface MissionScope {
  domains_allow: string[];
  credential_sites: string[];
  actions_allow: string[];               // the action kinds this mission may attempt
  account?: string;                       // the single client identity this mission is bound to (label)
  allow_credential_reveal?: boolean;
}

export interface Mission {
  id: string;
  scope: MissionScope;
  budgets: { max_actions: number; max_ms: number; max_domains: number };
  preauthorized_irreversible: string[];   // action-type tags this mission pre-approved; else block
  expires_ms: number;
  used: boolean;
}

export interface MissionStore {
  find(id: string, nowMs: number): Mission | null;   // fresh, unused, unexpired, signature-valid
  consume(id: string, nowMs: number): boolean;       // single-use
}

interface MissionFile {
  mission: Mission;
  sig: string; // base64 Ed25519 signature over canon(mission)
}

function pathFor(dir: string, id: string): string {
  return join(dir, `${id}.json`);
}

// Deterministic canonical JSON: object keys sorted recursively, undefined-valued properties
// dropped (so an optional field's presence-as-undefined vs. absence can never change the signed
// bytes). This is what gets signed/verified, not the raw file bytes, so field order in the
// serialized file is irrelevant to security.
function canon(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map((v) => canon(v)).join(",") + "]";
  if (value !== null && typeof value === "object") {
    const rec = value as Record<string, unknown>;
    const keys = Object.keys(rec)
      .filter((k) => rec[k] !== undefined)
      .sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canon(rec[k])).join(",") + "}";
  }
  return JSON.stringify(value);
}

function signMission(mission: Mission, privatePem: string): string {
  const key = createPrivateKey(privatePem);
  return edSign(null, Buffer.from(canon(mission)), key).toString("base64");
}

function verifyMission(mission: Mission, sig: string, publicPem: string): boolean {
  try {
    const pub = createPublicKey(publicPem);
    return edVerify(null, Buffer.from(canon(mission)), pub, Buffer.from(sig, "base64"));
  } catch {
    // Malformed key/signature material - never trust, never throw.
    return false;
  }
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

function isMissionScopeShape(obj: unknown): obj is MissionScope {
  if (typeof obj !== "object" || obj === null) return false;
  const s = obj as Record<string, unknown>;
  if (!isStringArray(s.domains_allow)) return false;
  if (!isStringArray(s.credential_sites)) return false;
  if (!isStringArray(s.actions_allow)) return false;
  if (s.account !== undefined && typeof s.account !== "string") return false;
  if (s.allow_credential_reveal !== undefined && typeof s.allow_credential_reveal !== "boolean") return false;
  return true;
}

function isBudgetsShape(obj: unknown): obj is Mission["budgets"] {
  if (typeof obj !== "object" || obj === null) return false;
  const b = obj as Record<string, unknown>;
  return typeof b.max_actions === "number" && typeof b.max_ms === "number" && typeof b.max_domains === "number";
}

function isMissionShape(obj: unknown): obj is Mission {
  if (typeof obj !== "object" || obj === null) return false;
  const m = obj as Record<string, unknown>;
  return (
    typeof m.id === "string" &&
    isMissionScopeShape(m.scope) &&
    isBudgetsShape(m.budgets) &&
    isStringArray(m.preauthorized_irreversible) &&
    typeof m.expires_ms === "number" &&
    typeof m.used === "boolean"
  );
}

// A malformed/unparseable/wrong-shape mission file is treated as absent, never trusted. So is a
// missing directory (readFileSync/existsSync simply report absence - never throws).
function readMissionFile(dir: string, id: string): MissionFile | null {
  const p = pathFor(dir, id);
  if (!existsSync(p)) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const f = parsed as Record<string, unknown>;
  if (!isMissionShape(f.mission) || typeof f.sig !== "string") return null;
  return { mission: f.mission, sig: f.sig };
}

function isFresh(m: Mission, nowMs: number): boolean {
  return !m.used && m.expires_ms > nowMs;
}

// Loads a mission strictly: shape-valid, id matches the requested id (never trust a filename
// that disagrees with its own content), and signature-valid against `publicPem`. Freshness is
// left to the caller (find() and consume() apply it differently: find() denies a stale mission
// outright, consume() re-checks it right before flipping `used`).
function loadVerified(dir: string, id: string, publicPem: string): Mission | null {
  const f = readMissionFile(dir, id);
  if (!f) return null;
  if (f.mission.id !== id) return null;
  if (!verifyMission(f.mission, f.sig, publicPem)) return null;
  return f.mission;
}

export function fileMissionStore(dir: string, publicPem: string): MissionStore {
  return {
    find(id, nowMs) {
      const mission = loadVerified(dir, id, publicPem);
      if (!mission) return null;
      if (!isFresh(mission, nowMs)) return null;
      return mission;
    },
    consume(id, nowMs) {
      const f = readMissionFile(dir, id);
      if (!f) return false;
      if (f.mission.id !== id) return false;
      if (!verifyMission(f.mission, f.sig, publicPem)) return false;
      if (!isFresh(f.mission, nowMs)) return false;
      // The signature covers `used`, so this write intentionally invalidates the stored
      // signature (no private key is available here to re-sign) - a consumed mission can never
      // pass verifyMission again, so it fails BOTH the freshness check and the signature check
      // on every future find()/consume() call. Belt and suspenders, never re-issuable.
      const updated: Mission = { ...f.mission, used: true };
      writeFileSync(pathFor(dir, id), JSON.stringify({ mission: updated, sig: f.sig } satisfies MissionFile));
      return true;
    }
  };
}

// Human/CLI path only (Task 34's scripts/mission.mjs). The agent must never see `privatePem`.
export function grantMission(dir: string, privatePem: string, m: Omit<Mission, "id" | "used">): Mission {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const mission: Mission = { ...m, id: randomBytes(16).toString("hex"), used: false };
  const sig = signMission(mission, privatePem);
  writeFileSync(pathFor(dir, mission.id), JSON.stringify({ mission, sig } satisfies MissionFile));
  return mission;
}
