import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileMissionStore, grantMission, type Mission, type MissionScope } from "../src/missions.js";

function keys() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    pub: publicKey.export({ type: "spki", format: "pem" }).toString()
  };
}

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "missions-"));
}

const baseScope: MissionScope = {
  domains_allow: ["client-a.example.com"],
  credential_sites: ["client-a.example.com"],
  actions_allow: ["NAVIGATE", "TYPE", "CLICK"],
  account: "client-a"
};

function baseGrant(overrides?: Partial<Omit<Mission, "id" | "used">>): Omit<Mission, "id" | "used"> {
  return {
    scope: baseScope,
    budgets: { max_actions: 50, max_ms: 600_000, max_domains: 1 },
    preauthorized_irreversible: [],
    expires_ms: Date.now() + 60_000,
    ...overrides
  };
}

describe("missions", () => {
  it("a granted mission is found and its scope round-trips", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const granted = grantMission(dir, priv, baseGrant());
    const store = fileMissionStore(dir, pub);
    const found = store.find(granted.id, Date.now());
    expect(found).not.toBeNull();
    expect(found!.id).toBe(granted.id);
    expect(found!.used).toBe(false);
    expect(found!.scope).toEqual(baseScope);
    expect(found!.budgets).toEqual({ max_actions: 50, max_ms: 600_000, max_domains: 1 });
    rmSync(dir, { recursive: true, force: true });
  });

  it("does not find an expired mission", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const now = Date.now();
    const granted = grantMission(dir, priv, baseGrant({ expires_ms: now + 1_000 }));
    const store = fileMissionStore(dir, pub);
    const found = store.find(granted.id, now + 2_000);
    expect(found).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("does not find an already-used mission", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const now = Date.now();
    const granted = grantMission(dir, priv, baseGrant());
    const store = fileMissionStore(dir, pub);
    expect(store.consume(granted.id, now)).toBe(true);
    const found = store.find(granted.id, now);
    expect(found).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("does not find a mission for a wrong/unknown id", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    grantMission(dir, priv, baseGrant());
    const store = fileMissionStore(dir, pub);
    const found = store.find("not-a-real-mission-id", Date.now());
    expect(found).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("a byte-flipped scope fails signature verification -> null", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const granted = grantMission(dir, priv, baseGrant());
    const store = fileMissionStore(dir, pub);
    const p = join(dir, `${granted.id}.json`);
    const file = JSON.parse(readFileSync(p, "utf8"));
    file.mission.scope.domains_allow.push("attacker.example.com"); // widen scope after signing
    writeFileSync(p, JSON.stringify(file));
    const found = store.find(granted.id, Date.now());
    expect(found).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("a byte-flipped budget fails signature verification -> null", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const granted = grantMission(dir, priv, baseGrant());
    const store = fileMissionStore(dir, pub);
    const p = join(dir, `${granted.id}.json`);
    const file = JSON.parse(readFileSync(p, "utf8"));
    file.mission.budgets.max_actions = 999_999; // inflate budget after signing
    writeFileSync(p, JSON.stringify(file));
    const found = store.find(granted.id, Date.now());
    expect(found).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("a byte-flipped expiry fails signature verification -> null", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const now = Date.now();
    const granted = grantMission(dir, priv, baseGrant({ expires_ms: now + 1_000 }));
    const store = fileMissionStore(dir, pub);
    const p = join(dir, `${granted.id}.json`);
    const file = JSON.parse(readFileSync(p, "utf8"));
    file.mission.expires_ms = now + 1_000_000_000; // extend TTL after signing
    writeFileSync(p, JSON.stringify(file));
    const found = store.find(granted.id, now + 2_000);
    expect(found).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("a mission signed with a different keypair never verifies (agent cannot forge a grant)", () => {
    const dir = freshDir();
    const { priv } = keys();
    const other = keys(); // store trusts a DIFFERENT public key than the one that signed
    const granted = grantMission(dir, priv, baseGrant());
    const store = fileMissionStore(dir, other.pub);
    expect(store.find(granted.id, Date.now())).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("consume returns true exactly once, then false on replay", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const now = Date.now();
    const granted = grantMission(dir, priv, baseGrant());
    const store = fileMissionStore(dir, pub);
    expect(store.consume(granted.id, now)).toBe(true);
    expect(store.consume(granted.id, now)).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("consume returns false for an expired mission", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const now = Date.now();
    const granted = grantMission(dir, priv, baseGrant({ expires_ms: now + 1_000 }));
    const store = fileMissionStore(dir, pub);
    expect(store.consume(granted.id, now + 2_000)).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("consume returns false for a missing id", () => {
    const dir = freshDir();
    const { pub } = keys();
    const store = fileMissionStore(dir, pub);
    expect(store.consume("no-such-id", Date.now())).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("consume returns false for a tampered mission (cannot smuggle a widened grant into use)", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const granted = grantMission(dir, priv, baseGrant());
    const store = fileMissionStore(dir, pub);
    const p = join(dir, `${granted.id}.json`);
    const file = JSON.parse(readFileSync(p, "utf8"));
    file.mission.scope.actions_allow.push("DELETE_ACCOUNT");
    writeFileSync(p, JSON.stringify(file));
    expect(store.consume(granted.id, Date.now())).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("ignores a malformed/unparseable mission file", () => {
    const dir = freshDir();
    const { pub } = keys();
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "bad.json"), "{ this is not valid json");
    const store = fileMissionStore(dir, pub);
    expect(store.find("bad", Date.now())).toBeNull();
    expect(store.consume("bad", Date.now())).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });

  it("ignores a mission file with the wrong shape", () => {
    const dir = freshDir();
    const { pub } = keys();
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "shape.json"), JSON.stringify({ mission: { id: "shape" }, sig: "x" }));
    const store = fileMissionStore(dir, pub);
    expect(store.find("shape", Date.now())).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("ignores a mission file whose embedded id disagrees with its filename", () => {
    const dir = freshDir();
    const { priv, pub } = keys();
    const granted = grantMission(dir, priv, baseGrant());
    const raw = readFileSync(join(dir, `${granted.id}.json`), "utf8");
    writeFileSync(join(dir, "spoofed-id.json"), raw); // same signed content, different filename/id
    const store = fileMissionStore(dir, pub);
    expect(store.find("spoofed-id", Date.now())).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("a missing directory yields no missions rather than throwing", () => {
    const dir = join(tmpdir(), "missions-does-not-exist-" + Math.random().toString(36).slice(2));
    const { pub } = keys();
    const store = fileMissionStore(dir, pub);
    expect(() => store.find("whatever", Date.now())).not.toThrow();
    expect(store.find("whatever", Date.now())).toBeNull();
    expect(() => store.consume("whatever", Date.now())).not.toThrow();
    expect(store.consume("whatever", Date.now())).toBe(false);
  });
});
