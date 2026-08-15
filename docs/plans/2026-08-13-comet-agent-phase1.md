# Comet Agent Control Plane - Phase 1 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Let an agent drive the user's real Comet browser for read-and-benign-act work through the MCP, with every action passing through a policy check and a signed audit log. No dangerous actions, no credentials, attended only.

**Architecture:** Ghost (OS input, undetectable) is the actor; the comet-bridge extension content script is the accurate DOM reader; both operate on the one live logged-in Comet window. comet-mcp is the single controller: it exposes MCP tools, and every tool runs `policy.check -> execute -> audit.append`. This is the foundation the later phases (injection containment, credential fill, unattended runs, dangerous actions) mount on. Those are OUT of scope here and stay disabled.

**Tech Stack:** TypeScript (comet-mcp, `@modelcontextprotocol/sdk`, `zod`, Node 20+ `fetch`, `node:crypto` Ed25519), Node HTTP (comet-bridge relay), MV3 content script (extension). Tests: `node --test` / existing test runners in each repo.

**Repos touched:**
- `~/projects/active/comet-mcp` - new modules + MCP wiring (primary).
- `~/projects/active/comet-bridge` - relay accepts `read` jobs; new reader content script.

**Design ref:** `docs/plans/2026-08-13-comet-agent-control-plane-design.md`.

**Phase 1 hard invariants (assert in tests):**
- `SUBMIT` and `CREDENTIAL_FILL` are always denied regardless of policy.
- No plaintext field values (esp. password inputs) ever leave the reader.
- Every executed action produces exactly one audit record; every denied action produces exactly one audit record.

---

### Task 1: Policy engine

**Files:**
- Create: `~/projects/active/comet-mcp/src/policy.ts`
- Test: `~/projects/active/comet-mcp/tests/policy.test.ts`

**Step 1: Write the failing tests**

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { check, newState, consume, DEFAULT_PHASE1_POLICY, type Policy } from "../src/policy.js";

const base: Policy = {
  domains_allow: ["mail.google.com", "app.example.com"],
  domains_deny: ["evil.com"],
  actions_allow: ["NAVIGATE", "READ", "CLICK", "TYPE", "SCROLL", "WAIT"],
  budgets: { max_actions: 3, max_domains: 2, max_ms: 60_000 }
};

test("allows an allowlisted navigation", () => {
  const s = newState(0);
  const r = check(base, { kind: "NAVIGATE", url: "https://mail.google.com/mail/u/0" }, s, 0);
  assert.equal(r.allowed, true);
});

test("denies a non-allowlisted domain", () => {
  const s = newState(0);
  const r = check(base, { kind: "NAVIGATE", url: "https://other.com" }, s, 0);
  assert.equal(r.allowed, false);
});

test("denies an explicitly denied domain even if suffix-allowed", () => {
  const s = newState(0);
  const r = check(base, { kind: "NAVIGATE", url: "https://evil.com/x" }, s, 0);
  assert.equal(r.allowed, false);
});

test("denies an action not in actions_allow", () => {
  const s = newState(0);
  const r = check(base, { kind: "EXTRACT" }, s, 0);
  assert.equal(r.allowed, false);
});

test("ALWAYS denies dangerous actions (phase 1)", () => {
  const wideOpen: Policy = { ...base, actions_allow: ["SUBMIT", "CREDENTIAL_FILL"] };
  const s = newState(0);
  assert.equal(check(wideOpen, { kind: "SUBMIT" }, s, 0).allowed, false);
  assert.equal(check(wideOpen, { kind: "CREDENTIAL_FILL" }, s, 0).allowed, false);
});

test("enforces the action budget", () => {
  let s = newState(0);
  for (let i = 0; i < 3; i++) { s = consume(s, { kind: "READ" }, undefined); }
  assert.equal(check(base, { kind: "READ" }, s, 0).allowed, false);
});

test("enforces the wall-clock budget", () => {
  const s = newState(0);
  assert.equal(check(base, { kind: "READ" }, s, 61_000).allowed, false);
});

test("enforces the distinct-domain budget", () => {
  let s = newState(0);
  s = consume(s, { kind: "NAVIGATE", url: "https://mail.google.com" }, "mail.google.com");
  s = consume(s, { kind: "NAVIGATE", url: "https://app.example.com" }, "app.example.com");
  // third distinct domain would exceed max_domains: 2
  const r = check({ ...base, domains_allow: ["mail.google.com","app.example.com","c.example.com"] },
                  { kind: "NAVIGATE", url: "https://c.example.com" }, s, 0);
  assert.equal(r.allowed, false);
});
```

**Step 2: Run tests, verify they fail**

Run: `cd ~/projects/active/comet-mcp && npx tsc --noEmit && node --test tests/policy.test.ts`
Expected: FAIL (module not found).

**Step 3: Implement `src/policy.ts`**

```ts
export type ActionKind =
  | "NAVIGATE" | "READ" | "CLICK" | "TYPE" | "SELECT" | "SCROLL"
  | "WAIT" | "EXTRACT" | "SUBMIT" | "CREDENTIAL_FILL" | "FINISH";

// Phase 1: these are NEVER allowed, whatever the policy says. Later phases relax this
// only behind injection containment + approval.
export const DANGEROUS: ReadonlySet<ActionKind> = new Set(["SUBMIT", "CREDENTIAL_FILL"]);

export interface Policy {
  domains_allow: string[];
  domains_deny?: string[];
  actions_allow: ActionKind[];
  budgets: { max_actions: number; max_domains: number; max_ms: number };
}

export interface ActionRequest { kind: ActionKind; url?: string; }

export interface PolicyState {
  started_ms: number;
  actions_used: number;
  domains_used: string[]; // JSON-serializable (not a Set) so it can go in audit + across the wire
}

export const DEFAULT_PHASE1_POLICY: Policy = {
  domains_allow: [],
  domains_deny: [],
  actions_allow: ["NAVIGATE", "READ", "CLICK", "TYPE", "SCROLL", "WAIT"],
  budgets: { max_actions: 50, max_domains: 5, max_ms: 300_000 }
};

export function newState(nowMs: number): PolicyState {
  return { started_ms: nowMs, actions_used: 0, domains_used: [] };
}

function hostOf(url?: string): string | undefined {
  if (!url) return undefined;
  try { return new URL(url).hostname.toLowerCase(); } catch { return undefined; }
}

function hostMatches(host: string, entry: string): boolean {
  const e = entry.toLowerCase();
  return host === e || host.endsWith("." + e);
}

export function check(policy: Policy, req: ActionRequest, state: PolicyState, nowMs: number):
  { allowed: boolean; reason?: string } {
  if (DANGEROUS.has(req.kind)) return { allowed: false, reason: "dangerous action disabled in phase 1" };
  if (!policy.actions_allow.includes(req.kind)) return { allowed: false, reason: `action ${req.kind} not in actions_allow` };
  if (state.actions_used >= policy.budgets.max_actions) return { allowed: false, reason: "action budget exhausted" };
  if (nowMs - state.started_ms > policy.budgets.max_ms) return { allowed: false, reason: "time budget exhausted" };

  // Fail closed on any request that carries a url but can't be parsed to a host (schemeless
  // "evil.com", file://, protocol-relative "//evil.com", etc). A silently-skipped check here
  // would make the domain allowlist bypassable by simply omitting the scheme.
  if (req.url !== undefined) {
    const host = hostOf(req.url);
    if (!host) return { allowed: false, reason: "unparseable or non-http(s) url" };
    if ((policy.domains_deny ?? []).some(d => hostMatches(host, d))) return { allowed: false, reason: `domain denied: ${host}` };
    if (!policy.domains_allow.some(d => hostMatches(host, d))) return { allowed: false, reason: `domain not allowlisted: ${host}` };
    const isNew = !state.domains_used.includes(host);
    if (isNew && state.domains_used.length >= policy.budgets.max_domains) return { allowed: false, reason: "domain budget exhausted" };
  }
  return { allowed: true };
}

export function consume(state: PolicyState, req: ActionRequest, host: string | undefined): PolicyState {
  const domains_used = state.domains_used.slice();
  if (host && !domains_used.includes(host)) domains_used.push(host);
  return { ...state, actions_used: state.actions_used + 1, domains_used };
}
```

**Step 4: Run tests, verify pass**

Run: `node --test tests/policy.test.ts`
Expected: PASS (8 tests).

**Step 5: Commit**

```bash
git -C ~/projects/active/comet-mcp add src/policy.ts tests/policy.test.ts
git -C ~/projects/active/comet-mcp commit -m "feat(policy): phase-1 policy engine with dangerous-action denylist and budgets"
```

---

### Task 2: Signed audit log (hash-chained + Ed25519)

**Files:**
- Create: `~/projects/active/comet-mcp/src/audit.ts`
- Test: `~/projects/active/comet-mcp/tests/audit.test.ts`

**Step 1: Write the failing tests**

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog, verifyLog } from "../src/audit.js";

function keys() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    pub: publicKey.export({ type: "spki", format: "pem" }).toString()
  };
}

test("appends records and the chain verifies", () => {
  const dir = mkdtempSync(join(tmpdir(), "audit-"));
  const path = join(dir, "audit.jsonl");
  const { priv, pub } = keys();
  const log = new AuditLog(path, priv);
  log.append({ ts: 1, run_id: "r1", actor: "agent", action: "NAVIGATE", policy_decision: "allow", target: "https://x" });
  log.append({ ts: 2, run_id: "r1", actor: "agent", action: "READ", policy_decision: "allow" });
  const v = verifyLog(path, pub);
  assert.equal(v.ok, true);
  assert.equal(v.count, 2);
  rmSync(dir, { recursive: true, force: true });
});

test("detects tampering", () => {
  const dir = mkdtempSync(join(tmpdir(), "audit-"));
  const path = join(dir, "audit.jsonl");
  const { priv, pub } = keys();
  const log = new AuditLog(path, priv);
  log.append({ ts: 1, run_id: "r1", actor: "agent", action: "NAVIGATE", policy_decision: "allow" });
  const fs = require("node:fs");
  const lines = fs.readFileSync(path, "utf8").trimEnd().split("\n");
  const obj = JSON.parse(lines[0]); obj.rec.action = "SUBMIT"; // tamper
  fs.writeFileSync(path, JSON.stringify(obj) + "\n");
  const v = verifyLog(path, pub);
  assert.equal(v.ok, false);
  rmSync(dir, { recursive: true, force: true });
});
```

**Step 2: Run, verify fail** - `node --test tests/audit.test.ts` -> FAIL (module not found).

**Step 3: Implement `src/audit.ts`**

```ts
import { appendFileSync, readFileSync, existsSync } from "node:fs";
import { createHash, sign as edSign, verify as edVerify, createPrivateKey, createPublicKey } from "node:crypto";

export interface AuditRecord {
  ts: number; run_id: string; actor: string; action: string;
  target?: string; provenance?: string; policy_decision: "allow" | "deny" | string;
  reason?: string; observation_hash?: string;
}

interface ChainLine { rec: AuditRecord; prev: string; hash: string; sig: string; }

const GENESIS = "0".repeat(64);

function canon(rec: AuditRecord): string {
  // Stable key order so the hash is deterministic.
  const keys = Object.keys(rec).sort();
  return JSON.stringify(rec, keys);
}

function hashOf(prev: string, rec: AuditRecord): string {
  return createHash("sha256").update(prev).update("|").update(canon(rec)).digest("hex");
}

export class AuditLog {
  private key;
  constructor(private path: string, privatePem: string) {
    this.key = createPrivateKey(privatePem);
  }
  private lastHash(): string {
    if (!existsSync(this.path)) return GENESIS;
    const txt = readFileSync(this.path, "utf8").trimEnd();
    if (!txt) return GENESIS;
    const last = txt.split("\n").pop()!;
    return (JSON.parse(last) as ChainLine).hash;
  }
  append(rec: AuditRecord): void {
    const prev = this.lastHash();
    const hash = hashOf(prev, rec);
    const sig = edSign(null, Buffer.from(hash, "hex"), this.key).toString("base64");
    const line: ChainLine = { rec, prev, hash, sig };
    appendFileSync(this.path, JSON.stringify(line) + "\n");
  }
}

export function verifyLog(path: string, publicPem: string): { ok: boolean; count: number; brokenAt?: number } {
  const pub = createPublicKey(publicPem);
  const txt = existsSync(path) ? readFileSync(path, "utf8").trimEnd() : "";
  if (!txt) return { ok: true, count: 0 };
  const lines = txt.split("\n");
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    const line = JSON.parse(lines[i]) as ChainLine;
    if (line.prev !== prev) return { ok: false, count: lines.length, brokenAt: i };
    if (hashOf(prev, line.rec) !== line.hash) return { ok: false, count: lines.length, brokenAt: i };
    if (!edVerify(null, Buffer.from(line.hash, "hex"), pub, Buffer.from(line.sig, "base64")))
      return { ok: false, count: lines.length, brokenAt: i };
    prev = line.hash;
  }
  return { ok: true, count: lines.length };
}

// Key bootstrap: load from env or a gitignored keyfile pair; generate on first run.
export function loadOrCreateKeys(dir: string): { priv: string; pub: string } {
  const fs = require("node:fs") as typeof import("node:fs");
  const path = require("node:path") as typeof import("node:path");
  const crypto = require("node:crypto") as typeof import("node:crypto");
  const privPath = path.join(dir, "audit.key");
  const pubPath = path.join(dir, "audit.pub");
  if (process.env.COMET_AUDIT_KEY && process.env.COMET_AUDIT_PUB)
    return { priv: process.env.COMET_AUDIT_KEY, pub: process.env.COMET_AUDIT_PUB };
  if (fs.existsSync(privPath) && fs.existsSync(pubPath))
    return { priv: fs.readFileSync(privPath, "utf8"), pub: fs.readFileSync(pubPath, "utf8") };
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const priv = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const pub = publicKey.export({ type: "spki", format: "pem" }).toString();
  fs.writeFileSync(privPath, priv, { mode: 0o600 });
  fs.writeFileSync(pubPath, pub);
  return { priv, pub };
}
```

**Step 4: Run, verify pass** - `node --test tests/audit.test.ts` -> PASS (2 tests).

**Step 5: Commit** - add `audit.key`/`audit.pub` to `.gitignore` first.

```bash
echo -e "audit.key\naudit.pub\n*.audit.jsonl" >> ~/projects/active/comet-mcp/.gitignore
git -C ~/projects/active/comet-mcp add src/audit.ts tests/audit.test.ts .gitignore
git -C ~/projects/active/comet-mcp commit -m "feat(audit): hash-chained Ed25519-signed action log with verify + tamper test"
```

---

### Task 3: Relay accepts `read` jobs

**Files:**
- Modify: `~/projects/active/comet-bridge/relay/store.js`
- Modify: `~/projects/active/comet-bridge/relay/server.js:30-40`
- Test: `~/projects/active/comet-bridge/test/relay-read.test.js` (follow the existing test file's runner; check `package.json` `scripts.test`)

**Step 1: Failing test** - POST a `{ kind: "read", url }` job (no `query`), expect 201; `GET /jobs/next` returns the job with `kind` and `payload`.

```js
const assert = require('node:assert');
const { test } = require('node:test');
const store = require('../relay/store');

test('createJob accepts a non-query read job', () => {
  store._reset();
  const job = store.createJob({ kind: 'read', payload: { url: 'https://mail.google.com', target: 'page' } });
  assert.equal(job.kind, 'read');
  const next = store.claimNext();
  assert.equal(next.kind, 'read');
  assert.equal(next.payload.target, 'page');
});
```

**Step 2: Run, verify fail.**

**Step 3: Implement** - generalize `store.createJob` to keep `kind` + `payload`; keep `query`/`mode` back-compat. In `server.js`, replace the `if (!body.query)` guard so a job is valid when it has `query` OR `kind`; make `/jobs/next` return `{ id, query, mode, kind, payload }`.

`store.js`:
```js
function createJob(body) {
  const id = String(++seq);
  const job = {
    id, status: 'pending', result: null, error: null,
    query: body.query || null, mode: body.mode || 'search',
    kind: body.kind || (body.query ? 'query' : null),
    payload: body.payload || null
  };
  jobs.set(id, job);
  return job;
}
```
`server.js` (the POST /jobs branch): `if (!body.query && !body.kind) return send(res, 400, { error: 'query or kind required' }, origin);` and the `/jobs/next` response: `return send(res, 200, { id: job.id, query: job.query, mode: job.mode, kind: job.kind, payload: job.payload }, origin);`

**Step 4: Run, verify pass.**  `cd ~/projects/active/comet-bridge && npm test`

**Step 5: Commit**
```bash
git -C ~/projects/active/comet-bridge add relay/store.js relay/server.js test/relay-read.test.js
git -C ~/projects/active/comet-bridge commit -m "feat(relay): accept read/act jobs (kind+payload) alongside query jobs"
```

---

### Task 4: Reader element-map (pure fn, jsdom-tested)

**Files:**
- Create: `~/projects/active/comet-bridge/extension/reader.js` (mirrors `scrape.js`: pure fn + content-script entry, testable in Node)
- Test: `~/projects/active/comet-bridge/test/reader.test.js` (add `jsdom` dev-dep if not present; `scrape` tests already run under a DOM - reuse that setup)

**Step 1: Failing test**

```js
const assert = require('node:assert');
const { test } = require('node:test');
const { JSDOM } = require('jsdom');
const { buildReaderState } = require('../extension/reader');

test('maps interactive elements with opaque refs and hides password values', () => {
  const dom = new JSDOM(`<html><body>
    <a href="https://x.com/a">Open X</a>
    <button id="b1">Send</button>
    <input type="text" name="q" value="hello">
    <input type="password" name="pw" value="SECRET">
  </body></html>`, { url: "https://app.example.com/inbox" });
  const s = buildReaderState(dom.window.document);
  assert.equal(s.url, "https://app.example.com/inbox");
  const kinds = s.elements.map(e => e.tag);
  assert.ok(kinds.includes('a') && kinds.includes('button') && kinds.includes('input'));
  const pw = s.elements.find(e => e.type === 'password');
  assert.equal(pw.value_present, true);
  assert.equal('value' in pw, false);           // raw password value NEVER included
  assert.ok(s.elements.every(e => typeof e.ref === 'number')); // opaque numeric refs
  assert.ok(JSON.stringify(s).indexOf('SECRET') === -1); // no secret anywhere in output
});
```

**Step 2: Run, verify fail.**

**Step 3: Implement `extension/reader.js`**

```js
// Builds a sanitized, LLM-safe view of a page: interactive elements with opaque refs and
// accessible names, plus bounded text. Raw input VALUES are never included (only value_present),
// so nothing the reader emits can leak a field's contents or become an instruction.
const INTERACTIVE = 'a[href],button,input,select,textarea,[role=button],[role=link],[contenteditable="true"]';

function accName(el) {
  return (el.getAttribute && (el.getAttribute('aria-label')
    || el.getAttribute('placeholder')
    || el.getAttribute('name')))
    || (el.textContent || '').trim().slice(0, 120)
    || '';
}

function buildReaderState(doc, opts) {
  const maxText = (opts && opts.maxText) || 20000;
  const els = [];
  let ref = 0;
  for (const el of doc.querySelectorAll(INTERACTIVE)) {
    const tag = el.tagName.toLowerCase();
    const type = el.getAttribute && el.getAttribute('type');
    const e = { ref: ref++, tag, role: el.getAttribute && el.getAttribute('role') || null,
                name: accName(el), type: type || null };
    if (tag === 'input' || tag === 'textarea' || tag === 'select') {
      e.value_present = !!(el.value && String(el.value).length);   // boolean only, never the value
    }
    // Bounding box for the actor (Ghost clicks by coordinate). getBoundingClientRect exists in the
    // live browser; in jsdom it returns zeros, which is fine for the unit test.
    const r = el.getBoundingClientRect ? el.getBoundingClientRect() : { x:0,y:0,width:0,height:0 };
    e.box = { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) };
    els.push(e);
  }
  const bodyText = ((doc.body && doc.body.textContent) || '').replace(/\s+/g, ' ').trim().slice(0, maxText);
  return {
    url: (doc.location && doc.location.href) || (doc.defaultView && doc.defaultView.location.href) || '',
    title: doc.title || '',
    elements: els,
    content: bodyText
  };
}

if (typeof module !== 'undefined') module.exports = { buildReaderState };
```

**Step 4: Run, verify pass.**

**Step 5: Commit**
```bash
git -C ~/projects/active/comet-bridge add extension/reader.js test/reader.test.js package.json
git -C ~/projects/active/comet-bridge commit -m "feat(reader): sanitized element-map builder (opaque refs, no raw field values)"
```

---

### Task 5: Extension handles `read` jobs on the active tab (live-verified)

**Files:**
- Modify: `~/projects/active/comet-bridge/extension/background.js`
- Modify: `~/projects/active/comet-bridge/extension/manifest.json` (broaden `host_permissions` to `<all_urls>` so the reader can run on client sites; keep relay origin locked)

**Note:** This is browser-integration code, validated by a live run (Task 9), not a unit test - the same convention `inject.js` already documents.

**Step 1:** In `background.js poll()`, branch on `job.kind`. For `read`, inject `reader.js` into the ACTIVE tab of the focused normal window (not the dedicated Perplexity bridge tab) and return `buildReaderState(document)`:

```js
async function handleRead(job) {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab) return { error: 'no_active_tab' };
  await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['reader.js'] });
  const [{ result }] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => buildReaderState(document)
  });
  return result;
}
```
Route in `handle()`: `if (job.kind === 'read') { result = await handleRead(job); }` else existing query path. Post back via the existing `/jobs/:id/result`.

**Step 2:** `manifest.json` -> `"host_permissions": ["<all_urls>", "http://127.0.0.1:8787/*"]`. Bump `version`.

**Step 3:** Reload the unpacked extension in Comet (`chrome://extensions` -> reload).

**Step 4:** Verified in Task 9.

**Step 5: Commit**
```bash
git -C ~/projects/active/comet-bridge add extension/background.js extension/manifest.json
git -C ~/projects/active/comet-bridge commit -m "feat(extension): read active tab via sanitized reader element-map"
```

---

### Task 6: comet-mcp bridge client (HTTP to relay)

**Files:**
- Create: `~/projects/active/comet-mcp/src/bridge_client.ts`
- Test: `~/projects/active/comet-mcp/tests/bridge_client.test.ts` (spin up the real `comet-bridge` relay server in-process, OR a tiny stub http server)

**Step 1: Failing test** (stub http server that mimics the relay job lifecycle):

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { BridgeClient } from "../src/bridge_client.js";

function stubRelay(): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    let job: any = null;
    const srv = http.createServer((req, res) => {
      let body = ""; req.on("data", c => body += c); req.on("end", () => {
        if (req.method === "POST" && req.url === "/jobs") { job = { id: "1", ...JSON.parse(body||"{}"), status: "pending" }; res.writeHead(201); return res.end(JSON.stringify({ id: "1" })); }
        if (req.method === "GET" && req.url === "/jobs/1") { res.writeHead(200); return res.end(JSON.stringify({ status: "done", result: { url: "https://x", elements: [] } })); }
        res.writeHead(404); res.end("{}");
      });
    });
    srv.listen(0, "127.0.0.1", () => resolve({ url: `http://127.0.0.1:${(srv.address() as any).port}`, close: () => srv.close() }));
  });
}

test("dispatch + poll returns the result", async () => {
  const relay = await stubRelay();
  const c = new BridgeClient(relay.url, "tok");
  const id = await c.dispatch({ kind: "read", payload: { target: "page" } });
  const out = await c.result(id, { timeoutMs: 2000, pollMs: 20 });
  assert.deepEqual(out, { url: "https://x", elements: [] });
  relay.close();
});
```

**Step 2: Run, verify fail.**

**Step 3: Implement `src/bridge_client.ts`**

```ts
export class BridgeClient {
  constructor(private base: string, private token: string) {}
  private h() { return { "content-type": "application/json", "x-bridge-token": this.token }; }

  async dispatch(job: { kind: string; payload?: unknown; query?: string; mode?: string }): Promise<string> {
    const r = await fetch(`${this.base}/jobs`, { method: "POST", headers: this.h(), body: JSON.stringify(job) });
    if (r.status !== 201) throw new Error(`dispatch failed: ${r.status} ${await r.text()}`);
    return (await r.json() as { id: string }).id;
  }

  async result(id: string, opts: { timeoutMs: number; pollMs: number }): Promise<any> {
    const deadline = Date.now() + opts.timeoutMs;
    while (Date.now() < deadline) {
      const r = await fetch(`${this.base}/jobs/${id}`, { headers: this.h() });
      if (r.status === 200) {
        const j = await r.json() as { status: string; result?: any; error?: string };
        if (j.status === "done") return j.result;
        if (j.status === "error") throw new Error(`bridge job error: ${j.error}`);
      }
      await new Promise(res => setTimeout(res, opts.pollMs));
    }
    throw new Error("bridge job timed out");
  }
}
```

**Step 4: Run, verify pass.**

**Step 5: Commit**
```bash
git -C ~/projects/active/comet-mcp add src/bridge_client.ts tests/bridge_client.test.ts
git -C ~/projects/active/comet-mcp commit -m "feat(bridge): HTTP client to dispatch read jobs and poll results"
```

---

### Task 7: Ghost actor (navigate / type / scroll / click)

**Files:**
- Create: `~/projects/active/comet-mcp/src/comet_window.ts` (extract `findOrLaunchComet` from `comet_driver.ts:71-87` so actor + driver share it - DRY)
- Modify: `~/projects/active/comet-mcp/src/comet_driver.ts` to use the shared helper
- Modify: `~/projects/active/comet-mcp/src/ghost_client.ts` (add pointer + scroll wrappers to `GhostTools`)
- Create: `~/projects/active/comet-mcp/src/actor.ts`
- Test: `~/projects/active/comet-mcp/tests/actor.test.ts` (inject a fake `GhostTools` that records calls)

**Step 0 - ALREADY DONE (2026-08-13). Results are binding; do NOT re-derive.**

The live `tools/list` probe against ghost-mcp found that **every Ghost method name currently in
`src/ghost_client.ts` is STALE and does not exist**. Ghost exposes high-level a11y verbs, not raw
input primitives. Correct mapping (this is the real, verified surface):

| `GhostTools` method (stale call) | REAL Ghost tool + params |
|---|---|
| `list_windows()` -> `ghost_list_windows` | `ghost_window` `{op:"list"}` -> `{windows:[{name,pid,focused,state}]}` |
| `focus_window(name)` -> `ghost_focus_window` | `ghost_window` `{op:"focus", name}` |
| `launch(path)` -> `ghost_launch` | `ghost_window` `{op:"launch", exe}` |
| `hotkey(mods,key)` -> `ghost_hotkey` | `ghost_key` `{keys:"Ctrl+L", window?}` (combo as ONE string) |
| `press(key)` -> `ghost_press` | `ghost_key` `{keys:"Enter", window?}` |
| `get_clipboard()` -> `ghost_get_clipboard` | `ghost_clipboard` `{op:"get"}` |
| `set_clipboard(t)` -> `ghost_set_clipboard` | `ghost_clipboard` `{op:"set", text}` |
| `screenshot_region(o)` -> `ghost_screenshot_region` | `ghost_screenshot` `{rect?,name?,role?,foreground?,max_dim?}` |

Newly available and BETTER than the original plan - use these:
- `ghost_wait` `{for:"navigate", url, window}` - focus window + navigate + wait for page idle in ONE
  call. Use this for NAVIGATE instead of the Ctrl+L/clipboard/Enter dance.
- `ghost_act` `{action:"click"|"type", name?, role?, text_input?, window, background?}` - atomic
  find->focus->act by ACCESSIBLE NAME (no raw coordinates). Use for CLICK/TYPE. Returns
  `{ok, verified, ...}`; `verified:false` means it dispatched but nothing visibly changed.
- `ghost_snapshot` `{window?, actionable_only?, limit?}` - structured element list (stable id, name,
  role, rect, center, enabled, actionable). Complements the extension reader.
- `ghost_scroll` `{direction, amount}` - direction is `up|down|left|right`.

Also fix (pre-existing bug, in scope for this task since you are editing this file):
`src/index.ts` defaults `GHOST_MCP_EXE` to
`C:\Users\Krist\projects\active\ghost\target\release\ghost-mcp.exe`, but the REGISTERED/canonical
binary is `C:\Users\Krist\.local\bin\ghost-mcp.exe`. Change the default to the `.local\bin` path.

Because these names are all wrong today, `CometDriver.ask()` (the existing `ask_perplexity` tool) is
almost certainly broken against current Ghost. Updating `GhostTools` fixes it as a side effect -
keep `CometDriver`'s call sites working (same `GhostTools` method names, new wire calls underneath).

**Step 1: Failing test** (records the Ghost calls the actor makes):

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { CometActor } from "../src/actor.js";

class FakeGhost {
  calls: Array<[string, any]> = [];
  async focus_window(n: string) { this.calls.push(["focus", n]); return { ok: true } as const; }
  async hotkey(m: string[], k: string) { this.calls.push(["hotkey", [m, k]]); return { ok: true } as const; }
  async press(k: string) { this.calls.push(["press", k]); return { ok: true } as const; }
  async set_clipboard(t: string) { this.calls.push(["clip", t]); return { ok: true } as const; }
  async list_windows() { return { windows: [{ name: "Comet - X", pid: 1, focused: true }] }; }
}

test("navigate uses ghost_wait for=navigate scoped to the Comet window", async () => {
  const g = new FakeGhost();
  const a = new CometActor(g as any);
  await a.navigate("https://mail.google.com");
  assert.deepEqual(g.calls.map(c => c[0]), ["navigate"]);
  assert.equal(g.calls[0][1].url, "https://mail.google.com");
  assert.match(g.calls[0][1].window, /comet/i);
});

test("click acts by accessible name, never raw coordinates", async () => {
  const g = new FakeGhost();
  const a = new CometActor(g as any);
  await a.click({ name: "Compose", role: "button" });
  assert.deepEqual(g.calls.map(c => c[0]), ["act"]);
  assert.equal(g.calls[0][1].action, "click");
  assert.equal(g.calls[0][1].name, "Compose");
});

test("type sends text via ghost_act type", async () => {
  const g = new FakeGhost();
  const a = new CometActor(g as any);
  await a.type("hello world", { name: "Search", role: "edit" });
  assert.equal(g.calls[0][1].action, "type");
  assert.equal(g.calls[0][1].text_input, "hello world");
});
```
(Write `FakeGhost` to record `["navigate"|"act"|"scroll", params]` matching the real wrappers below.)

**Step 2: Run, verify fail.**

**Step 3: Implement.**

First, CORRECT the stale wire names in `ghost_client.ts` `GhostTools` (keep the existing method
names so `CometDriver` keeps compiling; only the `this.call(...)` targets change):
```ts
list_windows(): Promise<{ windows: GhostWindow[] }> { return this.call("ghost_window", { op: "list" }); }
focus_window(name: string): Promise<{ ok: true }> { return this.call("ghost_window", { op: "focus", name }); }
launch(exe: string): Promise<{ ok: true }> { return this.call("ghost_window", { op: "launch", exe }); }
hotkey(modifiers: string[], key: string): Promise<{ ok: true }> { return this.call("ghost_key", { keys: [...modifiers, key].join("+") }); }
press(key: string): Promise<{ ok: true }> { return this.call("ghost_key", { keys: key }); }
get_clipboard(): Promise<{ text: string }> { return this.call("ghost_clipboard", { op: "get" }); }
set_clipboard(text: string): Promise<{ ok: true }> { return this.call("ghost_clipboard", { op: "set", text }); }
screenshot_region(opts): Promise<{ png_base64: string }> { return this.call("ghost_screenshot", opts); }
```
Then ADD the new high-level wrappers used by the actor:
```ts
navigate(url: string, window: string): Promise<unknown> { return this.call("ghost_wait", { for: "navigate", url, window, timeout_ms: 30000 }); }
act(args: { action: "click" | "type"; name?: string; role?: string; text_input?: string; window?: string }): Promise<{ ok: boolean; verified?: boolean }> { return this.call("ghost_act", args); }
scroll(direction: "up" | "down" | "left" | "right", amount = 3): Promise<{ ok: true }> { return this.call("ghost_scroll", { direction, amount }); }
snapshot(args: { window?: string; actionable_only?: boolean; limit?: number } = {}): Promise<unknown> { return this.call("ghost_snapshot", args); }
```
`comet_window.ts` exports `findOrLaunchComet(g)` (logic moved from `comet_driver.ts:71-87`).
`actor.ts`:
```ts
import type { GhostTools } from "./ghost_client.js";
import { findOrLaunchComet } from "./comet_window.js";

export type ElementRef = { name?: string; role?: string };

export class CometActor {
  constructor(private g: GhostTools) {}
  private async cometWindow(): Promise<string> { return (await findOrLaunchComet(this.g)).name; }
  async navigate(url: string) { await this.g.navigate(url, await this.cometWindow()); }
  async click(el: ElementRef) { await this.g.act({ action: "click", ...el, window: await this.cometWindow() }); }
  async type(text: string, el: ElementRef) { await this.g.act({ action: "type", text_input: text, ...el, window: await this.cometWindow() }); }
  async scroll(direction: "up" | "down") { await this.g.scroll(direction); }
}
```
Note `ghost_act` returns `{ok, verified}`; when `verified === false` the action dispatched but
nothing visibly changed. Surface that to the caller (Task 8 audits it) rather than swallowing it.

**Step 4: Run, verify pass.**

**Step 5: Commit**
```bash
git -C ~/projects/active/comet-mcp add src/comet_window.ts src/actor.ts src/ghost_client.ts src/comet_driver.ts tests/actor.test.ts
git -C ~/projects/active/comet-mcp commit -m "feat(actor): Ghost-driven navigate/type/scroll/click on the live Comet window"
```

---

### Task 8: Run manager + MCP tool wiring (policy + audit on every call)

**Files:**
- Create: `~/projects/active/comet-mcp/src/run_manager.ts`
- Modify: `~/projects/active/comet-mcp/src/mcp_server.ts` (register new tools)
- Modify: `~/projects/active/comet-mcp/src/index.ts` (construct actor, bridge client, audit log, run manager; pass into server)
- Test: `~/projects/active/comet-mcp/tests/run_manager.test.ts`

**Step 1: Failing test** - a `RunManager` with fake actor/bridge/audit: `begin(policy)` returns a run_id; a denied action appends a deny record and does NOT call the actor; an allowed navigate calls the actor and appends an allow record; budget decrements.

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { RunManager } from "../src/run_manager.js";

const fakeActor = () => { const calls: string[] = []; return { calls,
  navigate: async (_u: string) => { calls.push("nav"); },
  type: async (_t: string) => { calls.push("type"); },
  scroll: async (_d: string) => { calls.push("scroll"); },
  click: async (_el: { name?: string; role?: string }) => { calls.push("click"); } }; };
const fakeBridge = () => ({ read: async () => ({ url: "https://mail.google.com", elements: [], content: "inbox" }) });
const fakeAudit = () => { const recs: any[] = []; return { recs, append: (r: any) => recs.push(r) }; };

test("denied navigation is audited and never reaches the actor", async () => {
  const actor = fakeActor(); const audit = fakeAudit();
  const rm = new RunManager(actor as any, fakeBridge() as any, audit as any, () => 0);
  const { run_id } = rm.begin({ domains_allow: ["mail.google.com"], actions_allow: ["NAVIGATE"], budgets: { max_actions: 5, max_domains: 5, max_ms: 1000 } });
  const r = await rm.navigate(run_id, "https://evil.com");
  assert.equal(r.ok, false);
  assert.equal(actor.calls.length, 0);
  assert.equal(audit.recs.at(-1).policy_decision, "deny");
});

test("allowed navigation reaches the actor and is audited allow", async () => {
  const actor = fakeActor(); const audit = fakeAudit();
  const rm = new RunManager(actor as any, fakeBridge() as any, audit as any, () => 0);
  const { run_id } = rm.begin({ domains_allow: ["mail.google.com"], actions_allow: ["NAVIGATE"], budgets: { max_actions: 5, max_domains: 5, max_ms: 1000 } });
  const r = await rm.navigate(run_id, "https://mail.google.com/mail");
  assert.equal(r.ok, true);
  assert.deepEqual(actor.calls, ["nav"]);
  assert.equal(audit.recs.at(-1).policy_decision, "allow");
});
```

**Step 2: Run, verify fail.**

**Step 3: Implement `src/run_manager.ts`** - holds `Map<run_id, {policy, state}>`; each method does `check -> (deny: audit+return) | (execute -> consume -> audit)`. `now()` injected for testability. `read()` goes through the bridge client; reads still consume budget and audit. Then wire `mcp_server.ts` tools: `comet_session_begin`, `comet_navigate`, `comet_read`, `comet_act`, `comet_status`, keeping `ask_perplexity`. Each tool handler is a thin zod-parse + RunManager call. `index.ts` builds: `BridgeClient` (from `BRIDGE_URL`/`BRIDGE_TOKEN` env), `CometActor`, `AuditLog` (via `loadOrCreateKeys`), `RunManager`, and passes the manager to `build_mcp_server`.

Skeleton for `run_manager.ts`:
```ts
import { check, consume, newState, DANGEROUS, type Policy, type ActionKind } from "./policy.js";
type Now = () => number;
let counter = 0;
export class RunManager {
  private runs = new Map<string, { policy: Policy; state: ReturnType<typeof newState> }>();
  constructor(private actor: any, private bridge: any, private audit: any, private now: Now = () => Date.now()) {}
  begin(policy: Policy) { const run_id = `run_${++counter}`; this.runs.set(run_id, { policy, state: newState(this.now()) }); return { run_id }; }
  private guard(run_id: string, kind: ActionKind, url?: string) {
    const run = this.runs.get(run_id); if (!run) throw new Error("unknown run_id");
    const decision = check(run.policy, { kind, url }, run.state, this.now());
    return { run, decision };
  }
  private record(run_id: string, kind: ActionKind, decision: any, target?: string) {
    this.audit.append({ ts: this.now(), run_id, actor: "agent", action: kind,
      target, policy_decision: decision.allowed ? "allow" : "deny", reason: decision.reason });
  }
  async navigate(run_id: string, url: string) {
    const { run, decision } = this.guard(run_id, "NAVIGATE", url);
    this.record(run_id, "NAVIGATE", decision, url);
    if (!decision.allowed) return { ok: false, reason: decision.reason };
    await this.actor.navigate(url);
    let host; try { host = new URL(url).hostname.toLowerCase(); } catch {}
    run.state = consume(run.state, { kind: "NAVIGATE", url }, host);
    return { ok: true };
  }
  // read(), act() follow the same shape; act() maps kind -> actor.type/scroll/click; SUBMIT/CREDENTIAL_FILL
  // are rejected by check() before reaching here.
  status(run_id: string) { const r = this.runs.get(run_id); return r ? { ...r.state, policy: r.policy } : null; }
}
```

**Step 4: Run all tests + typecheck** - `cd ~/projects/active/comet-mcp && npx tsc --noEmit && node --test tests/*.test.ts && npm run build`
Expected: PASS, clean build.

**Step 5: Commit**
```bash
git -C ~/projects/active/comet-mcp add src/run_manager.ts src/mcp_server.ts src/index.ts tests/run_manager.test.ts
git -C ~/projects/active/comet-mcp commit -m "feat(mcp): run manager + tools (session/navigate/read/act/status) with policy+audit on every call"
```

---

### Task 9: Live proof run (attended, real Comet)

**Not unit-testable - this is the real-world validation. Capture the output.**

**Preconditions:** Comet running + signed in; ghost-mcp.exe present; comet-bridge relay running with the extension loaded (`host_permissions` now `<all_urls>`); comet-mcp registered/rebuilt.

**Steps (record each result):**
1. `comet_session_begin` with a policy allowing only a benign site you're logged into (e.g. `["mail.google.com"]`, actions `NAVIGATE, READ, SCROLL`). Record run_id.
2. `comet_navigate(run_id, "https://mail.google.com/mail/u/0")`. Confirm the real Comet window navigated.
3. `comet_read(run_id, "page")`. Confirm the returned element-map has real interactive elements and readable inbox text, and that NO password/field raw values appear.
4. `comet_act(run_id, { kind: "SCROLL", dir: "down" })`. Confirm scroll.
5. Negative control: `comet_navigate(run_id, "https://example.org")` (not allowlisted) -> expect `{ ok:false }` and a `deny` audit record. Also try a schemeless URL (`"evil.com"`) and a `file://` URL -> both must be denied (policy.ts fails closed on unparseable/non-http(s) urls).
6. Negative control: attempt `comet_act(run_id, { kind: "SUBMIT" })` -> expect denied.
7. `verifyLog(auditPath, pub)` -> `{ ok: true }` with the expected record count.

**Acceptance:** steps 2-4 succeed on the live browser, 5-6 are denied, 7 verifies. Paste the captured tool outputs + the audit tail into the PR/commit message.

---

### Task 10: Docs + register

**Files:** Modify `~/projects/active/comet-mcp/README.md` (new tools, env: `BRIDGE_URL`, `BRIDGE_TOKEN`, audit key), `~/projects/active/comet-bridge/README.md` (read job type).

- Re-register comet-mcp if entrypoint/env changed:
```bash
MSYS_NO_PATHCONV=1 claude mcp add comet --scope user --env BRIDGE_URL="http://127.0.0.1:8787" --env BRIDGE_TOKEN="..." -- node "C:\\Users\\Krist\\projects\\active\\comet-mcp\\dist\\index.js"
```
- Verify: `claude mcp get comet` shows Connected.
- Commit docs.

---

## Phase 1 done when
- `npx tsc --noEmit` clean, all unit tests green (policy, audit, bridge_client, actor, run_manager; relay + reader in comet-bridge).
- Live proof run (Task 9) captured: allowed actions work on real Comet, denied actions blocked, audit log verifies.
- Dangerous actions and credentials remain impossible to invoke (asserted by tests, confirmed live).

## Explicitly deferred to later phases (do NOT build here)
- Dual-LLM injection containment + provenance/egress gate (Phase 2) - the gate before anything riskier.
- Gated credential fill (Phase 3). Unattended runs (Phase 4). Dangerous-action set + DPAPI (Phase 5).
