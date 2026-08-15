import { describe, it, expect } from "vitest";
import { CometActor, AUTOFILL_KEY_SEQUENCE } from "../src/actor.js";

class FakeGhost {
  calls: Array<[string, any]> = [];
  async list_windows() { return { windows: [{ name: "Comet - X", pid: 1, focused: true }] }; }
  async launch(exe: string) { this.calls.push(["launch", exe]); return { ok: true as const }; }
  async navigate(url: string, window: string) { this.calls.push(["navigate", { url, window }]); return { ok: true }; }
  async act(args: any) { this.calls.push(["act", args]); return { ok: true, verified: true }; }
  async scroll(direction: string, x: number, y: number, amount?: number) { this.calls.push(["scroll", { direction, x, y, amount }]); return { ok: true as const }; }
  async find(args: any) { this.calls.push(["find", args]); return { center: { x: 100, y: 50 } }; }
  async assert(args: any) { this.calls.push(["assert", args]); return { ok: true }; }
  async press(key: string, window?: string) { this.calls.push(["press", { key, window }]); return { ok: true as const }; }
}

// Fake of the comet-bridge extension reader: reports only value_present (a boolean), never a raw
// value, matching the real reader.js content-script contract (docs/plans phase1 Task 4).
class FakeBridge {
  constructor(private elements: Array<Record<string, unknown>>) {}
  async read(_payload?: unknown) { return { elements: this.elements }; }
}

describe("CometActor", () => {
  it("navigate uses ghost_wait for=navigate scoped to the Comet window, then verifies landing", async () => {
    const g = new FakeGhost();
    const a = new CometActor(g as any);
    const r = await a.navigate("https://mail.google.com");
    expect(g.calls.map((c) => c[0])).toEqual(["navigate", "assert"]);
    expect(g.calls[0]![1].url).toBe("https://mail.google.com");
    expect(g.calls[0]![1].window).toMatch(/comet/i);
    // the landing check must assert on the real host, via the address bar
    expect(g.calls[1]![1].text).toBe("mail.google.com");
    expect(r).toEqual({ ok: true, landed: true });
  });

  // Regression: observed live 2026-08-13 - the address bar dropped the leading character
  // ("ttps://mail.google.com/...") while ghost still reported success. An unverified navigate
  // would report ok:true from a page the policy never authorised.
  it("fails closed when the browser did not land on the requested host", async () => {
    class WrongPageGhost extends FakeGhost {
      override async assert(args: any) {
        this.calls.push(["assert", args]);
        throw new Error("assertion failed: value-contains");
      }
      async focus_window(_n: string) { return { ok: true as const }; }
    }
    // Drive the retry/backoff to zero so this exercises the fail-closed PATH, not the wall clock.
    // (navigate now retries the whole focus->navigate->verify cycle because ghost_wait was observed
    // returning ok:true without navigating; the defaults are ~4s, well past vitest's 5s limit.)
    process.env.COMET_LANDING_ATTEMPTS = "1";
    process.env.COMET_LANDING_RETRY_MS = "0";
    process.env.COMET_NAV_CYCLES = "1";
    const g = new WrongPageGhost();
    const a = new CometActor(g as any);
    const r = await a.navigate("https://mail.google.com");
    delete process.env.COMET_LANDING_ATTEMPTS;
    delete process.env.COMET_LANDING_RETRY_MS;
    delete process.env.COMET_NAV_CYCLES;
    expect(r.ok).toBe(false);
    expect(r.landed).toBe(false);
    expect(r.reason).toMatch(/did not land on mail\.google\.com/);
  });

  it("click acts by accessible name, never raw coordinates", async () => {
    const g = new FakeGhost();
    const a = new CometActor(g as any);
    await a.click({ name: "Compose", role: "button" });
    expect(g.calls.map((c) => c[0])).toEqual(["act"]);
    expect(g.calls[0]![1].action).toBe("click");
    expect(g.calls[0]![1].name).toBe("Compose");
  });

  it("type sends text via ghost_act type", async () => {
    const g = new FakeGhost();
    const a = new CometActor(g as any);
    await a.type("hello world", { name: "Search", role: "edit" });
    expect(g.calls[0]![1].action).toBe("type");
    expect(g.calls[0]![1].text_input).toBe("hello world");
  });

  // Regression: ghost_scroll REQUIRES a coordinate - a bare {direction, amount} fails live with
  // "missing param: x". The actor anchors off the address bar and scrolls below it.
  it("scroll dispatches ghost_scroll with a coordinate anchored in page content", async () => {
    const g = new FakeGhost();
    const a = new CometActor(g as any);
    await a.scroll("down");
    expect(g.calls.map((c) => c[0])).toEqual(["find", "scroll"]);
    const scrollArgs = g.calls[1]![1];
    expect(scrollArgs.direction).toBe("down");
    expect(scrollArgs.x).toBe(100);
    expect(scrollArgs.y).toBeGreaterThan(50); // below the address bar, inside the page
  });

  it("surfaces verified:false from ghost_act instead of swallowing it", async () => {
    class UnverifiedGhost extends FakeGhost {
      override async act(args: any) { this.calls.push(["act", args]); return { ok: true, verified: false }; }
    }
    const g = new UnverifiedGhost();
    const a = new CometActor(g as any);
    const r = await a.click({ name: "Compose" });
    expect(r.verified).toBe(false);
  });

  describe("credentialFill", () => {
    it("focuses the target field before sending any autofill keys", async () => {
      const g = new FakeGhost();
      const bridge = new FakeBridge([{ name: "Password", role: "edit", value_present: true }]);
      const a = new CometActor(g as any, bridge as any);
      await a.credentialFill({ name: "Password", role: "edit" });
      const kinds = g.calls.map((c) => c[0]);
      expect(kinds[0]).toBe("act");
      expect(g.calls[0]![1].action).toBe("click");
      expect(kinds.slice(1)).toEqual(["press", "press"]);
    });

    it("sends the exported AUTOFILL_KEY_SEQUENCE, in order", async () => {
      const g = new FakeGhost();
      const bridge = new FakeBridge([{ name: "Password", role: "edit", value_present: true }]);
      const a = new CometActor(g as any, bridge as any);
      await a.credentialFill({ name: "Password", role: "edit" });
      const pressed = g.calls.filter((c) => c[0] === "press").map((c) => c[1].key);
      expect(pressed).toEqual([...AUTOFILL_KEY_SEQUENCE]);
    });

    it("returns ONLY {ok, filled} - no value, no extra keys", async () => {
      const g = new FakeGhost();
      const bridge = new FakeBridge([{ name: "Password", role: "edit", value_present: true }]);
      const a = new CometActor(g as any, bridge as any);
      const r = await a.credentialFill({ name: "Password", role: "edit" });
      expect(Object.keys(r).sort()).toEqual(["filled", "ok"]);
      expect(r).toEqual({ ok: true, filled: true });
    });

    it("yields filled:false when the underlying read reports value_present:false", async () => {
      const g = new FakeGhost();
      const bridge = new FakeBridge([{ name: "Password", role: "edit", value_present: false }]);
      const a = new CometActor(g as any, bridge as any);
      const r = await a.credentialFill({ name: "Password", role: "edit" });
      expect(r).toEqual({ ok: true, filled: false });
    });

    // Defense in depth for the no-plaintext invariant: even if a misbehaving bridge included a
    // raw value alongside value_present, the actor must never surface it.
    it("never surfaces a credential value even if the bridge read includes one", async () => {
      const g = new FakeGhost();
      const bridge = new FakeBridge([
        { name: "Password", role: "edit", value_present: true, value: "hunter2-sentinel-secret" }
      ]);
      const a = new CometActor(g as any, bridge as any);
      const r = await a.credentialFill({ name: "Password", role: "edit" });
      expect(JSON.stringify(r)).not.toContain("hunter2-sentinel-secret");
    });

    it("does not send autofill keys, and fails closed, when focusing the field fails", async () => {
      class UnfocusableGhost extends FakeGhost {
        override async act(args: any) { this.calls.push(["act", args]); return { ok: false }; }
      }
      const g = new UnfocusableGhost();
      const bridge = new FakeBridge([]);
      let readCalled = false;
      (bridge as any).read = async () => { readCalled = true; return { elements: [] }; };
      const a = new CometActor(g as any, bridge as any);
      const r = await a.credentialFill({ name: "Password", role: "edit" });
      expect(g.calls.map((c) => c[0])).toEqual(["act"]);
      expect(readCalled).toBe(false);
      expect(r).toEqual({ ok: false, filled: false });
    });
  });

  // Phase 5 Task 26: SUBMIT left policy.DANGEROUS, so this is now a real, reachable actor method.
  describe("submit", () => {
    it("clicks the named submit control when an element is given", async () => {
      const g = new FakeGhost();
      const a = new CometActor(g as any);
      const r = await a.submit({ name: "Send", role: "button" });
      expect(g.calls.map((c) => c[0])).toEqual(["act"]);
      expect(g.calls[0]![1].action).toBe("click");
      expect(g.calls[0]![1].name).toBe("Send");
      expect(r).toEqual({ ok: true, verified: true });
    });

    it("presses Enter in the focused field, scoped to the Comet window, when no element is given", async () => {
      const g = new FakeGhost();
      const a = new CometActor(g as any);
      const r = await a.submit();
      expect(g.calls.map((c) => c[0])).toEqual(["press"]);
      expect(g.calls[0]![1].key).toBe("Enter");
      expect(g.calls[0]![1].window).toMatch(/comet/i);
      expect(r).toEqual({ ok: true });
    });
  });
});
