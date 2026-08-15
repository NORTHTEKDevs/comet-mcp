import { describe, it, expect, vi } from "vitest";

// assistantAsk's tail (screenshot-stabilise then vision-extract) is live-verified and network/GPU
// bound; these tests target the click/wait/window-anchor logic, so the tail is stubbed.
vi.mock("../src/screenshot_stability.js", () => ({
  poll_until_stable: async () => ({ stable: true, jpeg_base64: "aGk=" })
}));
vi.mock("../src/nvidia_extractor.js", () => ({
  extract_from_screenshot: async () => ({ answer: "Tokyo", citations: [] })
}));
vi.mock("../src/vision_extractor.js", () => ({
  extract_from_screenshot: async () => ({ answer: "Tokyo", citations: [] })
}));

import { CometActor, ASSISTANT_UI } from "../src/actor.js";

// Regression fixtures for two live failures observed 2026-08-15 driving the real Comet browser:
//
// 1. STALE WINDOW-TITLE ANCHOR: assistantAsk captured the Comet window TITLE once, then the title
//    flipped mid-flow ("Untitled - Comet" -> "Perplexity - Comet" as the tab/sidebar settled), so
//    the later ghost_find failed with "could not focus window 'Untitled - Comet'" even though the
//    window and the input both existed.
//
// 2. UNFOCUSED CLICK: the sidebar-toggle click dispatched against an UNFOCUSED Comet window and
//    silently did nothing (ghost reported ok), so the input never appeared and the wait poll blew
//    with "Element not found: Type / for search modes" while the VLM was perfectly healthy.

const INPUT = ASSISTANT_UI.inputName;

class BaseGhost {
  calls: Array<[string, any]> = [];
  title = "Perplexity - Comet";
  async list_windows() { return { windows: [{ name: this.title, pid: 1, focused: true }] }; }
  async launch(exe: string) { this.calls.push(["launch", exe]); return { ok: true as const }; }
  async focus_window(name: string) { this.calls.push(["focus_window", name]); return { ok: true as const }; }
  async act(args: any) { this.calls.push(["act", args]); return { ok: true, verified: true }; }
  async find(args: any) { this.calls.push(["find", args]); return { center: { x: 100, y: 50 } }; }
  async press(key: string, window?: string) { this.calls.push(["press", { key, window }]); return { ok: true as const }; }
}

function fastPoll() {
  process.env.COMET_ASSISTANT_INPUT_WAIT_MS = "250";
  process.env.COMET_ASSISTANT_INPUT_POLL_MS = "50";
  return () => {
    delete process.env.COMET_ASSISTANT_INPUT_WAIT_MS;
    delete process.env.COMET_ASSISTANT_INPUT_POLL_MS;
  };
}

describe("CometActor.assistantAsk live-failure regressions", () => {
  it("survives the window title changing between sidebar-open and input-wait (stale anchor)", async () => {
    class TitleFlipGhost extends BaseGhost {
      override title = "Untitled - Comet";
      override async act(args: any) {
        const r = await super.act(args);
        // Opening the sidebar settles the tab and renames the OS window - observed live.
        if (args.name === ASSISTANT_UI.buttonName) this.title = "Perplexity - Comet";
        return r;
      }
      override async find(args: any) {
        // ghost_find's window anchor focuses BY TITLE and fails hard on a stale one.
        if (args.window !== undefined && args.window !== this.title) {
          throw new Error(`ghost_find: could not focus window '${args.window}': Process not found`);
        }
        return super.find(args);
      }
    }
    const restore = fastPoll();
    try {
      const g = new TitleFlipGhost();
      const a = new CometActor(g as any);
      const r = await a.assistantAsk("What is the capital of Japan?");
      expect(r.answer).toBe("Tokyo");
    } finally { restore(); }
  });

  it("focuses the Comet window before the sidebar-open click (unfocused click no-ops)", async () => {
    class UnfocusedGhost extends BaseGhost {
      focused = false;
      sidebarOpen = false;
      override async focus_window(name: string) { this.focused = true; return super.focus_window(name); }
      override async act(args: any) {
        if (args.name === ASSISTANT_UI.buttonName) {
          // A click on an unfocused window dispatches but toggles nothing - observed live.
          if (this.focused) this.sidebarOpen = true;
        }
        return super.act(args);
      }
      override async find(args: any) {
        if (args.name === INPUT && !this.sidebarOpen) throw new Error(`Element not found: Name("${INPUT}")`);
        return super.find(args);
      }
    }
    const restore = fastPoll();
    try {
      const g = new UnfocusedGhost();
      const a = new CometActor(g as any);
      const r = await a.assistantAsk("q");
      expect(r.answer).toBe("Tokyo");
      const firstFocus = g.calls.findIndex((c) => c[0] === "focus_window");
      const firstClick = g.calls.findIndex((c) => c[0] === "act" && c[1].name === ASSISTANT_UI.buttonName);
      expect(firstFocus).toBeGreaterThanOrEqual(0);
      expect(firstFocus).toBeLessThan(firstClick);
    } finally { restore(); }
  });

  it("re-clicks the sidebar toggle once when the input never appears after the first click", async () => {
    class DroppedClickGhost extends BaseGhost {
      clicksOnToggle = 0;
      sidebarOpen = false;
      override async act(args: any) {
        if (args.name === ASSISTANT_UI.buttonName) {
          this.clicksOnToggle++;
          // First click is dropped (foreground stolen mid-action - observed live); second lands.
          if (this.clicksOnToggle >= 2) this.sidebarOpen = true;
        }
        return super.act(args);
      }
      override async find(args: any) {
        if (args.name === INPUT && !this.sidebarOpen) throw new Error(`Element not found: Name("${INPUT}")`);
        return super.find(args);
      }
    }
    const restore = fastPoll();
    try {
      const g = new DroppedClickGhost();
      const a = new CometActor(g as any);
      const r = await a.assistantAsk("q");
      expect(r.answer).toBe("Tokyo");
      expect(g.clicksOnToggle).toBe(2);
    } finally { restore(); }
  });
});
