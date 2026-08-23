import type { GhostTools } from "./ghost_client.js";
import { extract_from_screenshot as anthropic_extract, type Citation } from "./vision_extractor.js";
import { extract_from_screenshot as nvidia_extract } from "./nvidia_extractor.js";
import { poll_until_stable } from "./screenshot_stability.js";
import { findOrLaunchComet } from "./comet_window.js";

// Read at CALL time, not module load: env vars set after import (test harnesses, MCP clients
// configuring the server post-spawn) were silently ignored with the module-load snapshot.
function extractor() {
  return (process.env.COMET_VISION_PROVIDER ?? "anthropic").toLowerCase() === "nvidia"
    ? nvidia_extract
    : anthropic_extract;
}

const STREAM_POLL_MS = 1000;
const STREAM_INITIAL_DELAY_MS = 2000;
const DEFAULT_TIMEOUT_MS = 300_000;

export type AskResult = {
  answer: string;
  sources: Citation[];
  truncated?: boolean;
};

export class CometDriver {
  private busy = false;

  constructor(private g: GhostTools) {}

  async ask(query: string, timeout_ms = DEFAULT_TIMEOUT_MS): Promise<AskResult> {
    if (this.busy) throw new Error("busy: a query is already in flight");
    this.busy = true;
    // The paste sequence destroys the user's clipboard; save it and restore in finally so the
    // side effect does not outlive the query. If the read fails (older ghost builds), proceed
    // without restore rather than blocking the query.
    let savedClipboard: string | undefined;
    try {
      try { savedClipboard = (await this.g.get_clipboard()).text; } catch { /* optional */ }
      const win = await findOrLaunchComet(this.g);
      await this.g.focus_window(win.name);
      await sleep(300);

      // Focus address/ask bar, paste query, submit. Enter is SCOPED to the Comet window -
      // unscoped, it dispatches to whatever owns OS focus, which after any focus race can be
      // an unrelated app.
      await this.g.hotkey(["Ctrl"], "L");
      await sleep(150);
      await this.g.set_clipboard(query);
      await sleep(60);
      await this.g.hotkey(["Ctrl"], "V");
      await sleep(80);
      await this.g.press("Enter", win.name);

      // Wait for answer to start streaming, then for screenshot to stabilize.
      const stab = await poll_until_stable(this.g, {
        poll_ms: STREAM_POLL_MS,
        timeout_ms,
        initial_delay_ms: STREAM_INITIAL_DELAY_MS
      });

      const result = await extractor()(stab.jpeg_base64, query);
      const truncated = !stab.stable;

      if (!result.answer) {
        // One retry: sometimes the first vision pass catches a half-rendered page.
        await sleep(1500);
        const { jpeg_base64 } = await this.g.screenshot_region({ foreground: true });
        const retry = await extractor()(jpeg_base64, query);
        if (!retry.answer) {
          throw new Error("vision could not read the answer (two attempts). Comet may not have completed the query.");
        }
        return truncated ? { ...retry, truncated: true } : retry;
      }
      return truncated ? { ...result, truncated: true } : result;
    } finally {
      if (savedClipboard !== undefined) {
        try { await this.g.set_clipboard(savedClipboard); } catch { /* best effort */ }
      }
      this.busy = false;
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}