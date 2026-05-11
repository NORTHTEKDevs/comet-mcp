import type { GhostTools, GhostWindow } from "./ghost_client.js";
import { extract_from_screenshot, type Citation } from "./vision_extractor.js";
import { poll_until_stable } from "./screenshot_stability.js";

const COMET_EXE = process.env.COMET_EXE_PATH
  ?? `${process.env.LOCALAPPDATA}\\Comet\\Application\\Comet.exe`;
const LAUNCH_POLL_MS = 500;
const LAUNCH_MAX_MS = 8000;
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
    try {
      const win = await this.find_or_launch_comet();
      await this.g.focus_window(win.name);
      await sleep(300);

      // Focus address/ask bar, paste query, submit.
      await this.g.hotkey(["Ctrl"], "L");
      await sleep(150);
      await this.g.set_clipboard(query);
      await sleep(60);
      await this.g.hotkey(["Ctrl"], "V");
      await sleep(80);
      await this.g.press("Enter");

      // Wait for answer to start streaming, then for screenshot to stabilize.
      const stab = await poll_until_stable(this.g, {
        poll_ms: STREAM_POLL_MS,
        timeout_ms,
        initial_delay_ms: STREAM_INITIAL_DELAY_MS
      });

      const result = await extract_from_screenshot(stab.png_base64, query);
      const truncated = !stab.stable;

      if (!result.answer) {
        // One retry: sometimes the first vision pass catches a half-rendered page.
        await sleep(1500);
        const { png_base64 } = await this.g.screenshot_region({ foreground: true });
        const retry = await extract_from_screenshot(png_base64, query);
        if (!retry.answer) {
          throw new Error("vision could not read the answer (two attempts). Comet may not have completed the query.");
        }
        return truncated ? { ...retry, truncated: true } : retry;
      }
      return truncated ? { ...result, truncated: true } : result;
    } finally {
      this.busy = false;
    }
  }

  private async find_or_launch_comet(): Promise<GhostWindow> {
    const found = await this.find_comet();
    if (found) return found;
    await this.g.launch(COMET_EXE);
    const deadline = Date.now() + LAUNCH_MAX_MS;
    while (Date.now() < deadline) {
      await sleep(LAUNCH_POLL_MS);
      const w = await this.find_comet();
      if (w) return w;
    }
    throw new Error(`Comet did not appear within ${LAUNCH_MAX_MS}ms after launch (${COMET_EXE})`);
  }

  private async find_comet(): Promise<GhostWindow | null> {
    const { windows } = await this.g.list_windows();
    return windows.find((w) => /comet|perplexity/i.test(w.name)) ?? null;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
