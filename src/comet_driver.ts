import type { GhostTools, GhostWindow } from "./ghost_client.js";
import { is_login_wall, parse_clipboard_answer, walk_citations, is_stream_stable, type Citation, type UiaNode } from "./extractor.js";

const COMET_EXE = process.env.COMET_EXE_PATH
  ?? `${process.env.LOCALAPPDATA}\\Comet\\Application\\Comet.exe`;
const LAUNCH_POLL_MS = 500;
const LAUNCH_MAX_MS = 8000;
const STREAM_POLL_MS = 200;
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
      await this.g.focus_window(win.handle);
      await sleep(300);

      const initial_tree = (await this.g.describe_screen()).tree as UiaNode;
      if (is_login_wall(initial_tree)) {
        throw new Error("Comet shows a sign-in wall. Open Comet manually and sign in once, then retry.");
      }

      await this.g.hotkey("Ctrl+L");
      await sleep(150);
      await this.g.type(query);
      await this.g.press("Enter");

      const { final_tree, truncated } = await this.poll_until_stable(timeout_ms);
      await this.g.hotkey("Ctrl+A");
      await sleep(80);
      await this.g.hotkey("Ctrl+C");
      await sleep(120);
      const cb = await this.g.get_clipboard();
      let answer = parse_clipboard_answer(cb.text ?? "");
      if (answer.length < 10) {
        // one retry
        await this.g.hotkey("Ctrl+C");
        await sleep(150);
        const cb2 = await this.g.get_clipboard();
        answer = parse_clipboard_answer(cb2.text ?? "");
        if (answer.length < 10) throw new Error("clipboard empty after answer extraction");
      }
      const sources = walk_citations(final_tree);
      return truncated ? { answer, sources, truncated: true } : { answer, sources };
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
    return windows.find((w) =>
      /comet\.exe$/i.test(w.process) || /perplexity|comet/i.test(w.title)
    ) ?? null;
  }

  private async poll_until_stable(timeout_ms: number): Promise<{ final_tree: UiaNode; truncated: boolean }> {
    const deadline = Date.now() + timeout_ms;
    let prev_text = "";
    let last_tree: UiaNode | null = null;
    while (Date.now() < deadline) {
      await sleep(STREAM_POLL_MS);
      const { tree } = await this.g.describe_screen();
      last_tree = tree as UiaNode;
      const sources_present = walk_citations(last_tree).length > 0;
      const curr_text = extract_visible_text(last_tree);
      if (sources_present && is_stream_stable(prev_text, curr_text)) {
        return { final_tree: last_tree, truncated: false };
      }
      prev_text = curr_text;
    }
    if (!last_tree) throw new Error("describe_screen never returned a tree");
    return { final_tree: last_tree, truncated: true };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function extract_visible_text(node: UiaNode | null | undefined): string {
  if (!node) return "";
  const own = node.role === "text" ? node.name : "";
  const child_text = (node.children ?? []).map(extract_visible_text).join(" ");
  return (own + " " + child_text).trim();
}
