import type { GhostTools } from "./ghost_client.js";
import { findOrLaunchComet } from "./comet_window.js";
import { extract_from_screenshot as anthropic_extract } from "./vision_extractor.js";
import { extract_from_screenshot as nvidia_extract } from "./nvidia_extractor.js";
import { poll_until_stable } from "./screenshot_stability.js";

export type ElementRef = { name?: string; role?: string };
export type ActResult = { ok: boolean; verified?: boolean };

// Distance below the address bar to land inside page content when scrolling.
const PAGE_CONTENT_OFFSET_Y = 300;

// Task 38 (Phase 6): same dual-provider selection as comet_driver.ts's ask_perplexity path -
// assistantAsk reads the Assistant sidebar's answer the identical way (screenshot-stabilise then
// vision-extract), since Comet page/sidebar CONTENT is invisible to UIA (see the plan's
// live-verified facts block) and there is no named "answer container" element to read by
// accessible name.
const VISION_PROVIDER = (process.env.COMET_VISION_PROVIDER ?? "anthropic").toLowerCase();
const extract_from_screenshot = VISION_PROVIDER === "nvidia" ? nvidia_extract : anthropic_extract;

// Task 38 (Phase 6): live-verified 2026-08-14 (Step 0 of the Task 38 spec) against the real,
// running Comet browser via ghost_snapshot({actionable_only:true}) on a focused Comet window:
// - a toolbar button named "Assistant" (role button) opens the Perplexity Assistant sidebar.
// - the sidebar's query field's accessible name is "Ask anything" plus a trailing single Unicode
//   ellipsis codepoint (U+2026, NOT three ASCII periods) once opened - built below with a
//   backslash-u escape (source text "u 2 0 2 6", no literal Unicode byte) so the exact codepoint
//   survives any formatting pass; a literal ellipsis character in source is exactly what a "no
//   decorative Unicode" formatting pass normalizes to three periods, which silently breaks the
//   match - reproduced live on this very file while writing this constant (the literal character
//   was rewritten to three periods twice in a row before this fix).
// A single exported constant block so a UI rename is a one-line fix. The live Comet window closed
// (unrelated to this driving - a pre-existing tab/process, not launched by this run) before a
// query could be submitted to also observe the answer container's accessible name, so this
// deliberately does NOT claim one it never verified - assistantAsk below reads the answer via
// screenshot-stabilise + vision-extract instead (same mechanism CometDriver.ask already uses for
// ask_perplexity), which needs no named answer element at all. See the Task 38 spec's Step 0 and
// its escape hatch ("if the Assistant proves undrivable by name, fall back to the existing
// ask_perplexity address-bar path and SAY SO") - the button and input WERE drivable by name; only
// the answer-read path uses that documented fallback mechanism, not the click/type path.
export const ASSISTANT_UI = {
  buttonName: "Assistant",
  buttonRole: "button",
  inputName: "Ask anything" + "\u2026",
  inputRole: "edit"
} as const;

// Landing-check polling and navigate retry. Read at CALL time, not module load, so a test can turn
// the backoff off without re-importing the module (and so an operator can retune without a restart).
const navTuning = () => ({
  attempts: Number(process.env.COMET_LANDING_ATTEMPTS ?? 3),
  retryMs: Number(process.env.COMET_LANDING_RETRY_MS ?? 700),
  cycles: Number(process.env.COMET_NAV_CYCLES ?? 2)
});
const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

const ASSISTANT_STABILITY_INITIAL_DELAY_MS = 2000;
const DEFAULT_ASSISTANT_TIMEOUT_MS = 300_000;

// Chromium's standard behaviour on a saved-login field: Down opens the autofill dropdown,
// Enter accepts the (only) suggestion. Named + exported so a test can assert the exact sequence
// and so it can be retuned without touching credentialFill's logic.
export const AUTOFILL_KEY_SEQUENCE = ["Down", "Enter"] as const;

// The comet-bridge extension's page reader (see docs/plans phase1 Task 4 / reader.js). Read-only,
// and by contract the elements it returns carry value_present (a boolean) but NEVER a raw value -
// credentialFill relies on that contract to verify a fill without ever seeing the secret.
export interface CredentialBridgeReader {
  read(payload?: Record<string, unknown>): Promise<unknown>;
  // Optional: navigate the active tab via the extension (chrome.tabs.update) and return the tab's
  // REAL final url. Preferred over Ghost's omnibox navigation - see navigate() for why.
  navigate?(url: string, timeoutMs?: number): Promise<{ url?: string; error?: string }>;
}

type ReaderElement = { name?: unknown; role?: unknown; value_present?: unknown };

function elementMatches(e: ReaderElement, target: ElementRef): boolean {
  if (target.name !== undefined && e.name !== target.name) return false;
  if (target.role !== undefined && e.role !== target.role) return false;
  return true;
}

// Drives the live Comet window via Ghost's high-level a11y verbs (find by accessible name, never
// raw coordinates). Every method resolves the target Comet window itself so callers never have to
// track focus state.
export class CometActor {
  // bridge is optional so existing construction sites (index.ts: new CometActor(tools)) keep
  // compiling; Phase 3 Task 20 wires the real bridge reader through. credentialFill fails closed
  // (filled:false) when it is absent rather than skipping verification.
  constructor(private g: GhostTools, private bridge?: CredentialBridgeReader) {}

  private async cometWindow(): Promise<string> {
    return (await findOrLaunchComet(this.g)).name;
  }

  // Navigating is NOT trustworthy on its own: a dropped first keystroke in the address bar was
  // observed live (asked for "https://mail.google.com/...", landed on "ttps://mail.google.com/...")
  // while ghost still reported success. Since policy authorises the REQUESTED url, an unverified
  // navigate lets the agent believe it is on an allowlisted domain while it is somewhere else.
  // So: navigate, then confirm the address bar actually contains the expected host.
  async navigate(url: string): Promise<{ ok: boolean; landed?: boolean; reason?: string }> {
    const window = await this.cometWindow();
    let host: string;
    try { host = new URL(url).hostname; } catch { return { ok: false, reason: "unparseable url" }; }

    // `ghost_wait for=navigate` CANNOT BE TRUSTED on its own: observed live, it returned
    // {ok:true} in 190ms having navigated nowhere, because Comet was not the foreground window
    // (other apps steal focus constantly on this machine). Every navigate after the first in a
    // run silently no-opped while reporting success - which would have let a mission read the
    // WRONG PAGE and believe it was on an allowlisted one. So: focus the window explicitly first,
    // then navigate, then VERIFY, and repeat the whole cycle if the browser did not move. The
    // landing check is the only thing that makes this safe; it is what caught the no-op.
    // PREFERRED PATH: drive the tab through the extension. It needs no OS foreground, no
    // keystrokes and no address bar, so none of the three failure modes seen live with Ghost's
    // omnibox navigation apply (dropped leading character; a silent no-op that still returned
    // ok:true; foreground stolen mid-action). It also returns the tab's REAL final url, so a
    // redirect is detected rather than assumed. Ghost remains the fallback, and remains the actor
    // for CLICK/TYPE where isTrusted input genuinely matters.
    if (this.bridge?.navigate) {
      try {
        const res = await this.bridge.navigate(url, 30000);
        const landedUrl = res?.url;
        if (landedUrl) {
          let landedHost: string;
          try { landedHost = new URL(landedUrl).hostname.toLowerCase(); } catch { landedHost = ""; }
          if (landedHost === host.toLowerCase()) return { ok: true, landed: true };
          return {
            ok: false, landed: false,
            reason: `navigation did not land on ${host}: tab is on ${landedHost || landedUrl}`
          };
        }
      } catch { /* fall through to the Ghost path below */ }
    }

    const { attempts, retryMs, cycles } = navTuning();
    let lastErr = "";
    for (let cycle = 0; cycle < cycles; cycle++) {
      try { await this.g.focus_window(window); } catch { /* best effort - verification is the gate */ }
      await this.g.navigate(url, window);

      for (let attempt = 0; attempt < attempts; attempt++) {
        try {
          await this.g.assert({ predicate: "value-contains", name: "Address and search bar", role: "edit", text: host });
          return { ok: true, landed: true };
        } catch (err) {
          lastErr = (err as Error).message;
          if (attempt < attempts - 1) await sleep(retryMs);
        }
      }
    }
    return { ok: false, landed: false, reason: `navigation did not land on ${host}: ${lastErr}` };
  }

  // ghost_act returns { ok, verified }; verified:false means the click/type dispatched but
  // nothing visibly changed. Return it rather than swallowing it so the audit layer (Task 8) sees it.
  async click(el: ElementRef): Promise<ActResult> {
    return this.g.act({ action: "click", ...el, window: await this.cometWindow() });
  }

  async type(text: string, el: ElementRef): Promise<ActResult> {
    return this.g.act({ action: "type", text_input: text, ...el, window: await this.cometWindow() });
  }

  // ghost_scroll needs a point to scroll AT. Anchor off the address bar (a reliably-present
  // element) and drop into the page content below it, rather than hardcoding screen coordinates.
  async scroll(direction: "up" | "down" | "left" | "right", amount?: number): Promise<{ ok: true }> {
    const window = await this.cometWindow();
    const anchor = await this.g.find({ name: "Address and search bar", role: "edit", window });
    return this.g.scroll(direction, anchor.center.x, anchor.center.y + PAGE_CONTENT_OFFSET_Y, amount);
  }

  // Native autofill fill path (Phase 3 Task 19). comet-mcp NEVER reads, requests, or returns a
  // credential value: the browser's own saved-login autofill injects the secret directly into the
  // DOM in response to the key sequence below, and the only thing this method ever inspects
  // afterward is the reader's value_present BOOLEAN. The result surface is {ok, filled} - nothing
  // else - by construction (an explicit object literal, never a spread of anything read-derived).
  async credentialFill(el: ElementRef): Promise<{ ok: boolean; filled: boolean }> {
    const window = await this.cometWindow();

    // 1. Focus the target field. If focusing fails, stop - never send autofill keys blind.
    const focused = await this.g.act({ action: "click", ...el, window });
    if (!focused.ok) return { ok: false, filled: false };

    // 2. Trigger the browser's saved-credential autofill: Down opens the dropdown, Enter accepts it.
    for (const key of AUTOFILL_KEY_SEQUENCE) {
      await this.g.press(key, window);
    }

    // 3. Verify by shape, never by value.
    const filled = await this.readValuePresent(el);
    return { ok: true, filled };
  }

  // Phase 5 Task 26: SUBMIT left policy.DANGEROUS, so this is now a real, reachable action - but
  // only when the run's policy lists SUBMIT in actions_allow (RunManager still runs the ordinary
  // policy guard first). Two forms, matching what a human does: click a named submit control if
  // one is given, or press Enter in whatever field already has focus if not - both scoped to the
  // Comet window like every other actor method, never OS-wide focus.
  async submit(el?: ElementRef): Promise<ActResult> {
    const window = await this.cometWindow();
    if (el !== undefined) {
      return this.g.act({ action: "click", ...el, window });
    }
    const result = await this.g.press("Enter", window);
    return { ok: result.ok };
  }

  // Task 38 (Phase 6): ask Comet's Perplexity Assistant sidebar - opens it, types the query,
  // submits (reusing submit()'s no-element "press Enter in the focused field" form), waits for
  // the streamed answer to stop changing, then vision-reads it. Returns the answer TEXT only -
  // RunManager.assistantAsk is what applies the untrusted-content/quarantine discipline on top of
  // this; this method has no opinion about content_mode and never redacts.
  async assistantAsk(query: string, timeoutMs: number = DEFAULT_ASSISTANT_TIMEOUT_MS): Promise<{ answer: string }> {
    await this.click({ name: ASSISTANT_UI.buttonName, role: ASSISTANT_UI.buttonRole });
    await this.type(query, { name: ASSISTANT_UI.inputName, role: ASSISTANT_UI.inputRole });
    await this.submit();

    const stab = await poll_until_stable(this.g, {
      timeout_ms: timeoutMs,
      initial_delay_ms: ASSISTANT_STABILITY_INITIAL_DELAY_MS
    });
    const result = await extract_from_screenshot(stab.png_base64, query);
    return { answer: result.answer };
  }

  private async readValuePresent(el: ElementRef): Promise<boolean> {
    if (!this.bridge) return false;
    let raw: unknown;
    try {
      raw = await this.bridge.read();
    } catch {
      return false;
    }
    if (raw === null || typeof raw !== "object") return false;
    const elements = (raw as Record<string, unknown>).elements;
    if (!Array.isArray(elements)) return false;
    const match = elements.find(
      (e): e is ReaderElement => e !== null && typeof e === "object" && elementMatches(e as ReaderElement, el)
    );
    return match !== undefined && match.value_present === true;
  }
}