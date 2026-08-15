import { createHash } from "node:crypto";
import type { GhostTools } from "./ghost_client.js";

export type StabilityOpts = {
  poll_ms?: number;
  timeout_ms: number;
  initial_delay_ms?: number;
};

export type StabilityResult = {
  jpeg_base64: string;
  stable: boolean;        // true if two consecutive hashes matched; false if timed out
  polls: number;
};

export async function poll_until_stable(g: GhostTools, opts: StabilityOpts): Promise<StabilityResult> {
  const poll_ms = opts.poll_ms ?? 1000;
  const initial = opts.initial_delay_ms ?? 0;
  if (initial > 0) await sleep(initial);
  const deadline = Date.now() + opts.timeout_ms;
  let prev_hash = "";
  let polls = 0;
  let last_jpeg = "";
  while (Date.now() < deadline) {
    const { jpeg_base64 } = await g.screenshot_region({ foreground: true });
    last_jpeg = jpeg_base64;
    polls++;
    const hash = createHash("sha256").update(jpeg_base64).digest("hex");
    if (hash === prev_hash && polls >= 2) {
      return { jpeg_base64, stable: true, polls };
    }
    prev_hash = hash;
    await sleep(poll_ms);
  }
  return { jpeg_base64: last_jpeg, stable: false, polls };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
