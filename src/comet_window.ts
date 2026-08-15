import type { GhostTools, GhostWindow } from "./ghost_client.js";

// Verified against a live install 2026-08-13: Comet ships under Perplexity\Comet, NOT Comet\.
// The old default (%LOCALAPPDATA%\Comet\Application\Comet.exe) does not exist on disk, so
// findOrLaunchComet could only ever work if Comet happened to be running already.
const COMET_EXE = process.env.COMET_EXE_PATH
  ?? `${process.env.LOCALAPPDATA}\\Perplexity\\Comet\\Application\\comet.exe`;
const LAUNCH_POLL_MS = 500;
const LAUNCH_MAX_MS = 8000;

// Shared by CometDriver (ask_perplexity) and CometActor (navigate/click/type/scroll): find the
// live Comet window, launching it if it isn't already running.
export async function findOrLaunchComet(g: GhostTools): Promise<GhostWindow> {
  const found = await find_comet(g);
  if (found) return found;
  await g.launch(COMET_EXE);
  const deadline = Date.now() + LAUNCH_MAX_MS;
  while (Date.now() < deadline) {
    await sleep(LAUNCH_POLL_MS);
    const w = await find_comet(g);
    if (w) return w;
  }
  throw new Error(`Comet did not appear within ${LAUNCH_MAX_MS}ms after launch (${COMET_EXE})`);
}

async function find_comet(g: GhostTools): Promise<GhostWindow | null> {
  const { windows } = await g.list_windows();
  return windows.find((w) => /comet|perplexity/i.test(w.name)) ?? null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
