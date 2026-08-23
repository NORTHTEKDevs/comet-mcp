// HTTP client that dispatches jobs to the comet-bridge relay (a localhost process the Comet
// extension polls) and waits for the extension to post back a result. This is the only path by
// which comet-mcp talks to the relay; every failure mode below is a hard throw so a relay/network
// problem can never be mistaken for a successful (but empty) read.

export interface BridgeJobRequest {
  kind: string;
  payload?: unknown;
  query?: string;
  mode?: string;
}

export interface BridgePollOpts {
  timeoutMs: number;
  pollMs: number;
}

async function readJsonBody(r: Response, context: string): Promise<Record<string, unknown>> {
  const text = await r.text();
  if (!text) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`bridge ${context}: relay returned a non-JSON response (status ${r.status}): ${text.slice(0, 300)}`);
  }
  if (parsed && typeof parsed === "object") return parsed as Record<string, unknown>;
  return { value: parsed };
}

export class BridgeClient {
  constructor(private base: string, private token: string) {}

  private headers(): Record<string, string> {
    return { "content-type": "application/json", "x-bridge-token": this.token };
  }

  async dispatch(job: BridgeJobRequest): Promise<string> {
    const r = await fetch(`${this.base}/jobs`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(job),
      // A stalled relay must not block past a sane dispatch window - the poll loop's deadline
      // only bounds the RESULT wait, not this initial POST.
      signal: AbortSignal.timeout(15_000)
    });
    const body = await readJsonBody(r, "dispatch");
    if (r.status !== 201) {
      throw new Error(`bridge dispatch failed: ${r.status} ${JSON.stringify(body)}`);
    }
    const id = body.id;
    if (typeof id !== "string") {
      throw new Error(`bridge dispatch failed: relay response missing job id: ${JSON.stringify(body)}`);
    }
    return id;
  }

  async result(id: string, opts: BridgePollOpts): Promise<unknown> {
    const deadline = Date.now() + opts.timeoutMs;
    while (Date.now() < deadline) {
      // Each individual poll is bounded by the REMAINING budget (capped at 10s): a stalled HTTP
      // response otherwise blocks for undici's multi-minute defaults while the loop's own
      // deadline check never gets a chance to run.
      const remaining = deadline - Date.now();
      const r = await fetch(`${this.base}/jobs/${id}`, {
        headers: this.headers(),
        signal: AbortSignal.timeout(Math.min(remaining, 10_000))
      });
      const body = await readJsonBody(r, `poll job ${id}`);
      if (r.status !== 200) {
        throw new Error(`bridge poll job ${id} failed: ${r.status} ${JSON.stringify(body)}`);
      }
      if (body.status === "done") return body.result;
      if (body.status === "error") {
        const reason = typeof body.error === "string" ? body.error : "unknown error";
        throw new Error(`bridge job ${id} failed: ${reason}`);
      }
      await new Promise((resolve) => setTimeout(resolve, opts.pollMs));
    }
    throw new Error(`bridge job ${id} timed out after ${opts.timeoutMs}ms`);
  }
}
