import Anthropic from "@anthropic-ai/sdk";

export type Citation = { n: number; title: string };
export type ExtractResult = { answer: string; sources: Citation[] };

const VISION_MODEL = process.env.COMET_VISION_MODEL ?? "claude-sonnet-4-6";

const SYSTEM_PROMPT = `You are extracting structured data from a screenshot of Perplexity Comet's answer page.

Return STRICT JSON in this exact shape (no prose, no markdown fences, no explanation):
{
  "answer": "<the main answer text, in plain prose, no inline citation markers like [1] [2]>",
  "sources": [
    {"n": 1, "title": "<visible source title>"}
  ]
}

If the answer is not yet visible or still loading, return {"answer": "", "sources": []}.
If you can read the answer but no sources are visible, return sources as [].
Never wrap your output in markdown fences. Output ONLY the JSON object.`;

let _client: Anthropic | null = null;
function client(): Anthropic {
  if (!_client) {
    const auth_token = process.env.ANTHROPIC_AUTH_TOKEN;
    const api_key = process.env.ANTHROPIC_API_KEY;
    if (!auth_token && !api_key) {
      throw new Error("ANTHROPIC_AUTH_TOKEN or ANTHROPIC_API_KEY env var must be set");
    }
    // Prefer auth token (subscription billing) over API key (per-call billing).
    _client = auth_token
      ? new Anthropic({ authToken: auth_token, apiKey: null })
      : new Anthropic({ apiKey: api_key });
  }
  return _client;
}

export async function extract_from_screenshot(png_base64: string, query: string): Promise<ExtractResult> {
  const resp = await client().messages.create({
    model: VISION_MODEL,
    max_tokens: 4096,
    system: SYSTEM_PROMPT,
    messages: [
      {
        role: "user",
        content: [
          { type: "image", source: { type: "base64", media_type: "image/png", data: png_base64 } },
          { type: "text", text: `The user asked: "${query}". Extract the answer and sources from this screenshot.` }
        ]
      }
    ]
  });
  const text_block = resp.content.find((b) => b.type === "text");
  const text = text_block && "text" in text_block ? text_block.text.trim() : "";
  if (!text) return { answer: "", sources: [] };
  return parse_vision_json(text);
}

export function parse_vision_json(text: string): ExtractResult {
  // Strip markdown fences if the model defied instructions
  let cleaned = text.trim();
  if (cleaned.startsWith("```")) {
    cleaned = cleaned.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/, "").trim();
  }
  // Some models (Llama Vision) emit trailing/leading junk around the JSON.
  // Walk braces to find the first balanced JSON object and parse only that.
  const start = cleaned.indexOf("{");
  if (start >= 0) {
    let depth = 0;
    let in_str = false;
    let esc = false;
    for (let i = start; i < cleaned.length; i++) {
      const c = cleaned[i];
      if (esc) { esc = false; continue; }
      if (c === "\\") { esc = true; continue; }
      if (c === '"') { in_str = !in_str; continue; }
      if (in_str) continue;
      if (c === "{") depth++;
      else if (c === "}" && --depth === 0) {
        cleaned = cleaned.slice(start, i + 1);
        break;
      }
    }
  }
  const parsed = JSON.parse(cleaned);
  return {
    answer: typeof parsed.answer === "string" ? parsed.answer : "",
    sources: Array.isArray(parsed.sources)
      ? parsed.sources
          .filter((s: any) => s && typeof s.title === "string")
          .map((s: any, i: number) => ({ n: typeof s.n === "number" ? s.n : i + 1, title: s.title }))
      : []
  };
}
