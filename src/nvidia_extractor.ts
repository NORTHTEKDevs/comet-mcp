import { parse_vision_json, type ExtractResult } from "./vision_extractor.js";

const NVIDIA_MODEL = process.env.COMET_NVIDIA_MODEL ?? "meta/llama-3.2-90b-vision-instruct";
const NVIDIA_ENDPOINT = process.env.NVIDIA_API_BASE ?? "https://integrate.api.nvidia.com/v1/chat/completions";

const SYSTEM_PROMPT = `You are extracting structured data from a screenshot of Perplexity Comet's answer page.

Return STRICT JSON ONLY. No prose, no markdown fences, no explanation.

Shape:
{"answer":"<the main answer text in plain prose, no inline citation markers like [1] [2]>","sources":[{"n":1,"title":"<visible source title>"}]}

If the answer is not yet visible or still loading, return {"answer":"","sources":[]}.
If no sources visible, sources should be [].
Output ONLY the JSON object.`;

export async function extract_from_screenshot(png_base64: string, query: string): Promise<ExtractResult> {
  const api_key = process.env.NVIDIA_API_KEY;
  if (!api_key) throw new Error("NVIDIA_API_KEY env var not set");

  const body = {
    model: NVIDIA_MODEL,
    max_tokens: 4096,
    temperature: 0.1,
    messages: [
      {
        role: "user",
        content: [
          { type: "text", text: `${SYSTEM_PROMPT}\n\nThe user asked: "${query}". Extract the answer and sources from this screenshot.` },
          { type: "image_url", image_url: { url: `data:image/png;base64,${png_base64}` } }
        ]
      }
    ]
  };

  const resp = await fetch(NVIDIA_ENDPOINT, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${api_key}`,
      "Accept": "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  if (!resp.ok) {
    const err_body = await resp.text();
    throw new Error(`NVIDIA API ${resp.status}: ${err_body.slice(0, 500)}`);
  }

  const data = await resp.json() as { choices?: Array<{ message?: { content?: string } }> };
  const text = data?.choices?.[0]?.message?.content?.trim() ?? "";
  if (!text) return { answer: "", sources: [] };
  return parse_vision_json(text);
}
