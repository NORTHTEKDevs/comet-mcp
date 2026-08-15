export type Citation = { n: number; title: string };

const MIN_STABLE_LENGTH = 20;

export function is_stream_stable(prev: string, curr: string): boolean {
  if (curr.length < MIN_STABLE_LENGTH) return false;
  return prev === curr;
}

const HEADER_PATTERNS = [/^Pro Search\s*\n+/i, /^Quick Search\s*\n+/i];
const SOURCES_FOOTER = /\n+Sources\s*\n[\s\S]*$/i;

export function parse_clipboard_answer(raw: string): string {
  let text = raw.trim();
  if (!text) return "";
  for (const re of HEADER_PATTERNS) text = text.replace(re, "");
  text = text.replace(SOURCES_FOOTER, "");
  return text.trim();
}
