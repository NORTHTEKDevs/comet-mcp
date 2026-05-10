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

export type UiaElement = {
  name: string;
  role: string;
  left: number;
  top: number;
  right: number;
  bottom: number;
};

export type Citation = { n: number; title: string };

export function walk_citations(elements: UiaElement[] | null | undefined): Citation[] {
  if (!elements || elements.length === 0) return [];
  const sources_header = elements.find(
    (e) => /^sources$/i.test(e.name) && (e.role === "text" || e.role === "group" || e.role === "heading")
  );
  if (!sources_header) return [];
  const links = elements
    .filter((e) => /(hyperlink|link)/i.test(e.role) && e.top > sources_header.top && e.name.trim().length > 0)
    .sort((a, b) => a.top - b.top);
  return links.map((link, i) => ({ n: i + 1, title: link.name.trim() }));
}

export function is_login_wall(elements: UiaElement[] | null | undefined): boolean {
  if (!elements || elements.length === 0) return false;
  const has_sign_in = elements.some((e) => /sign in/i.test(e.name));
  const has_continue_button = elements.some((e) => e.role === "button" && /continue with/i.test(e.name));
  return has_sign_in && has_continue_button;
}
