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

export type UiaNode = {
  name: string;
  role: string;
  bounds?: { x: number; y: number; w: number; h: number };
  value?: string;
  children?: UiaNode[];
};

export type Citation = { n: number; title: string; url: string };

function find_subtree(node: UiaNode | null | undefined, predicate: (n: UiaNode) => boolean): UiaNode | null {
  if (!node) return null;
  if (predicate(node)) return node;
  for (const child of node.children ?? []) {
    const hit = find_subtree(child, predicate);
    if (hit) return hit;
  }
  return null;
}

function flatten(node: UiaNode | null | undefined): UiaNode[] {
  if (!node) return [];
  return [node, ...(node.children ?? []).flatMap(flatten)];
}

export function walk_citations(tree: UiaNode | null | undefined): Citation[] {
  if (!tree) return [];
  const sources_node = find_subtree(tree, (n) => /^sources$/i.test(n.name));
  if (!sources_node) return [];
  const links = flatten(sources_node).filter((n) => n.role === "hyperlink" && n.value);
  return links.map((link, i) => ({
    n: i + 1,
    title: link.name,
    url: link.value!
  }));
}

export function is_login_wall(tree: UiaNode | null | undefined): boolean {
  if (!tree) return false;
  const all = flatten(tree);
  const has_sign_in = all.some((n) => /sign in/i.test(n.name));
  const has_continue_button = all.some((n) => n.role === "button" && /continue with/i.test(n.name));
  return has_sign_in && has_continue_button;
}
