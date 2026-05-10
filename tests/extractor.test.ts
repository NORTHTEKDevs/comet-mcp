import { describe, it, expect } from "vitest";
import { is_stream_stable, parse_clipboard_answer, walk_citations, is_login_wall } from "../src/extractor.js";
import answer_fixture from "./fixtures/answer-with-citations.json" with { type: "json" };
import login_fixture from "./fixtures/login-wall.json" with { type: "json" };

describe("is_stream_stable", () => {
  it("returns false when current is longer than previous", () => {
    expect(is_stream_stable("hello", "hello world")).toBe(false);
  });

  it("returns true when previous and current are identical and non-trivial", () => {
    expect(is_stream_stable("a complete and stable answer", "a complete and stable answer")).toBe(true);
  });

  it("returns false when both are empty", () => {
    expect(is_stream_stable("", "")).toBe(false);
  });

  it("returns false when below minimum length even if equal", () => {
    expect(is_stream_stable("hi", "hi")).toBe(false);
  });

  it("returns true when equal at exactly the minimum length", () => {
    const s = "x".repeat(20);
    expect(is_stream_stable(s, s)).toBe(true);
  });
});

describe("parse_clipboard_answer", () => {
  it("returns trimmed text unchanged when no UI noise", () => {
    expect(parse_clipboard_answer("  Plain answer.  ")).toBe("Plain answer.");
  });

  it("strips a trailing 'Sources' section if present", () => {
    const raw = "The answer is 42.\n\nSources\n1. example.com\n2. other.com";
    expect(parse_clipboard_answer(raw)).toBe("The answer is 42.");
  });

  it("strips a leading 'Pro Search' / 'Quick Search' header if present", () => {
    const raw = "Pro Search\n\nThe answer is 42.";
    expect(parse_clipboard_answer(raw)).toBe("The answer is 42.");
  });

  it("returns empty string on empty input", () => {
    expect(parse_clipboard_answer("")).toBe("");
  });

  it("returns empty string on whitespace-only input", () => {
    expect(parse_clipboard_answer("   \n\t  ")).toBe("");
  });
});

describe("walk_citations", () => {
  it("extracts {n, title} for each citation under Sources", () => {
    const sources = walk_citations(answer_fixture.elements);
    expect(sources).toEqual([
      { n: 1, title: "Example Domain" },
      { n: 2, title: "Other Domain" }
    ]);
  });

  it("returns empty array if no Sources heading present", () => {
    expect(walk_citations(login_fixture.elements)).toEqual([]);
  });

  it("returns empty array on null/empty input", () => {
    expect(walk_citations(null)).toEqual([]);
    expect(walk_citations([])).toEqual([]);
  });
});

describe("is_login_wall", () => {
  it("returns true when 'Sign in' text + 'Continue with' button both present", () => {
    expect(is_login_wall(login_fixture.elements)).toBe(true);
  });

  it("returns false on a normal answer page", () => {
    expect(is_login_wall(answer_fixture.elements)).toBe(false);
  });

  it("returns false on null/empty input", () => {
    expect(is_login_wall(null)).toBe(false);
    expect(is_login_wall([])).toBe(false);
  });
});
