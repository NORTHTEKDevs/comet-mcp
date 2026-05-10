import { describe, it, expect } from "vitest";
import { is_stream_stable } from "../src/extractor.js";

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
