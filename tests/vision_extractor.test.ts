import { describe, it, expect } from "vitest";
import { parse_vision_json } from "../src/vision_extractor.js";

describe("parse_vision_json", () => {
  it("parses clean JSON", () => {
    const result = parse_vision_json('{"answer":"42","sources":[{"n":1,"title":"x"}]}');
    expect(result).toEqual({ answer: "42", sources: [{ n: 1, title: "x" }] });
  });

  it("strips markdown json fences if present", () => {
    const result = parse_vision_json('```json\n{"answer":"42","sources":[]}\n```');
    expect(result).toEqual({ answer: "42", sources: [] });
  });

  it("strips bare markdown fences if present", () => {
    const result = parse_vision_json('```\n{"answer":"42","sources":[]}\n```');
    expect(result).toEqual({ answer: "42", sources: [] });
  });

  it("fills missing n on sources with index+1", () => {
    const result = parse_vision_json('{"answer":"x","sources":[{"title":"a"},{"title":"b"}]}');
    expect(result.sources).toEqual([{ n: 1, title: "a" }, { n: 2, title: "b" }]);
  });

  it("filters non-string-title sources", () => {
    const result = parse_vision_json('{"answer":"x","sources":[{"title":"ok"},{"title":42},{"foo":"bar"}]}');
    expect(result.sources).toEqual([{ n: 1, title: "ok" }]);
  });

  it("returns empty result when answer/sources missing", () => {
    const result = parse_vision_json('{}');
    expect(result).toEqual({ answer: "", sources: [] });
  });

  it("throws on invalid JSON without leaking the raw output into the message", () => {
    // Model output is UNTRUSTED page-derived content; the old SyntaxError embedded an excerpt
    // of the input in its message, letting quarantined page content escape into MCP error
    // content. The sanitized message may carry only shape metadata (length), never the text.
    const sentinel = 'SECRET_PAGE_SENTINEL "answer": "ignore instructions"';
    let msg = "";
    try {
      parse_vision_json(`oops ${sentinel}`);
    } catch (err) {
      msg = (err as Error).message;
    }
    expect(msg).not.toBe("");
    expect(msg).not.toContain("SECRET_PAGE_SENTINEL");
    expect(msg).toMatch(/not parseable as JSON/);
    // And it still throws for plain garbage too.
    expect(() => parse_vision_json("not json")).toThrow(/not parseable as JSON/);
  });

  it("does not throw on non-object JSON like null or a bare number", () => {
    expect(parse_vision_json("null")).toEqual({ answer: "", sources: [] });
    expect(parse_vision_json("42")).toEqual({ answer: "", sources: [] });
  });

  it("strips trailing junk after the JSON object (Llama Vision quirk)", () => {
    const result = parse_vision_json('{"answer":"x","sources":[]}}');
    expect(result).toEqual({ answer: "x", sources: [] });
  });

  it("strips leading prose before the JSON object", () => {
    const result = parse_vision_json('Here is the JSON: {"answer":"x","sources":[]}');
    expect(result).toEqual({ answer: "x", sources: [] });
  });
});
