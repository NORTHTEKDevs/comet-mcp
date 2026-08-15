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

  it("throws on invalid JSON", () => {
    expect(() => parse_vision_json("not json")).toThrow();
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
