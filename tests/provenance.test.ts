import { describe, it, expect } from "vitest";
import { originOf, tagUntrusted, tagTrusted, merge, isForeignTo, type Provenance } from "../src/provenance.js";

describe("provenance", () => {
  describe("originOf", () => {
    it("returns the lowercased hostname for a valid url", () => {
      expect(originOf("https://Mail.Google.com/mail/u/0")).toBe("mail.google.com");
    });

    it("returns null for an unparseable url", () => {
      expect(originOf("not a url")).toBeNull();
    });

    it("returns null for a url with no host", () => {
      expect(originOf("mailto:test@example.com")).toBeNull();
    });
  });

  describe("tagUntrusted", () => {
    it("records the source page's host with untrusted trust", () => {
      const t = tagUntrusted("hello", "https://evil.com/page");
      expect(t.value).toBe("hello");
      expect(t.provenance.origins).toEqual(["evil.com"]);
      expect(t.provenance.trust).toBe("untrusted");
    });
  });

  describe("tagTrusted", () => {
    it("carries no page origin and trusted trust", () => {
      const t = tagTrusted("hello");
      expect(t.value).toBe("hello");
      expect(t.provenance.origins).toEqual([]);
      expect(t.provenance.trust).toBe("trusted");
    });
  });

  describe("merge", () => {
    it("unions origins from both sides", () => {
      const a: Provenance = { origins: ["a.com"], trust: "trusted" };
      const b: Provenance = { origins: ["b.com"], trust: "trusted" };
      const m = merge(a, b);
      expect(m.origins.sort()).toEqual(["a.com", "b.com"]);
    });

    it("downgrades trust to untrusted if either side is untrusted", () => {
      const trusted: Provenance = { origins: ["a.com"], trust: "trusted" };
      const untrusted: Provenance = { origins: ["b.com"], trust: "untrusted" };
      expect(merge(trusted, untrusted).trust).toBe("untrusted");
      expect(merge(untrusted, trusted).trust).toBe("untrusted");
    });

    it("stays trusted only when both sides are trusted", () => {
      const a: Provenance = { origins: ["a.com"], trust: "trusted" };
      const b: Provenance = { origins: ["b.com"], trust: "trusted" };
      expect(merge(a, b).trust).toBe("trusted");
    });

    it("de-duplicates origins present on both sides", () => {
      const a: Provenance = { origins: ["a.com"], trust: "trusted" };
      const b: Provenance = { origins: ["a.com"], trust: "trusted" };
      expect(merge(a, b).origins).toEqual(["a.com"]);
    });
  });

  describe("isForeignTo", () => {
    it("is true when the provenance contains an origin different from the destination", () => {
      const p: Provenance = { origins: ["evil.com"], trust: "untrusted" };
      expect(isForeignTo(p, "good.com")).toBe(true);
    });

    it("is false when it is same-origin only", () => {
      const p: Provenance = { origins: ["good.com"], trust: "untrusted" };
      expect(isForeignTo(p, "good.com")).toBe(false);
    });

    it("reports foreign even when the provenance is marked trusted (trust != provenance)", () => {
      const p: Provenance = { origins: ["evil.com"], trust: "trusted" };
      expect(isForeignTo(p, "good.com")).toBe(true);
    });

    it("is true when any one of multiple origins differs from the destination", () => {
      const p: Provenance = { origins: ["good.com", "evil.com"], trust: "untrusted" };
      expect(isForeignTo(p, "good.com")).toBe(true);
    });
  });
});
