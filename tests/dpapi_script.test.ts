import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// Regression for the single worst bug of the whole build, and the ONLY one that a live run could
// have found: `unwrapMasterKey` shells out to Windows PowerShell 5.1, which does NOT load the
// System.Security assembly by default - so `[System.Security.Cryptography.ProtectedData]` was an
// unknown type, every unwrap threw, and read()'s deliberate catch-all turned that into a plain
// `null`. The entire credential vault was dead in production while all 466 tests stayed green,
// because every unit test injects a fixture master key and never executes this function.
//
// unwrapMasterKey cannot be unit-tested without real DPAPI and a real profile, so this asserts the
// one property that was missing and is checkable statically: the PowerShell script loads the
// assembly it depends on. A source-level assertion is a poor substitute for execution - the real
// coverage is scripts/ + the live vault probe - but it is enough to stop a silent re-deletion.
describe("DPAPI unwrap script", () => {
  const src = readFileSync(join(process.cwd(), "src", "credential_store.ts"), "utf8");

  it("loads System.Security before using ProtectedData", () => {
    expect(src).toContain("Add-Type -AssemblyName System.Security");
    const addTypeAt = src.indexOf("Add-Type -AssemblyName System.Security");
    // Anchor on the actual CALL, not the bare type name - the explanatory comments above mention
    // the type by name, so indexOf on the type would match prose rather than the script.
    const callAt = src.indexOf("::Unprotect(");
    expect(addTypeAt).toBeGreaterThan(-1);
    expect(callAt).toBeGreaterThan(-1);
    expect(addTypeAt).toBeLessThan(callAt);
  });

  it("uses Windows PowerShell (5.1), where DPAPI ProtectedData is available", () => {
    expect(src).toContain("powershell.exe");
  });

  it("warns on stderr when the master key cannot be unwrapped", () => {
    // A configuration fault must not be indistinguishable from "this site has no saved login".
    expect(src).toContain("credential vault unavailable");
  });
});
