import { describe, it, expect } from "vitest";
import { canonicalJson, sha256Hex, computeScopeChecksum, computeToolPermissionsHash, computePlatformPermissionsHash, matchGlob } from "../crypto.js";

describe("canonicalJson", () => {
  it("sorts keys alphabetically", () => {
    const result = canonicalJson({ z: 1, a: 2, m: 3 });
    expect(result).toBe('{"a":2,"m":3,"z":1}');
  });

  it("sorts nested objects", () => {
    const result = canonicalJson({ b: { d: 1, c: 2 }, a: 0 });
    expect(result).toBe('{"a":0,"b":{"c":2,"d":1}}');
  });

  it("preserves array order", () => {
    const result = canonicalJson({ items: [3, 1, 2] });
    expect(result).toBe('{"items":[3,1,2]}');
  });

  it("handles null and undefined", () => {
    expect(canonicalJson(null)).toBe("null");
    expect(canonicalJson(undefined)).toBe(undefined);
  });
});

describe("sha256Hex", () => {
  it("produces correct hex digest", async () => {
    const hash = await sha256Hex("hello");
    expect(hash).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });

  it("returns consistent results", async () => {
    const a = await sha256Hex("test-input");
    const b = await sha256Hex("test-input");
    expect(a).toBe(b);
  });
});

describe("computeScopeChecksum", () => {
  it("produces sha256-prefixed checksum", async () => {
    const checksum = await computeScopeChecksum({
      governance_profile: "standard",
      phase: "build",
      allowed_paths: ["src/"],
      denied_paths: [".env"],
      active_modules: ["core"],
      tool_permissions_hash: "sha256:abc",
      platform_permissions_hash: "sha256:def",
    });
    expect(checksum).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("is deterministic", async () => {
    const input = {
      governance_profile: "standard",
      phase: "build",
      allowed_paths: [],
      denied_paths: [],
      active_modules: [],
      tool_permissions_hash: "sha256:000",
      platform_permissions_hash: "sha256:111",
    };
    const a = await computeScopeChecksum(input);
    const b = await computeScopeChecksum(input);
    expect(a).toBe(b);
  });
});

describe("computeToolPermissionsHash", () => {
  it("produces sha256-prefixed hash", async () => {
    const hash = await computeToolPermissionsHash({ "foundry.file.create": { allowed: true } });
    expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });
});

describe("computePlatformPermissionsHash", () => {
  it("handles undefined input", async () => {
    const hash = await computePlatformPermissionsHash(undefined);
    expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("handles empty object", async () => {
    const a = await computePlatformPermissionsHash(undefined);
    const b = await computePlatformPermissionsHash({});
    expect(a).toBe(b);
  });
});

describe("matchGlob", () => {
  it("matches exact paths", () => {
    expect(matchGlob("src/index.ts", "src/index.ts")).toBe(true);
  });

  it("matches single-star wildcard", () => {
    expect(matchGlob("src/*.ts", "src/index.ts")).toBe(true);
    expect(matchGlob("src/*.ts", "src/deep/index.ts")).toBe(false);
  });

  it("matches globstar", () => {
    expect(matchGlob("src/**/*.ts", "src/deep/index.ts")).toBe(true);
    expect(matchGlob("src/**", "src/a/b/c.js")).toBe(true);
  });

  it("matches directory prefix", () => {
    expect(matchGlob("src/", "src/anything")).toBe(true);
  });

  it("rejects non-matching paths", () => {
    expect(matchGlob("lib/*.ts", "src/index.ts")).toBe(false);
  });
});
