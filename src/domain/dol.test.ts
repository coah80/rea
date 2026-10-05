import { describe, expect, it } from "vitest";
import { parseDolHeader } from "./dol.js";
import { parseExecutableHeader } from "./binaryTarget.js";
import { elf } from "./binaryTarget.fixture.js";

const fixture = () => {
  const bytes = Buffer.alloc(0x120);
  bytes.writeUInt32BE(0x100, 0);
  bytes.writeUInt32BE(0x80003400, 0x48);
  bytes.writeUInt32BE(0x20, 0x90);
  bytes.writeUInt32BE(0x80004000, 0xd8);
  bytes.writeUInt32BE(0x100, 0xdc);
  bytes.writeUInt32BE(0x80003400, 0xe0);
  return bytes;
};

describe("Wii executable headers", () => {
  it("admits big-endian ELF32 PowerPC and rejects other PowerPC layouts", () => {
    expect(parseExecutableHeader(elf(1, 2, 20), "x64")).toMatchObject({
      ok: true,
      value: { architecture: "powerpc", format: "elf" },
    });
    for (const bytes of [elf(1, 1, 20), elf(2, 2, 20), elf(2, 2, 21)])
      expect(parseExecutableHeader(bytes, "x64").ok).toBe(false);
  });

  it("preserves DOL section mappings and accepts the Wii physical entry alias", () => {
    const bytes = fixture();
    bytes.writeUInt32BE(0x3400, 0xe0);
    expect(parseDolHeader(bytes, bytes.length)).toEqual({
      ok: true,
      value: {
        sections: [
          {
            name: ".text0",
            offset: 0x100,
            address: 0x80003400,
            size: 0x20,
            executable: true,
          },
        ],
        bssAddress: 0x80004000,
        bssSize: 0x100,
        entryPoint: 0x80003400,
      },
    });
  });

  it.each([
    [0, 0xf0],
    [0x90, 0x1000],
    [0x48, 0xfffffff0],
    [0xe0, 0x80003500],
    [0xe0, 0x80003401],
    [0xd8, 0xfffffff0],
  ])("rejects invalid DOL fields at %s", (offset, value) => {
    const bytes = fixture();
    bytes.writeUInt32BE(value, offset);
    expect(parseDolHeader(bytes, bytes.length).ok).toBe(false);
  });

  it("rejects empty, truncated, and overlapping DOL sections", () => {
    expect(parseDolHeader(Buffer.alloc(0x100), 0x100).ok).toBe(false);
    expect(parseDolHeader(fixture().subarray(0, 0xff), 0x120).ok).toBe(false);
    const bytes = fixture();
    bytes.writeUInt32BE(0x100, 4);
    bytes.writeUInt32BE(0x80003410, 0x4c);
    bytes.writeUInt32BE(0x10, 0x94);
    expect(parseDolHeader(bytes, bytes.length).ok).toBe(false);
  });
});
