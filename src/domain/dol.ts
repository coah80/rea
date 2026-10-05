import { err, ok, type Result } from "./result.js";

export interface DolSection {
  readonly name: string;
  readonly offset: number;
  readonly address: number;
  readonly size: number;
  readonly executable: boolean;
}

export interface DolHeader {
  readonly sections: readonly DolSection[];
  readonly bssAddress: number;
  readonly bssSize: number;
  readonly entryPoint: number;
}

export const parseDolHeader = (
  bytes: Buffer,
  fileSize: number,
): Result<DolHeader, string> => {
  if (bytes.length < 0x100 || fileSize < 0x100)
    return err("truncated DOL header");
  const sections: DolSection[] = [];
  for (let i = 0; i < 18; i++) {
    const offset = bytes.readUInt32BE(i * 4);
    const address = bytes.readUInt32BE(0x48 + i * 4);
    const size = bytes.readUInt32BE(0x90 + i * 4);
    if (size === 0) continue;
    if (
      offset < 0x100 ||
      offset + size > fileSize ||
      address + size > 0x100000000
    )
      return err("DOL section extends outside file or address space");
    if (
      sections.some(
        (s) =>
          (offset < s.offset + s.size && s.offset < offset + size) ||
          (address < s.address + s.size && s.address < address + size),
      )
    )
      return err("overlapping DOL sections");
    sections.push({
      name: i < 7 ? `.text${i}` : `.data${i - 7}`,
      offset,
      address,
      size,
      executable: i < 7,
    });
  }
  const bssAddress = bytes.readUInt32BE(0xd8);
  const bssSize = bytes.readUInt32BE(0xdc);
  if (bssAddress + bssSize > 0x100000000)
    return err("DOL BSS extends outside address space");
  let entryPoint = bytes.readUInt32BE(0xe0);
  const containsEntry = (address: number) =>
    sections.some(
      (s) =>
        s.executable && address >= s.address && address < s.address + s.size,
    );
  if (!containsEntry(entryPoint) && entryPoint < 0x01800000)
    entryPoint += 0x80000000;
  if (entryPoint % 4 !== 0 || !containsEntry(entryPoint))
    return err("DOL entry point is outside a text section");
  return ok({ sections, bssAddress, bssSize, entryPoint });
};
