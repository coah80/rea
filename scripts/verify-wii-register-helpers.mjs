import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { resolveGhidraAnalysisProfile } from "../dist/ghidra/GhidraAnalysisProfile.js";
import { GhidraClient } from "../dist/ghidra/GhidraClient.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { GhidraHeadlessLauncher } from "../dist/ghidra/GhidraLauncher.js";
import { GHIDRA_PROVIDER_IDENTITY } from "../dist/ghidra/GhidraProvider.js";

const output =
  process.argv[2] ?? (await mkdtemp(join(tmpdir(), "rea-helpers-")));
await mkdir(output, { recursive: true });
const input = join(output, "helpers.elf");
await writeFile(input, fixture());
const installation = inspectGhidraInstallation({
  installDir: process.env.GHIDRA_INSTALL_DIR,
  javaHome: process.env.JAVA_HOME,
});
assert.equal(installation.status, "available", JSON.stringify(installation));
const parsed = await parseBinaryTarget(input);
assert(parsed.ok, JSON.stringify(parsed));
const target = parsed.value;
const resolved = await resolveGhidraAnalysisProfile(
  target,
  GHIDRA_PROVIDER_IDENTITY,
  installation,
);
assert(resolved.ok && resolved.value.profile, JSON.stringify(resolved));
const client = new GhidraClient({
  launcher: new GhidraHeadlessLauncher({
    analyzeHeadlessPath: installation.analyzeHeadlessPath,
    javaHome: process.env.JAVA_HOME,
    bridgeScriptPath: fileURLToPath(
      new URL("../bridge/ghidra/ReaGhidraBridge.java", import.meta.url),
    ),
    targetFormat: "elf",
    powerpc: true,
  }),
  targetPath: target.path,
  targetSha256: target.sha256,
  providerVersion: installation.providerVersion,
  profileDigest: resolved.value.profile.digest,
});
try {
  const started = await client.start();
  assert(started.ok, JSON.stringify(started));
  for (const procedure of ["add_seven", "double_value", "spoof_caller"]) {
    const result = await client.callTool("procedure_pseudo_code", {
      document: null,
      procedure,
    });
    assert(
      result.ok && typeof result.value === "string",
      JSON.stringify(result),
    );
    const code = result.value;
    await writeFile(join(output, `${procedure}.c`), code);
    if (procedure === "add_seven") {
      assert.match(code, /int add_seven\(int (\w+)\)/);
      assert.match(code, /return \w+ \+ 7;/);
      assert.doesNotMatch(code, /_(?:save|rest)gpr_29\(/);
    } else if (procedure === "double_value") {
      assert.match(code, /double double_value\(double (\w+)\)/);
      assert.match(code, /return (\w+) \+ \1;/);
      assert.doesNotMatch(code, /_(?:save|rest)fpr_29\(/);
    } else {
      assert.match(code, /_savegpr_28\(/);
      assert.doesNotMatch(code, /Inlined function: _savegpr_28/);
    }
  }
  console.log(
    JSON.stringify({ status: "PASS", output, sha256: target.sha256 }),
  );
} finally {
  await client.close();
}

function fixture() {
  const base = 0x80004000;
  const words = [];
  const functions = [];
  function caller(name, floatingPoint) {
    functions.push([name, words.length * 4, 52]);
    words.push(
      0x9421ffe0,
      0x7c0802a6,
      0x90010024,
      0x39610020,
      0x48000031,
      floatingPoint ? 0xffa00890 : 0x7c7d1b78,
      floatingPoint ? 0xfc3de82a : 0x387d0007,
      0x39610020,
      0x48000031,
      0x80010024,
      0x7c0803a6,
      0x38210020,
      0x4e800020,
      0,
      0,
      0,
    );
    for (const saving of [true, false]) {
      functions.push([
        `_${saving ? "save" : "rest"}${floatingPoint ? "fpr" : "gpr"}_29`,
        words.length * 4,
        16,
      ]);
      for (let register = 29; register <= 31; register++) {
        const opcode = floatingPoint ? (saving ? 54 : 50) : saving ? 36 : 32;
        words.push(
          ((opcode << 26) |
            (register << 21) |
            (11 << 16) |
            (((floatingPoint ? 8 : 4) * (register - 32)) & 0xffff)) >>>
            0,
        );
      }
      words.push(0x4e800020);
    }
  }
  caller("add_seven", false);
  caller("double_value", true);
  functions.push(["spoof_caller", words.length * 4, 32]);
  words.push(
    0x9421ffe0,
    0x7c0802a6,
    0x90010024,
    0x48000015,
    0x80010024,
    0x7c0803a6,
    0x38210020,
    0x4e800020,
  );
  functions.push(["_savegpr_28", words.length * 4, 8]);
  words.push(0x38630001, 0x4e800020);
  functions.push(["_restgpr_28", words.length * 4, 4]);
  words.push(0x838bfff0);
  const text = Buffer.alloc(words.length * 4);
  words.forEach((word, index) => text.writeUInt32BE(word, index * 4));
  return executableFixture(text, functions, base);
}

function executableFixture(text, functions, base) {
  const strings = Buffer.from(
    `\0${functions.map(([name]) => name).join("\0")}\0`,
  );
  const names = Buffer.from("\0.text\0.symtab\0.strtab\0.shstrtab\0");
  const symbols = Buffer.alloc((functions.length + 1) * 16);
  functions.forEach(([name, offset, size], index) => {
    const at = (index + 1) * 16;
    symbols.writeUInt32BE(strings.indexOf(name), at);
    symbols.writeUInt32BE(base + offset, at + 4);
    symbols.writeUInt32BE(size, at + 8);
    symbols[at + 12] = 0x12;
    symbols.writeUInt16BE(1, at + 14);
  });
  const textOffset = 256;
  const symbolOffset = textOffset + text.length;
  const stringOffset = symbolOffset + symbols.length;
  const nameOffset = stringOffset + strings.length;
  const sectionOffset = (nameOffset + names.length + 3) & ~3;
  const elf = Buffer.alloc(sectionOffset + 5 * 40);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 1, 2, 1]).copy(elf);
  elf.writeUInt16BE(2, 16);
  elf.writeUInt16BE(20, 18);
  [1, base, 52, sectionOffset, 0].forEach((value, index) =>
    elf.writeUInt32BE(value, 20 + index * 4),
  );
  [52, 32, 1, 40, 5, 4].forEach((value, index) =>
    elf.writeUInt16BE(value, 40 + index * 2),
  );
  [1, textOffset, base, base, text.length, text.length, 5, 256].forEach(
    (value, index) => elf.writeUInt32BE(value, 52 + index * 4),
  );
  text.copy(elf, textOffset);
  symbols.copy(elf, symbolOffset);
  strings.copy(elf, stringOffset);
  names.copy(elf, nameOffset);
  [
    [".text", 1, 6, base, textOffset, text.length, 0, 0, 4, 0],
    [".symtab", 2, 0, 0, symbolOffset, symbols.length, 3, 1, 4, 16],
    [".strtab", 3, 0, 0, stringOffset, strings.length, 0, 0, 1, 0],
    [".shstrtab", 3, 0, 0, nameOffset, names.length, 0, 0, 1, 0],
  ].forEach(([name, ...values], index) => {
    [names.indexOf(name), ...values].forEach((value, field) =>
      elf.writeUInt32BE(value, sectionOffset + (index + 1) * 40 + field * 4),
    );
  });
  return elf;
}
