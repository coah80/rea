import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";

const [ghidra, source] = process.argv.slice(2);
assert(
  ghidra && source,
  "Usage: node scripts/install-wii-language.mjs GHIDRA_ROOT GAMECUBE_LOADER_SOURCE",
);
const expected = "921504c9ddba6e8d9b3655b665a60f1a33306220";
const observed = execFileSync(
  "git",
  ["-C", resolve(source), "rev-parse", "HEAD"],
  { encoding: "utf8" },
).trim();
assert.equal(observed, expected, "Use the documented language source revision");
assert.equal(
  execFileSync(
    "git",
    [
      "-C",
      resolve(source),
      "status",
      "--porcelain",
      "--",
      "data/languages",
      "Module.manifest",
      "LICENSE",
    ],
    { encoding: "utf8" },
  ).trim(),
  "",
  "Language source must be unchanged",
);
const properties = await readFile(
  join(ghidra, "Ghidra/application.properties"),
  "utf8",
);
assert(
  /^application.version=12\.1\.4\s*$/m.test(properties),
  "Ghidra 12.1.4 is required",
);
const modulePath = join(resolve(ghidra), "Ghidra/Extensions/ReaWiiPowerPC");
await mkdir(modulePath);
await cp(join(source, "data/languages"), join(modulePath, "data/languages"), {
  recursive: true,
});
for (const name of ["Module.manifest", "LICENSE"])
  await cp(join(source, name), join(modulePath, name));
await writeFile(
  join(modulePath, "extension.properties"),
  "name=ReaWiiPowerPC\ndescription=Gekko and Broadway language\nauthor=Cuyler and contributors\ncreatedOn=2026-10-05\nversion=12.1.4\n",
);
execFileSync(
  join(resolve(ghidra), "support/sleigh"),
  [join(modulePath, "data/languages/ppc_gekko_broadway.slaspec")],
  { stdio: "inherit" },
);
console.log(`Installed ${modulePath}`);
