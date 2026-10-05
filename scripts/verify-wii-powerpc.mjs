import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { GhidraClient } from "../dist/ghidra/GhidraClient.js";
import { GhidraHeadlessLauncher } from "../dist/ghidra/GhidraLauncher.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { resolveGhidraAnalysisProfile } from "../dist/ghidra/GhidraAnalysisProfile.js";
import { GHIDRA_PROVIDER_IDENTITY } from "../dist/ghidra/GhidraProvider.js";

const [input, procedure, output = "build/wii-verification"] =
  process.argv.slice(2);
assert(
  input && procedure,
  "Usage: node scripts/verify-wii-powerpc.mjs INPUT PROCEDURE [OUTPUT_DIRECTORY]",
);
const installation = inspectGhidraInstallation({
  installDir: process.env.GHIDRA_INSTALL_DIR,
  javaHome: process.env.JAVA_HOME,
});
assert.equal(installation.status, "available", JSON.stringify(installation));
const parsed = await parseBinaryTarget(input);
assert(parsed.ok, JSON.stringify(parsed));
const target = parsed.value;
assert.equal(target.architecture, "powerpc");
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
    targetFormat: target.format,
    powerpc: target.architecture === "powerpc",
  }),
  targetPath: target.path,
  targetSha256: target.sha256,
  providerVersion: installation.providerVersion,
  profileDigest: resolved.value.profile.digest,
});
const results = {};
try {
  const started = await client.start();
  assert(started.ok, JSON.stringify(started));
  assert.equal(
    started.value.target.language_id,
    "PowerPC:BE:32:Gekko_Broadway",
  );
  assert.equal(started.value.target.sha256, target.sha256);
  assert.equal(started.value.analysis_complete, true);
  assert.equal(started.value.analysis_timed_out, false);
  results.session = started.value;
  for (const operation of [
    "list_segments",
    "list_procedures",
    "procedure_assembly",
    "procedure_pseudo_code",
  ]) {
    const result = await client.callTool(
      operation,
      operation.startsWith("procedure_")
        ? { document: null, procedure }
        : { document: null },
    );
    assert(result.ok, JSON.stringify(result));
    results[operation] = result.value;
  }
  assert.equal(typeof results.procedure_assembly, "string");
  assert(results.procedure_assembly.length > 0);
  if (procedure === "PSMTXIdentity")
    assert.match(results.procedure_assembly, /psq_st/);
  assert.equal(typeof results.procedure_pseudo_code, "string");
  assert(results.procedure_pseudo_code.length > 0);
  await mkdir(output, { recursive: true });
  await writeFile(
    resolve(output, `${target.format}.json`),
    JSON.stringify(
      { target, profile: resolved.value.profile, ...results },
      null,
      2,
    ),
  );
  await writeFile(
    resolve(output, `${target.format}.c`),
    results.procedure_pseudo_code,
  );
  console.log(
    JSON.stringify({
      status: "PASS",
      format: target.format,
      architecture: target.architecture,
      sha256: target.sha256,
      procedure,
      output: resolve(output),
    }),
  );
} finally {
  await client.close();
}
