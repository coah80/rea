import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import type {
  AnalysisProfileResolution,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { createAnalysisProfile } from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTarget.js";
import {
  AnalysisCancelledError,
  ProviderAdapterError,
  type AnalysisError,
} from "../domain/errors.js";
import { err, ok, type Result } from "../domain/result.js";
import type { GhidraInstallationInspection } from "./GhidraInstallation.js";

/** Resolve version-bound, deterministic semantics before Ghidra imports a target. */
export const resolveGhidraAnalysisProfile = (
  target: BinaryTarget,
  identity: ProviderIdentity,
  installation: GhidraInstallationInspection,
  signal?: AbortSignal,
): Promise<Result<AnalysisProfileResolution, AnalysisError>> => {
  if (signal?.aborted === true)
    return Promise.resolve(err(new AnalysisCancelledError("open_binary")));
  if (target.kind !== "executable")
    return Promise.resolve(ok({ profile: null, compatibility: {} }));
  if (installation.status === "unavailable")
    return Promise.resolve(
      err(new ProviderAdapterError(identity.id, "resolve_analysis_profile")),
    );
  const provider = { ...identity, version: installation.providerVersion };
  let powerpcLanguageDigest: string | undefined;
  if (target.architecture === "powerpc") {
    try {
      const hash = createHash("sha256");
      for (const suffix of ["sla", "cspec", "pspec", "ldefs"]) {
        hash.update(suffix);
        hash.update(
          readFileSync(
            join(
              installation.installDir,
              "Ghidra/Extensions/ReaWiiPowerPC/data/languages",
              `ppc_gekko_broadway.${suffix}`,
            ),
          ),
        );
      }
      powerpcLanguageDigest = hash.digest("hex");
    } catch (cause: unknown) {
      return Promise.resolve(
        err(
          new ProviderAdapterError(identity.id, "resolve_analysis_profile", {
            cause,
          }),
        ),
      );
    }
  }
  return Promise.resolve(
    ok({
      profile: createAnalysisProfile(provider, {
        target_kind: target.kind,
        target_format: target.format,
        architecture: target.architecture ?? null,
        available_architectures: [
          ...(target.availableArchitectures ?? []),
        ].sort(),
        import_mode: "ephemeral-read-only",
        loader: target.format === "dol" ? "rea-dol-v1" : "auto-from-header",
        language_id:
          target.architecture === "powerpc"
            ? "PowerPC:BE:32:Gekko_Broadway"
            : "auto-from-header",
        compiler_spec_id:
          target.architecture === "powerpc" ? "default" : "auto-default",
        analyzer_preset: "ghidra-default",
        ...(powerpcLanguageDigest === undefined
          ? {}
          : {
              powerpc_language_sha256: powerpcLanguageDigest,
            }),
      }),
      compatibility: {
        languageId:
          target.architecture === "powerpc"
            ? "PowerPC:BE:32:Gekko_Broadway"
            : "auto",
        compilerSpecId: target.architecture === "powerpc" ? "default" : "auto",
      },
    }),
  );
};
