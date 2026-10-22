import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { Result } from "../domain/result.js";
import type { GhidraInstallationInspection } from "./GhidraInstallation.js";
import {
  ghidraProcessorExtensionSchema,
  inspectGhidraProcessorExtension,
  resolveGhidraProcessorExtension,
  type GhidraProcessorExtension,
  type GhidraProcessorExtensionSpec,
} from "./GhidraProcessorExtension.js";

/** The caller-installed ghidra-allegrex extension required by the PSP profile. */
export const GHIDRA_PSP_EXTENSION_SPEC: GhidraProcessorExtensionSpec<"ghidra-allegrex"> =
  {
    id: "ghidra-allegrex",
    label: "Allegrex",
    profile: "PSP",
    unavailableCode: "PSP_EXTENSION_UNAVAILABLE",
    jarRole: "loader",
    required: [
      "Module.manifest",
      "extension.properties",
      "data/languages/allegrex.ldefs",
      "data/languages/allegrex.sla",
      "data/languages/allegrex.pspec",
      "data/languages/allegrex.cspec",
    ],
  };

export const ghidraPspExtensionSchema =
  ghidraProcessorExtensionSchema("ghidra-allegrex");
export type GhidraPspExtension = GhidraProcessorExtension<"ghidra-allegrex">;

/** Read-only fingerprint of all installed files; no home scanning or installation. */
export const inspectGhidraPspExtension = (
  root: string,
  ghidraVersion: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<GhidraPspExtension> =>
  inspectGhidraProcessorExtension(
    GHIDRA_PSP_EXTENSION_SPEC,
    root,
    ghidraVersion,
    resources,
    signal,
  );

/** Resolve prerequisites before opening or admitting cached PSP analysis. */
export const resolveGhidraPspExtension = (
  installation: GhidraInstallationInspection,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<Result<GhidraPspExtension, AnalysisError>> =>
  resolveGhidraProcessorExtension(
    GHIDRA_PSP_EXTENSION_SPEC,
    installation,
    resources,
    signal,
  );
