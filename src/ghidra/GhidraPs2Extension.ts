import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { Result } from "../domain/result.js";
import type { GhidraInstallationInspection } from "./GhidraInstallation.js";
import {
  ghidraProcessorExtensionSchema,
  inspectGhidraProcessorExtension,
  resolveGhidraProcessorExtension,
  type GhidraInstalledExtensionFile,
  type GhidraProcessorExtension,
  type GhidraProcessorExtensionSpec,
} from "./GhidraProcessorExtension.js";

const LANGUAGES = "data/languages/";
const COMPILED = `${LANGUAGES}r5900.sla`;
/** Ghidra 12.1 `SlaFormat`: "sla" followed by format version 4. */
const SLA_HEADER = Buffer.from([0x73, 0x6c, 0x61, 0x04]);

/**
 * Ghidra recompiles a missing, wrong-format or stale `.sla` inside the
 * installation when the file is writable. Release builds of this extension ship
 * only SLEIGH sources, so the caller must precompile it; REA refuses an
 * installation that Ghidra would modify during analysis.
 */
const validateCompiledLanguage = (
  files: ReadonlyMap<string, GhidraInstalledExtensionFile>,
): string | null => {
  const compiled = files.get(COMPILED);
  if (compiled === undefined) return null; // Reported as a missing component.
  if (!compiled.head.subarray(0, SLA_HEADER.length).equals(SLA_HEADER))
    return "r5900.sla is not a SLEIGH format-4 file for the selected Ghidra; precompile it with that installation's support/sleigh.";
  for (const [path, file] of files)
    if (
      path.startsWith(LANGUAGES) &&
      !path.slice(LANGUAGES.length).includes("/") &&
      (path.endsWith(".slaspec") || path.endsWith(".sinc")) &&
      file.modifiedMs > compiled.modifiedMs
    )
      return `r5900.sla is older than ${path.slice(LANGUAGES.length)}; Ghidra would recompile it inside the installation. Precompile it with that installation's support/sleigh.`;
  return null;
};

/** The caller-installed Emotion Engine: Reloaded extension required by the PS2 profile. */
export const GHIDRA_PS2_EXTENSION_SPEC: GhidraProcessorExtensionSpec<"ghidra-emotionengine-reloaded"> =
  {
    id: "ghidra-emotionengine-reloaded",
    label: "Emotion Engine",
    profile: "PS2",
    unavailableCode: "PS2_EXTENSION_UNAVAILABLE",
    jarRole: "ELF extension",
    required: [
      "Module.manifest",
      "extension.properties",
      `${LANGUAGES}emotionengine.ldefs`,
      `${LANGUAGES}r5900.slaspec`,
      COMPILED,
      `${LANGUAGES}r5900.pspec`,
      `${LANGUAGES}r5900.cspec`,
    ],
    validate: validateCompiledLanguage,
  };

export const ghidraPs2ExtensionSchema = ghidraProcessorExtensionSchema(
  "ghidra-emotionengine-reloaded",
);
export type GhidraPs2Extension =
  GhidraProcessorExtension<"ghidra-emotionengine-reloaded">;

/** Read-only fingerprint of all installed files; no home scanning or installation. */
export const inspectGhidraPs2Extension = (
  root: string,
  ghidraVersion: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<GhidraPs2Extension> =>
  inspectGhidraProcessorExtension(
    GHIDRA_PS2_EXTENSION_SPEC,
    root,
    ghidraVersion,
    resources,
    signal,
  );

/** Resolve prerequisites before opening or admitting cached PS2 analysis. */
export const resolveGhidraPs2Extension = (
  installation: GhidraInstallationInspection,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<Result<GhidraPs2Extension, AnalysisError>> =>
  resolveGhidraProcessorExtension(
    GHIDRA_PS2_EXTENSION_SPEC,
    installation,
    resources,
    signal,
  );
