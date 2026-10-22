import { createHash } from "node:crypto";
import { lstat, opendir, realpath } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { z } from "zod";
import { sameRegularFileState } from "../filesystem/RegularFile.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import type { GhidraInstallationInspection } from "./GhidraInstallation.js";
import { parseGhidraJavaProperties } from "./GhidraJavaProperties.js";

import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import { OwnedDirectoryHandle } from "../filesystem/OwnedDirectoryHandle.js";
import {
  assertArtifactReadActive,
  artifactFileCancellationCause,
  artifactFilePrimaryFailure,
  bindArtifactFileCleanup,
  withArtifactRegularFile,
} from "../artifacts/ArtifactFileOperation.js";

/** One installed file's observed state, captured while its content is hashed. */
export interface GhidraInstalledExtensionFile {
  readonly size: number;
  /** Whole milliseconds, matching Java's `File.lastModified` comparisons. */
  readonly modifiedMs: number;
  /** At most the first eight content bytes. */
  readonly head: Buffer;
}

/**
 * A caller-installed Ghidra processor extension that a bounded profile requires.
 * The specification owns the directory name, required files and refusal code;
 * the fingerprinting rules below are shared by every processor profile.
 */
export interface GhidraProcessorExtensionSpec<Id extends string = string> {
  /** Installed directory name and required `extension.properties` name. */
  readonly id: Id;
  /** Component name used in refusals, such as "Allegrex". */
  readonly label: string;
  /** Platform profile name used in refusals, such as "PSP". */
  readonly profile: string;
  /** Public refusal code prefix. */
  readonly unavailableCode: string;
  readonly required: readonly string[];
  /** Describes the role of the required `lib/*.jar` in refusals. */
  readonly jarRole: string;
  /** Additional installed-state checks; returns a refusal reason or null. */
  readonly validate?: (
    files: ReadonlyMap<string, GhidraInstalledExtensionFile>,
  ) => string | null;
}

/** Installed processor code and data, distinct from REA's analysis-extension ABI. */
export const ghidraProcessorExtensionSchema = <Id extends string>(id: Id) =>
  z.strictObject({
    id: z.literal(id),
    root: z.string().refine(isAbsolute),
    ghidra_version: z.string().min(1),
    sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  });
export interface GhidraProcessorExtension<Id extends string = string> {
  readonly id: Id;
  readonly root: string;
  readonly ghidra_version: string;
  readonly sha256: string;
}

// Resource bounds for scanning a caller-installed extension, not target limits.
const MAX_ENTRIES = 1024;
const MAX_BYTES = 64 * 1024 * 1024;
const MAX_DEPTH = 16;
const HEAD_BYTES = 8;

/** Read-only fingerprint of all installed files; no home scanning or installation. */
export const inspectGhidraProcessorExtension = async <Id extends string>(
  spec: GhidraProcessorExtensionSpec<Id>,
  root: string,
  ghidraVersion: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<GhidraProcessorExtension<Id>> => {
  try {
    return await resources.run(() =>
      fingerprint(spec, root, ghidraVersion, resources, signal),
    );
  } catch (cause: unknown) {
    throw ghidraProcessorExtensionError(spec, cause);
  }
};

const fingerprint = async <Id extends string>(
  spec: GhidraProcessorExtensionSpec<Id>,
  root: string,
  ghidraVersion: string,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<GhidraProcessorExtension<Id>> => {
  const { label } = spec;
  assertArtifactReadActive(signal);
  if (!isAbsolute(root) || (await realpath(root)) !== root)
    throw new Error(
      `The installed ${label} directory must be a canonical non-symlink path.`,
    );
  const files: string[] = [];
  let entries = 1; // The root itself consumes one inventory entry.
  const visit = async (relative: string, depth: number): Promise<void> => {
    assertArtifactReadActive(signal);
    if (depth > MAX_DEPTH)
      throw new Error(
        `${label} extension directory nesting exceeds the inspection limit.`,
      );
    const path = join(root, relative);
    const metadata = await lstat(path);
    if (metadata.isDirectory()) {
      const children = await readChildren(
        spec,
        path,
        MAX_ENTRIES - entries,
        resources,
        signal,
      );
      entries += children.length;
      children.sort();
      for (const child of children)
        await visit(
          relative === "" ? child : `${relative}/${child}`,
          depth + 1,
        );
    } else if (metadata.isFile()) {
      files.push(relative);
    } else
      throw new Error(
        `${label} extension entries must be regular files or directories: ${relative}`,
      );
  };
  await visit("", 0);
  for (const required of spec.required)
    if (!files.includes(required))
      throw new Error(`Missing installed ${label} component: ${required}`);
  if (!files.some((path) => path.startsWith("lib/") && path.endsWith(".jar")))
    throw new Error(
      `The installed ${label} extension has no ${spec.jarRole} JAR.`,
    );
  const hash = createHash("sha256");
  const observed = new Map<string, GhidraInstalledExtensionFile>();
  let bytesRead = 0;
  let properties = Buffer.alloc(0);
  for (const relative of files) {
    assertArtifactReadActive(signal);
    const path = join(root, relative);
    await withArtifactRegularFile(path, resources, signal, async (handle) => {
      const before = await handle.stat();
      if (
        !Number.isSafeInteger(before.size) ||
        before.size > MAX_BYTES - bytesRead
      )
        throw new Error(
          `${label} extension bytes exceed the inspection limit.`,
        );
      if (relative === "extension.properties" && before.size > 65536)
        throw new Error(
          `${label} extension properties exceed the inspection limit.`,
        );
      hash.update(JSON.stringify([relative, before.size]));
      const buffer = Buffer.alloc(Math.min(65536, before.size + 1));
      let offset = 0;
      let head = Buffer.alloc(0);
      const chunks: Buffer[] = [];
      // Serial reads keep final close behind every native read. One extra byte
      // detects growth without a stream's read-ahead or unbounded allocation.
      while (offset <= before.size) {
        assertArtifactReadActive(signal);
        const { bytesRead } = await handle.read(
          buffer,
          0,
          Math.min(buffer.length, before.size - offset + 1),
          offset,
        );
        assertArtifactReadActive(signal);
        if (bytesRead === 0) break;
        offset += bytesRead;
        if (offset > before.size)
          throw new Error(
            `${label} component changed during inspection: ${relative}`,
          );
        const chunk = buffer.subarray(0, bytesRead);
        hash.update(chunk);
        if (head.length < HEAD_BYTES)
          head = Buffer.concat([
            head,
            Buffer.from(chunk.subarray(0, HEAD_BYTES - head.length)),
          ]);
        if (relative === "extension.properties")
          chunks.push(Buffer.from(chunk));
      }
      if (offset !== before.size)
        throw new Error(`Truncated ${label} component: ${relative}`);
      if (
        !sameRegularFileState(before, await handle.stat()) ||
        !sameRegularFileState(before, await lstat(path))
      )
        throw new Error(
          `${label} component changed during inspection: ${relative}`,
        );
      bytesRead += before.size;
      observed.set(relative, {
        size: before.size,
        modifiedMs: Math.floor(before.mtimeMs),
        head,
      });
      if (relative === "extension.properties")
        properties = Buffer.concat(chunks);
    });
  }
  // Ghidra's extension.properties version is the compatible Ghidra version,
  // not the extension release; content identity supplies the latter.
  const parsedProperties = parseGhidraJavaProperties(
    properties.toString("latin1"),
  );
  if (!parsedProperties.ok)
    throw new Error(
      `Invalid ${label} extension properties: ${parsedProperties.error}`,
    );
  const property = (name: string): string | undefined =>
    parsedProperties.value.get(name);
  if (property("name") !== spec.id || property("version") !== ghidraVersion)
    throw new Error(
      `${label} extension metadata does not match the selected Ghidra ${ghidraVersion}; install or rebuild a compatible extension.`,
    );
  const invalid = spec.validate?.(observed) ?? null;
  if (invalid !== null) throw new Error(invalid);
  assertArtifactReadActive(signal);
  return {
    id: spec.id,
    root,
    ghidra_version: ghidraVersion,
    sha256: hash.digest("hex"),
  };
};

/** The canonical installed location of a processor extension. */
export const ghidraProcessorExtensionRoot = async (
  spec: GhidraProcessorExtensionSpec,
  installDir: string,
): Promise<string> =>
  join(await realpath(installDir), "Ghidra", "Extensions", spec.id);

/** Resolve prerequisites before opening or admitting cached profile analysis. */
export const resolveGhidraProcessorExtension = async <Id extends string>(
  spec: GhidraProcessorExtensionSpec<Id>,
  installation: GhidraInstallationInspection,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<Result<GhidraProcessorExtension<Id>, AnalysisError>> => {
  try {
    assertArtifactReadActive(signal);
    if (
      installation.status !== "available" ||
      installation.platform !== "linux" ||
      installation.architecture !== "x64"
    )
      throw new Error(
        `The initial ${spec.profile} profile requires a supported Linux x64 Ghidra installation.`,
      );
    return ok(
      await inspectGhidraProcessorExtension(
        spec,
        await ghidraProcessorExtensionRoot(spec, installation.installDir),
        installation.providerVersion,
        resources,
        signal,
      ),
    );
  } catch (cause: unknown) {
    return err(ghidraProcessorExtensionError(spec, cause));
  }
};

/** Preserve the producer's primary failure and its live cleanup dependencies. */
const ghidraProcessorExtensionError = (
  spec: GhidraProcessorExtensionSpec,
  cause: unknown,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  const cleanup =
    cause instanceof ArtifactReaderFailure ? cause.cleanup : undefined;
  const primary = artifactFilePrimaryFailure(cause);
  const reason = `${spec.unavailableCode}: ${primary instanceof Error ? primary.message : String(primary)} Use a compatible caller-installed ${spec.id} under GHIDRA_INSTALL_DIR/Ghidra/Extensions; REA does not install it.`;
  const error =
    cause instanceof ArtifactReaderFailure && cause.reason === "cancelled"
      ? new AnalysisCancelledError("resolve_analysis_profile", {
          cause: artifactFileCancellationCause(cause),
          cleanup,
        })
      : new AnalysisCapabilityUnavailableError(
          "ghidra",
          "resolve_analysis_profile",
          reason,
          {
            cause,
            userMessage: reason,
            cleanup,
          },
        );
  bindArtifactFileCleanup(cause, error);
  return error;
};

/** Close before descending, retaining the exact directory owner on uncertainty. */
const readChildren = async (
  spec: GhidraProcessorExtensionSpec,
  path: string,
  remainingEntries: number,
  resources: ArtifactResourceScope,
  signal?: AbortSignal,
): Promise<string[]> => {
  assertArtifactReadActive(signal);
  const owner = new OwnedDirectoryHandle(await opendir(path));
  let outcome:
    | { readonly kind: "completed"; readonly names: string[] }
    | { readonly kind: "failed"; readonly cause: unknown };
  try {
    const names: string[] = [];
    for (;;) {
      assertArtifactReadActive(signal);
      const child = await owner.handle.read();
      assertArtifactReadActive(signal);
      if (child === null) break;
      if (names.length >= remainingEntries)
        throw new Error(
          `${spec.label} extension inventory exceeds the inspection limit.`,
        );
      names.push(child.name);
    }
    outcome = { kind: "completed", names };
  } catch (cause: unknown) {
    outcome = { kind: "failed", cause };
  }
  const lease = new AnalysisCleanupLease(() => owner.close(), [path]);
  const attempt = await resources.release({
    kind: "lease",
    resource: path,
    lease,
  });
  if (attempt.kind === "failed") {
    const primary =
      outcome.kind === "failed"
        ? outcome.cause
        : signal?.aborted
          ? new ArtifactReaderFailure(
              "cancelled",
              `${spec.profile} inspection cancelled during directory close`,
              { cause: signal.reason },
            )
          : attempt.cause;
    const error = ghidraProcessorExtensionError(
      spec,
      ArtifactReaderFailure.withCleanup(
        primary,
        ArtifactReaderFailure.cleanupObservation(attempt.cause, path),
      ),
    );
    lease.bindCleanupError(error);
    throw error;
  }
  if (outcome.kind === "failed") throw outcome.cause;
  assertArtifactReadActive(signal);
  return outcome.names;
};
