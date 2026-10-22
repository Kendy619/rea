#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import {
  inspectMipsReadelf,
  expectedMipsElfProfile,
  inspectLegacyMipsReadelf,
  assertMipsLoadedImage,
  assertMipsProbe,
  assertMipsGlobal,
  assertMipsSoftFloatStorage,
} from "../tests/conformance/ghidra/mips-checks.mjs";
import { parseEvidence } from "../dist/domain/evidence.js";
import { parseAnalysisSnapshot } from "../dist/domain/analysisSnapshot.js";
import { functionDossierSchema } from "../dist/domain/hopperValues.js";
import { inspectVerifierGhidraInstallation } from "./lib/ghidra-installation-inspection.mjs";
import { buildMipsFixture } from "../tests/conformance/ghidra/mips-fixture.mjs";
import {
  buildPspFixture,
  assertPspLoadedImage,
  assertPspProbe,
} from "../tests/conformance/ghidra/psp-fixture.mjs";
import {
  buildPs2Fixture,
  assertPs2LoadedImage,
  assertPs2Probe,
  PS2_VARIANTS,
} from "../tests/conformance/ghidra/ps2-fixture.mjs";
import {
  requireMcpToolError,
  requireMcpOperationResult,
} from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Optional cross-target lane. No tool acquisition and no target execution.
const mode = process.argv[2];
const psp = mode === "--psp" || mode === "--psp-missing-extension";
const ps2 = mode === "--ps2" || mode === "--ps2-missing-extension";
const missingExtension =
  mode === "--psp-missing-extension" || mode === "--ps2-missing-extension";
if (process.argv.length > 3 || (mode !== undefined && !psp && !ps2))
  throw new Error(
    "Usage: node scripts/verify-real-ghidra-mips.mjs [--psp|--psp-missing-extension|--ps2|--ps2-missing-extension]",
  );
const prefix = psp ? "rea_psp" : ps2 ? "rea_ps2" : "rea_mips";
const extensionRefusal = ps2
  ? /PS2_EXTENSION_UNAVAILABLE/u
  : /PSP_EXTENSION_UNAVAILABLE/u;
const markerText = `${prefix.replace("_", "-")}-source-owned-fixture\0`;
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "MIPS verification requires a supported Linux/macOS Ghidra host",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error("Missing prerequisite: caller-supplied GHIDRA_INSTALL_DIR");
const installation = await inspectVerifierGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `Ghidra prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const execute = promisify(execFile);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-mips-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  GHIDRA_INSTALL_DIR: installation.installDir,
  JAVA_HOME: installation.javaHome,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
};
for (const setting of ["GHIDRA_HEADLESS_MAXMEM", "GHIDRA_MAXMEM"]) {
  if (process.env[setting] !== undefined) env[setting] = process.env[setting];
}

/**
 * Typed float signatures must use soft-float o32 storage, and callers must see
 * the source constants through it rather than FPU inputs.
 */
async function verifySoftFloat(call, symbols, byteOrder) {
  const boundaries = {};
  for (const name of [
    "rea_mips_soft_pick",
    "rea_mips_soft_wide",
    "rea_mips_soft_mixed",
    "rea_mips_soft_struct",
  ]) {
    const api = await call("inspect_native_api", { procedure: symbols[name] });
    boundaries[name] = api.boundary;
  }
  assertMipsSoftFloatStorage(boundaries, byteOrder);
  const caller = functionDossierSchema.parse(
    await call("analyze_function", {
      procedure: symbols.rea_mips_soft_caller,
    }),
  );
  // Includes the struct call and the indirect call through a typed pointer.
  assert.doesNotMatch(caller.pseudocode, /\bin_f\d+\b/u);
  for (const literal of [
    "1.5",
    "2.5",
    "3.25",
    "4.75",
    "5.5",
    "6.125",
    "7.5",
    "8.5",
    "9.5",
  ])
    assert.ok(
      caller.pseudocode.includes(literal),
      `Soft-float caller lost argument ${literal}`,
    );
  return { storage: boundaries };
}
function assertIncompleteMipsInspection(error) {
  assert.equal(error.code, "capability_unavailable");
  assert.equal(error.details.selection_reason, "target_unsupported");
  const rejection = error.details.rejections.find(
    (candidate) => candidate.provider_id === "ghidra",
  );
  assert.equal(rejection?.code, "architecture_unsupported");
  assert.match(rejection.reason, /ABI declaration inspection is incomplete/u);
  assert.match(rejection.reason, /section header table/u);
}

const reports = [];
let primaryFailure;
try {
  if (!psp && !ps2) {
    // Recordless legacy admission: ABI field 0, no ABI flags record, pinned
    // 32-bit language. Independent GNU readelf checks the header interpretation.
    for (const byteOrder of ["little", "big"]) {
      const fixture = await buildMipsFixture(workspace, byteOrder, "hard", {
        legacy: true,
      });
      const legacy = await inspectLegacyMipsReadelf(fixture.path, byteOrder);
      const resolved = await parseBinaryTarget(fixture.path);
      if (!resolved.ok) throw resolved.error;
      assert.equal(resolved.value.mips.flags, 0x50000001);
      assert.equal(resolved.value.mips.abiFlags, null);
      assert.deepEqual(
        resolved.value.mips.limitations ?? [],
        legacy.limitations,
        "REA legacy ABI-record absence interpretation disagrees with GNU readelf",
      );
      assert.equal(resolved.value.sha256, fixture.sha256);
      const snapshotPath = join(workspace, `${byteOrder}-legacy.snapshot.json`);
      const transport = new StdioClientTransport({
        command: process.execPath,
        args: [entrypoint, "mcp"],
        env,
        stderr: "pipe",
      });
      const client = new Client({
        name: "rea-real-mips-legacy-proof",
        version: "1",
      });
      let stderr = "";
      transport.stderr?.on("data", (chunk) => {
        stderr = (stderr + chunk.toString()).slice(-65536);
      });
      const call = async (name, args = {}) => {
        const reply = await client.callTool(
          { name, arguments: args },
          undefined,
          { timeout: 180000 },
        );
        return requireMcpOperationResult(reply, name);
      };
      try {
        await client.connect(transport);
        const selected = await call("open_binary", {
          path: fixture.path,
          provider_id: "ghidra",
        });
        assert.equal(selected.architecture, "mips");
        assert.equal(selected.sha256, fixture.sha256);
        const image = await call("inspect_native_load_image");
        assertMipsLoadedImage(image.observations, byteOrder, fixture.sha256);
        // The pinned import language is the checked one, not an auto-selection.
        assert.equal(
          image.observations.language_id,
          `MIPS:${byteOrder === "little" ? "LE" : "BE"}:32:default`,
        );
        const procedures = await call("list_procedures");
        const entry = procedures.find((p) => p.value === "rea_mips_entry");
        assert.ok(entry, "Entry function missing from legacy inventory");
        assert.equal(
          BigInt(entry.address),
          BigInt(legacy.symbols.rea_mips_entry),
        );
        const probe = await call("inspect_native_instruction", {
          address: legacy.symbols.rea_mips_probe,
        });
        const probeBranch = await call("inspect_native_instruction", {
          address: `0x${(BigInt(legacy.symbols.rea_mips_probe) + 4n).toString(16)}`,
        });
        assertMipsProbe(
          probe,
          probeBranch,
          byteOrder,
          legacy.symbols.rea_mips_probe,
        );
        const dossier = functionDossierSchema.parse(
          await call("analyze_function", { procedure: entry.address }),
        );
        assert.ok(dossier.pseudocode.trim().length > 0);
        const saved = await call("close_binary", {
          snapshot_path: snapshotPath,
        });
        assert.ok(saved.evidence_records > 0);
        const snapshot = parseAnalysisSnapshot(
          JSON.parse(await readFile(snapshotPath, "utf8")),
        );
        assert.equal(snapshot.target.architecture, "mips");
        const parameters = snapshot.binding.analysis_profile.parameters;
        assert.equal(
          parameters.language_id,
          `MIPS:${byteOrder === "little" ? "LE" : "BE"}:32:default`,
        );
        assert.equal(parameters.language_selection, "provider-pinned-v1");
        assert.equal(
          parameters.mips_support_lane,
          "elf32-exec-arch32-legacy-pinned-v1",
        );
        assert.equal(parameters.mips_abi_basis, "inferred-o32-assumption-v1");
        assert.ok(
          snapshot.evidence_bundle.records.some((record) =>
            parseEvidence(record).limitations.some((item) =>
              item.includes("analysis assumption"),
            ),
          ),
          "Legacy o32 assumption limitation missing from retained Evidence",
        );
        assert.ok(
          snapshot.evidence_bundle.records.some((record) =>
            parseEvidence(record).limitations.some((item) =>
              item.includes("Floating-point ABI semantics are unverified"),
            ),
          ),
          "Legacy floating-point uncertainty missing from retained Evidence",
        );
        await call("open_binary", {
          path: fixture.path,
          provider_id: "ghidra",
          snapshot_path: snapshotPath,
        });
        assert.deepEqual(await call("list_procedures"), procedures);
        await call("close_binary");
      } catch (cause) {
        throw new Error(
          `MIPS legacy ${byteOrder} verification failed; MCP stderr: ${stderr}`,
          { cause },
        );
      } finally {
        try {
          await client.close();
        } finally {
          await transport.close();
        }
      }
      reports.push({
        ...fixture,
        independent_reader: legacy,
        variant: "recordless-legacy-pinned",
        effective_language: `MIPS:${
          byteOrder === "little" ? "LE" : "BE"
        }:32:default`,
        procedures: "verified-through-snapshot",
        checks: [
          "recordless header admitted with inferred o32 assumption",
          "pinned 32-bit language checked after import",
          "legacy limitations retained in Evidence",
          "snapshot round-trip and profile parameters",
        ],
        status: "passed",
      });
    }
  }
  for (const [byteOrder, floatAbi, variant] of psp
    ? [["little", "hard"]]
    : ps2
      ? [
          ["little", "hard", "ps2sdk"],
          ["little", "hard", "legacy"],
        ]
      : [
          ["little", "hard"],
          ["big", "hard"],
          ["little", "soft"],
          ["big", "soft"],
        ]) {
    const fixture = psp
      ? await buildPspFixture(workspace)
      : ps2
        ? await buildPs2Fixture(workspace, variant)
        : await buildMipsFixture(workspace, byteOrder, floatAbi);
    const independent =
      psp || ps2
        ? fixture
        : await inspectMipsReadelf(fixture.path, byteOrder, floatAbi);
    const resolved = await parseBinaryTarget(fixture.path);
    if (!resolved.ok) throw resolved.error;
    if (psp) {
      assert.equal(resolved.value.mips.flags, 0x10a23001);
      assert.deepEqual(
        resolved.value.mips,
        independent.mips,
        "REA PSP ELF/ABI interpretation disagrees with GNU readelf and raw ABI bytes",
      );
    } else if (ps2) {
      assert.equal(resolved.value.mips.flags, PS2_VARIANTS[variant].flags);
      assert.deepEqual(
        resolved.value.mips,
        independent.mips,
        "REA PS2 ELF/ABI interpretation disagrees with GNU readelf and raw ABI bytes",
      );
    } else {
      assert.deepEqual(
        resolved.value.mips,
        independent.mips,
        "REA ELF/ABI interpretation disagrees with GNU readelf",
      );
    }
    assert.equal(resolved.value.sha256, fixture.sha256);
    const snapshotPath = join(
      workspace,
      `${byteOrder}-${variant ?? floatAbi}.snapshot.json`,
    );
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env,
      stderr: "pipe",
    });
    const client = new Client({ name: "rea-real-mips-proof", version: "1" });
    let stderr = "";
    transport.stderr?.on("data", (chunk) => {
      stderr = (stderr + chunk.toString()).slice(-65536);
    });
    const call = async (name, args = {}) => {
      const reply = await client.callTool(
        { name, arguments: args },
        { timeout: 180000 },
      );
      return requireMcpOperationResult(reply, name);
    };
    try {
      await client.connect(transport);
      if (missingExtension) {
        const rejected = await client.callTool(
          {
            name: "open_binary",
            arguments: { path: fixture.path, provider_id: "ghidra" },
          },
          { timeout: 60000 },
        );
        const error = requireMcpToolError(rejected);
        assert.match(JSON.stringify(error), extensionRefusal);
        let cliError;
        try {
          await execute(
            process.execPath,
            [
              entrypoint,
              "function",
              fixture.path,
              `${prefix}_entry`,
              "--provider",
              "ghidra",
              "--json",
            ],
            { env, timeout: 60000, maxBuffer: 1024 * 1024 },
          );
        } catch (cause) {
          cliError = cause;
        }
        assert.ok(
          cliError && Number.isInteger(cliError.code) && cliError.code !== 0,
          "Expected a typed public rejection, not a timeout or success",
        );
        assert.match(
          `${cliError.stdout}\n${cliError.stderr}`,
          extensionRefusal,
        );
        reports.push({
          path: fixture.path,
          status: "expected-missing-extension-refusal",
          cli_exit: cliError.code,
          mcp_error: error,
        });
        continue;
      }
      const target = await call("open_binary", {
        path: fixture.path,
        provider_id: "ghidra",
      });
      assert.equal(target.architecture, "mips");
      assert.equal(target.sha256, fixture.sha256);
      // ELF load-image verification is not the DOS comparison lane. Its retained
      // observations still expose the actual Ghidra language and loaded bytes.
      const image = await call("inspect_native_load_image");
      if (psp) assertPspLoadedImage(image.observations, fixture.sha256);
      else if (ps2) assertPs2LoadedImage(image.observations, fixture.sha256);
      else assertMipsLoadedImage(image.observations, byteOrder, fixture.sha256);
      const procedures = await call("list_procedures");
      const entry = procedures.find((p) => p.value === `${prefix}_entry`);
      const leaf = procedures.find((p) => p.value === `${prefix}_leaf`);
      assert.ok(entry, "Entry function missing from real Ghidra inventory");
      assert.ok(leaf, "Leaf function missing from real Ghidra inventory");
      assert.equal(
        BigInt(entry.address),
        BigInt(independent.symbols[`${prefix}_entry`]),
      );
      assert.equal(
        BigInt(leaf.address),
        BigInt(independent.symbols[`${prefix}_leaf`]),
      );
      const probe = independent.symbols[`${prefix}_probe`];
      assert.ok(
        procedures.some(
          (p) =>
            p.value === `${prefix}_probe` &&
            BigInt(p.address) === BigInt(probe),
        ),
      );
      const move = await call("inspect_native_instruction", { address: probe });
      const branch = await call("inspect_native_instruction", {
        address: `0x${(BigInt(probe) + 4n).toString(16)}`,
      });
      let ps2Instructions;
      if (psp) assertPspProbe(move, branch);
      else if (ps2) {
        // MIPS ADDIU, MMI PADDW/PCPYLD, R5900 MULT and VU0 macro VADD.xyzw.
        ps2Instructions = [];
        for (const expected of fixture.probe)
          ps2Instructions.push(
            await call("inspect_native_instruction", {
              address: expected.address,
            }),
          );
        assertPs2Probe(ps2Instructions, fixture.probe);
      } else assertMipsProbe(move, branch, byteOrder, probe);
      const global = await call("read_bytes", {
        address: independent.symbols[`${prefix}_global`],
        length: 4,
      });
      assert.equal(global.returned_bytes, 4);
      assertMipsGlobal(global.bytes_hex, byteOrder);
      const marker = await call("read_bytes", {
        address: independent.symbols[`${prefix}_marker`],
        length: Buffer.byteLength(markerText),
      });
      assert.equal(marker.bytes_hex, Buffer.from(markerText).toString("hex"));
      const callees = await call("procedure_callees", {
        procedure: entry.address,
      });
      assert.ok(
        callees.includes(leaf.address),
        "Expected direct call not recovered",
      );
      let ps2References;
      if (ps2) {
        // Incoming relationships and string inventory through public operations.
        const callers = await call("procedure_callers", {
          procedure: leaf.address,
        });
        assert.ok(
          callers.includes(entry.address),
          "Expected caller of the leaf function not recovered",
        );
        const incoming = await call("xrefs", { address: leaf.address });
        const entryStart = BigInt(entry.address);
        assert.ok(
          incoming.some(
            (source) =>
              BigInt(source) >= entryStart &&
              BigInt(source) < entryStart + 0x100n,
          ),
          "Expected call-site reference from the entry function not recovered",
        );
        const globalXrefs = await call("xrefs", {
          address: independent.symbols[`${prefix}_global`],
        });
        const strings = await call("search_strings", {
          pattern: "^rea-ps2-source-owned-fixture$",
          mode: "regex",
          case_sensitive: true,
        });
        // The extension maps the EE RAM mirrors (uncached at 0x20000000,
        // uncached-accelerated at 0x30100000) over the same bytes.
        const markerAddress = BigInt(independent.symbols[`${prefix}_marker`]);
        const mirrors = [
          markerAddress,
          markerAddress + 0x20000000n,
          markerAddress + 0x30100000n,
        ];
        assert.ok(
          strings.some((item) => BigInt(item.address) === markerAddress),
          "Fixture marker string not found at its symbol address",
        );
        assert.ok(
          strings.every(
            (item) =>
              item.value === "rea-ps2-source-owned-fixture" &&
              mirrors.includes(BigInt(item.address)),
          ),
          "Marker string reported outside its address or EE RAM mirrors",
        );
        ps2References = {
          callers,
          leaf_xrefs: incoming,
          global_xrefs: globalXrefs,
          marker_strings: strings,
          segments: await call("list_segments"),
        };
      }
      const softFloat =
        floatAbi === "soft"
          ? await verifySoftFloat(call, independent.symbols, byteOrder)
          : undefined;
      const assembly = await call("procedure_assembly", {
        procedure: entry.address,
      });
      assert.ok(assembly.trim().length > 0);
      const dossier = functionDossierSchema.parse(
        await call("analyze_function", { procedure: entry.address }),
      );
      assert.ok(dossier.pseudocode.trim().length > 0);
      const mapping = await call("address_to_file_offset", {
        address: entry.address,
      });
      const memory = await call("read_bytes", {
        address: entry.address,
        length: 16,
      });
      const sourceBytes = await readFile(fixture.path);
      assert.equal(memory.returned_bytes, 16);
      assert.equal(
        memory.bytes_hex,
        sourceBytes
          .subarray(mapping.file_offset, mapping.file_offset + 16)
          .toString("hex"),
      );
      const saved = await call("close_binary", {
        snapshot_path: snapshotPath,
      });
      assert.ok(saved.evidence_records > 0);
      const snapshot = parseAnalysisSnapshot(
        JSON.parse(await readFile(snapshotPath, "utf8")),
      );
      assert.equal(snapshot.target.architecture, "mips");
      assert.deepEqual(
        snapshot.binding.analysis_profile.parameters.mips_elf,
        expectedMipsElfProfile(independent.mips),
        "Snapshot profile did not retain the independently inspected ELF/ABI declaration",
      );
      assert.equal(
        snapshot.binding.analysis_profile.parameters.mips_soft_float_storage,
        floatAbi === "soft" ? "o32-soft-float-prototype-v1" : undefined,
      );
      assert.equal(
        snapshot.evidence_bundle.records.some((record) =>
          /Soft-float prototype outcome: 4 functions and [1-9]\d* function-pointer definitions use __rea_soft_float\./u.test(
            JSON.stringify(record),
          ),
        ),
        floatAbi === "soft",
        "Soft-float prototype outcome missing from, or unexpected in, retained Evidence",
      );
      assert.ok(snapshot.evidence_bundle.records.length > 0);
      if (ps2) {
        const parameters = snapshot.binding.analysis_profile.parameters;
        assert.equal(parameters.language_id, "r5900:LE:32:default");
        assert.equal(parameters.loader, "ElfLoader");
        assert.equal(
          parameters.mips_support_lane,
          "ps2-ee-elf32-exec-r5900-v1",
        );
        assert.equal(
          parameters.ps2_abi_declaration,
          PS2_VARIANTS[variant].abiDeclaration,
        );
        assert.match(parameters.ps2_extension.sha256, /^[a-f0-9]{64}$/u);
        const retained = JSON.stringify(snapshot.evidence_bundle.records);
        assert.ok(
          retained.includes("MMI and VU0 macro-mode"),
          "PS2 limitations missing from retained Evidence",
        );
        assert.equal(
          retained.includes("no MIPS ABI flags record"),
          variant === "legacy",
          "Recordless EABI64 limitation missing from, or unexpected in, Evidence",
        );
      }
      if (psp) {
        assert.equal(
          snapshot.binding.analysis_profile.parameters.language_id,
          "Allegrex:LE:32:default",
        );
        assert.match(
          snapshot.binding.analysis_profile.parameters.psp_extension.sha256,
          /^[a-f0-9]{64}$/u,
        );
        assert.ok(
          snapshot.evidence_bundle.records.some((record) =>
            JSON.stringify(record).includes("VFPU prefix"),
          ),
          "PSP limitations missing from retained Evidence",
        );
      }
      for (const evidence of snapshot.evidence_bundle.records)
        assert.equal(parseEvidence(evidence).subject?.architecture, "mips");
      await call("open_binary", {
        path: fixture.path,
        provider_id: "ghidra",
        snapshot_path: snapshotPath,
      });
      assert.deepEqual(await call("list_procedures"), procedures);
      await call("close_binary");

      if (psp || variant === "ps2sdk") {
        const alternate = join(workspace, "alternate");
        await mkdir(alternate);
        const other = psp
          ? await buildPspFixture(alternate, 11)
          : await buildPs2Fixture(alternate, variant, 11);
        assert.notEqual(other.sha256, fixture.sha256);
        assert.equal(
          other.symbols[`${prefix}_global`],
          fixture.symbols[`${prefix}_global`],
          "Target-switch control must reuse the same global address",
        );
        for (const item of [fixture, other, fixture]) {
          const selected = await call("open_binary", {
            path: item.path,
            provider_id: "ghidra",
          });
          assert.equal(selected.sha256, item.sha256);
          const word = await call("read_bytes", {
            address: item.symbols[`${prefix}_global`],
            length: 4,
          });
          const expected = Buffer.alloc(4);
          expected.writeUInt32LE(item.global_value);
          assert.equal(word.bytes_hex, expected.toString("hex"));
          await call("close_binary");
        }
        const wrongSnapshot = await client.callTool(
          {
            name: "open_binary",
            arguments: {
              path: other.path,
              provider_id: "ghidra",
              snapshot_path: snapshotPath,
            },
          },
          { timeout: 180000 },
        );
        requireMcpToolError(wrongSnapshot);
        // A bad snapshot must not poison the next clean public session.
        await call("open_binary", {
          path: fixture.path,
          provider_id: "ghidra",
        });
        await call("close_binary");
      }

      // Same public operation through CLI, not a private injected provider.
      const cli = await execute(
        process.execPath,
        [
          entrypoint,
          "function",
          fixture.path,
          `${prefix}_entry`,
          "--provider",
          "ghidra",
          "--json",
        ],
        { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
      );
      const evidence = parseEvidence(JSON.parse(cli.stdout));
      assert.equal(evidence.subject?.architecture, "mips");
      assert.equal(evidence.subject?.digest.sha256, fixture.sha256);
      const cliDossier = functionDossierSchema.parse(
        evidence.normalized_result,
      );
      assert.equal(cliDossier.procedure.address, dossier.procedure.address);
      assert.ok(cliDossier.pseudocode.trim().length > 0);
      assert.equal(
        createHash("sha256")
          .update(await readFile(fixture.path))
          .digest("hex"),
        fixture.sha256,
        "Analysis modified the source executable",
      );
      // This upstream carved-firmware proof is specific to the generic MIPS fixture.
      // PSP and PS2 keep their independent processor/A-B-A checks; carved
      // PSP and PS2 images are not verified.
      let carved;
      if (!psp && !ps2) {
        // A program-header ABI record survives carving, but GNU declarations in
        // uncaptured section headers remain unknown: both adapters must refuse.
        const read16 = (offset) =>
          byteOrder === "little"
            ? sourceBytes.readUInt16LE(offset)
            : sourceBytes.readUInt16BE(offset);
        const read32 = (offset) =>
          byteOrder === "little"
            ? sourceBytes.readUInt32LE(offset)
            : sourceBytes.readUInt32BE(offset);
        const sectionOffset = read32(32);
        const cut = sectionOffset - 1;
        const programOffset = read32(28);
        const programCount = read16(44);
        assert.equal(read16(42), 32);
        assert.ok(cut >= programOffset + programCount * 32);
        for (let i = 0; i < programCount; i += 1) {
          const offset = programOffset + i * 32;
          assert.ok(read32(offset + 4) + read32(offset + 16) <= cut);
        }
        const carvedBytes = sourceBytes.subarray(0, cut);
        const carvedPath = join(
          workspace,
          `${byteOrder}-${floatAbi}-carved.elf`,
        );
        const carvedSha256 = createHash("sha256")
          .update(carvedBytes)
          .digest("hex");
        await writeFile(carvedPath, carvedBytes);
        const carvedResolved = await parseBinaryTarget(carvedPath);
        if (!carvedResolved.ok) throw carvedResolved.error;
        assert.deepEqual(
          carvedResolved.value.mips.abiFlags,
          independent.mips.abiFlags,
        );
        assert.match(
          carvedResolved.value.mips.limitations.join(" "),
          /section header table/u,
        );
        const carvedError = requireMcpToolError(
          await client.callTool(
            {
              name: "open_binary",
              arguments: { path: carvedPath, provider_id: "ghidra" },
            },
            { timeout: 60000 },
          ),
        );
        assertIncompleteMipsInspection(carvedError);
        let carvedCliError;
        try {
          await execute(
            process.execPath,
            [
              entrypoint,
              "function",
              carvedPath,
              independent.symbols.rea_mips_entry,
              "--provider",
              "ghidra",
              "--json",
            ],
            { env, timeout: 60000, maxBuffer: 1024 * 1024 },
          );
        } catch (cause) {
          carvedCliError = cause;
        }
        assert.ok(
          carvedCliError &&
            Number.isInteger(carvedCliError.code) &&
            carvedCliError.code !== 0,
          "Expected an incomplete-ABI refusal, not a timeout or success",
        );
        assertIncompleteMipsInspection(JSON.parse(carvedCliError.stdout));
        assert.deepEqual(await readFile(carvedPath), carvedBytes);
        carved = {
          sha256: carvedSha256,
          source_bytes: carvedBytes.length,
          section_header_offset: sectionOffset,
          status: "expected-incomplete-abi-refusal",
          limitations: carvedResolved.value.mips.limitations,
          cli_exit: carvedCliError.code,
          mcp_error: carvedError,
        };
      }
      reports.push({
        ...fixture,
        independent_reader: independent,
        effective_language: image.observations.language_id,
        effective_compiler_spec: image.observations.compiler_spec_id,
        checks: [
          "independent ELF/ABI and symbols",
          "loaded Ghidra identity",
          "fixed instruction bytes and immediate",
          psp
            ? "Allegrex BITREV decoding and A-B-A target identity"
            : ps2
              ? `R5900 MMI/VU0 macro decoding, callers, xrefs and strings${
                  variant === "ps2sdk" ? ", A-B-A target identity" : ""
                }`
              : "conditional branch destination",
          "global word and marker bytes",
          "CLI/MCP and snapshot identity",
          ...(floatAbi === "soft"
            ? ["soft-float o32 parameter/return storage and caller constants"]
            : []),
        ],
        ...(softFloat === undefined ? {} : { soft_float: softFloat }),
        ...(ps2Instructions === undefined
          ? {}
          : {
              ps2_instructions: ps2Instructions.map((instruction) => ({
                address: instruction.address,
                bytes: instruction.bytes,
                mnemonic: instruction.mnemonic,
              })),
              ps2_references: ps2References,
            }),
        procedures: procedures.length,
        carved: carved ?? {
          status: "not_run",
          reason:
            "Carved-firmware verification covers generic MIPS fixtures; carved PSP and PS2 coverage is not established.",
        },
        status: "passed",
      });
    } catch (cause) {
      throw new Error(
        `MIPS ${byteOrder} ${floatAbi}-float verification failed; MCP stderr: ${stderr}`,
        { cause },
      );
    } finally {
      try {
        await client.close();
      } finally {
        await transport.close();
      }
    }
  }
} catch (cause) {
  primaryFailure = cause;
}
const completed = await completeVerifierRun(run);
if (
  completed.process_lineage.status !== "verified" ||
  completed.process_lineage.descendants.length !== 0
)
  throw new Error(
    `Cleanup unverified; retained diagnostic workspace: ${workspace}`,
    { cause: primaryFailure },
  );
if (primaryFailure !== undefined)
  throw new Error(
    `MIPS verification failed; retained workspace: ${workspace}`,
    {
      cause: primaryFailure,
    },
  );
await rm(workspace, { recursive: true, force: true });
console.log(JSON.stringify({ ...completed, fixtures: reports }, null, 2));
