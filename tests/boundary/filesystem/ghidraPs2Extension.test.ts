import { mkdir, rename, utimes, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ArtifactResourceScope } from "../../../src/artifacts/ArtifactResourceScope.js";
import { parseBinaryTarget } from "../../../src/application/BinaryTargetResolver.js";
import { parseConfig } from "../../../src/config/parseConfig.js";
import { ok as javaProbeOk } from "../../../src/domain/result.js";
import type {
  BinaryTarget,
  MipsAbiFlags,
} from "../../../src/domain/binaryTargetTypes.js";
import type { GhidraInstallationHost } from "../../../src/ghidra/GhidraInstallation.js";
import type { GhidraJavaObservation } from "../../../src/ghidra/GhidraJavaProbe.js";
import {
  GhidraHeadlessLauncher,
  ghidraHeadlessArguments,
} from "../../../src/ghidra/GhidraLauncher.js";
import { GhidraProvider } from "../../../src/ghidra/GhidraProvider.js";
import { inspectGhidraPs2Extension } from "../../../src/ghidra/GhidraPs2Extension.js";
import {
  GHIDRA_PS2_LIMITATIONS,
  ghidraPs2Limitations,
  isGhidraPs2Target,
} from "../../../src/ghidra/GhidraPs2Profile.js";
import {
  ghidraProcessorUnsupportedReason,
  isGhidraPspTarget,
} from "../../../src/ghidra/GhidraPspProfile.js";
import { silentLogger } from "../../../src/logger.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

afterEach(() => {
  vi.restoreAllMocks();
});

// Synthetic installation files exercise the filesystem/profile boundary, not
// Emotion Engine decoding. Only the optional real CLI/MCP lane
// (scripts/verify-real-ghidra-mips.mjs --ps2) proves tool behavior.
// Independently inspected with ps2dev v2.0.0 / GNU readelf 2.45.1.
const ps2AbiFlags: MipsAbiFlags = {
  version: 0,
  isaLevel: 3,
  isaRevision: 0,
  gprSize: 2,
  cpr1Size: 2,
  cpr2Size: 0,
  fpAbi: 2,
  isaExtension: 6,
  ases: 0,
  flags1: 1,
  flags2: 0,
};
type MipsTarget = Extract<BinaryTarget, { architecture: "mips" }>;
const target = {
  kind: "executable",
  format: "elf",
  architecture: "mips",
  availableArchitectures: ["mips"],
  path: "/caller/ps2.elf",
  sha256: "a".repeat(64),
  mips: {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    // PS2SDK: noreorder, cpic, abi2 (n32), R5900, MIPS III.
    flags: 0x20920025,
    gnuAttributes: { fpAbi: 2, msa: null },
    abiFlags: ps2AbiFlags,
  },
} satisfies BinaryTarget;
// Legacy-SDK header shape: noreorder, EABI64, R5900, MIPS III, no record.
const legacyTarget: MipsTarget = {
  ...target,
  mips: {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    flags: 0x20924001,
    gnuAttributes: null,
    abiFlags: null,
  },
};
const host: GhidraInstallationHost = {
  platform: "linux",
  architecture: "x64",
  readText: () => "application.version=12.1.3\napplication.java.min=21\n",
  executable: () => true,
  probeJava: () =>
    javaProbeOk<GhidraJavaObservation>({
      osArch: "amd64",
      osName: "Linux",
      version: "21.0.13",
      major: 21,
      home: "/jdk-21",
      bits: 64,
      runtime: "jdk",
    }),
};
const SOURCES = "data/languages/";
async function installation() {
  const directory = await createTestTempDirectory("rea-ps2-profile-");
  const root = join(
    directory,
    "Ghidra",
    "Extensions",
    "ghidra-emotionengine-reloaded",
  );
  const contents = {
    "Module.manifest": "",
    "extension.properties":
      "name=ghidra-emotionengine-reloaded\nversion=12.1.3\n",
    [`${SOURCES}emotionengine.ldefs`]: "synthetic language definition",
    [`${SOURCES}r5900.slaspec`]: "synthetic SLEIGH source",
    [`${SOURCES}eecore.sinc`]: "synthetic SLEIGH include",
    [`${SOURCES}r5900.pspec`]: "synthetic processor specification",
    [`${SOURCES}r5900.cspec`]: "synthetic compiler specification",
    "lib/extension.jar": "synthetic ELF extension artifact",
  };
  for (const [path, text] of Object.entries(contents)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), text);
  }
  // Compiled after its sources, as `support/sleigh` leaves it.
  await writeFile(
    join(root, `${SOURCES}r5900.sla`),
    Buffer.concat([Buffer.from("sla\x04"), Buffer.from("synthetic")]),
  );
  const past = new Date(Date.now() - 60_000);
  for (const source of ["r5900.slaspec", "eecore.sinc"])
    await utimes(join(root, SOURCES, source), past, past);
  await mkdir(join(directory, "support"));
  const parsed = parseConfig({ GHIDRA_INSTALL_DIR: directory });
  if (!parsed.ok) throw parsed.error;
  return {
    directory,
    root,
    config: parsed.value,
    provider: new GhidraProvider(parsed.value, silentLogger, {}, host),
  };
}
const inspect = (root: string) =>
  inspectGhidraPs2Extension(root, "12.1.3", new ArtifactResourceScope());

describe("PS2 target classification", () => {
  it("selects the Emotion Engine profile only from the R5900 machine declaration", () => {
    expect(isGhidraPs2Target(target)).toBe(true);
    expect(isGhidraPs2Target(legacyTarget)).toBe(true);
    expect(isGhidraPspTarget(target)).toBe(false);
    for (const flags of [
      0x70001001, // generic MIPS32r2 o32
      0x00001001, // IOP-style R3000 / MIPS I o32
      0x10a23001, // PSP Allegrex
      0x20000021, // MIPS III n32 without a machine declaration
    ])
      expect(
        isGhidraPs2Target({ ...target, mips: { ...target.mips, flags } }),
      ).toBe(false);
  });

  it("keeps generic MIPS refusals for an IOP-shaped header", () => {
    const iop: MipsTarget = {
      ...target,
      mips: { ...target.mips, flags: 0x00001001 },
    };
    expect(ghidraProcessorUnsupportedReason(iop)).toContain(
      "EF_MIPS_ARCH_32R2",
    );
  });

  it.each([
    ["PS2SDK n32 with its R5900 ABI record", target],
    ["legacy EABI64 without an ABI record", legacyTarget],
    [
      "legacy EABI64 with an R5900 ABI record",
      {
        ...target,
        mips: { ...target.mips, flags: 0x20924001 },
      } satisfies MipsTarget,
    ],
  ])("admits %s", (_, admitted) => {
    expect(ghidraProcessorUnsupportedReason(admitted)).toBeNull();
  });

  it("states the missing record only for a recordless legacy header", () => {
    expect(ghidraPs2Limitations(target)).toEqual([]);
    expect(ghidraPs2Limitations(legacyTarget)).toEqual([
      expect.stringContaining("no MIPS ABI flags record"),
    ]);
  });

  it.skipIf(process.platform === "win32").each([
    [{ byteOrder: "big" }, "little-endian"],
    [{ elfClass: 64 }, "ELF32"],
    [{ type: 1 }, "ET_EXEC"],
    [{ type: 0xff80 }, "IRX"],
    [{ flags: 0x10920025 }, "MIPS III"],
    [{ flags: 0x20920027 }, "PIC"],
    [{ flags: 0x20920225 }, "FP64"],
    [{ flags: 0x24920025 }, "ASE"],
    [{ flags: 0x20921005 }, "n32 (EF_MIPS_ABI2) or EABI64"],
    [{ flags: 0x20923005 }, "n32 (EF_MIPS_ABI2) or EABI64"],
    [{ flags: 0x20924021 }, "n32 (EF_MIPS_ABI2) or EABI64"],
    [{ abiFlags: null }, "requires the separate MIPS ABI flags record"],
    [{ abiFlags: undefined }, "was not inspected"],
    [{ gnuAttributes: undefined }, "attribute inspection is unavailable"],
    [{ gnuAttributes: { fpAbi: 1, msa: null } }, "single-precision"],
    [{ gnuAttributes: { fpAbi: 2, msa: 1 } }, "MSA ABI"],
    [
      { limitations: ["section header table is unavailable"] },
      "inspection is incomplete",
    ],
  ])(
    "refuses unverified PS2 declarations %j before extension reads",
    async (change, reason) => {
      const { provider, root } = await installation();
      await rename(root, `${root}-unavailable`);
      const altered = {
        ...target,
        mips: { ...target.mips, ...change },
      } as BinaryTarget;
      expect(ghidraProcessorUnsupportedReason(altered)).toContain(reason);
      expect(provider.inspectTargetSupport(altered).status).toBe("unsupported");
      const result = await provider.resolveAnalysisProfile(altered);
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("Invalid target was admitted");
      expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
    },
  );

  it.each([
    ["version", 1],
    ["isaLevel", 2],
    ["isaRevision", 1],
    ["gprSize", 1],
    ["cpr1Size", 1],
    ["cpr2Size", 1],
    ["fpAbi", 1],
    ["fpAbi", 3],
    ["isaExtension", 0],
    ["isaExtension", 13],
    ["ases", 1],
    ["flags1", 0],
    ["flags2", 1],
  ] satisfies [keyof MipsAbiFlags, number][])(
    "rejects unverified PS2 ABI field %s=%i",
    (field, value) => {
      const altered: MipsTarget = {
        ...target,
        mips: { ...target.mips, abiFlags: { ...ps2AbiFlags, [field]: value } },
      };
      expect(ghidraProcessorUnsupportedReason(altered)).toContain(
        "verified PS2SDK R5900 declaration",
      );
    },
  );
});

describe.skipIf(process.platform === "win32")(
  "PS2 installed-extension and profile boundary",
  () => {
    it("binds source interpretation and installed content", async () => {
      const { provider, root } = await installation();
      expect(provider.inspectTargetSupport(target).status).toBe("supported");
      const first = await provider.resolveAnalysisProfile(target);
      if (!first.ok) throw first.error;
      const again = await provider.resolveAnalysisProfile(target);
      if (!again.ok) throw again.error;
      expect(again.value.profile?.digest).toBe(first.value.profile?.digest);
      expect(first.value.profile?.parameters).toMatchObject({
        architecture: "mips",
        language_id: "r5900:LE:32:default",
        compiler_spec_id: "default",
        loader: "ElfLoader",
        mips_support_lane: "ps2-ee-elf32-exec-r5900-v1",
        ps2_abi_declaration: "n32",
        mips_elf: {
          elf_class: 32,
          byte_order: "little",
          type: 2,
          flags: 0x20920025,
          gnu_attributes: { fp_abi: 2, msa: null },
          abi_flags: { isa_level: 3, gpr_size: 2, isa_extension: 6 },
        },
        ps2_extension: {
          id: "ghidra-emotionengine-reloaded",
          root,
          ghidra_version: "12.1.3",
          sha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
        },
      });
      expect(first.value.profile?.parameters).not.toHaveProperty(
        "psp_extension",
      );
      const legacy = await provider.resolveAnalysisProfile(legacyTarget);
      if (!legacy.ok) throw legacy.error;
      expect(legacy.value.profile?.parameters).toMatchObject({
        ps2_abi_declaration: "eabi64",
        mips_elf: { flags: 0x20924001, abi_flags: null, gnu_attributes: null },
      });
      await writeFile(
        join(root, `${SOURCES}r5900.sla`),
        Buffer.from("sla\x04changed processor semantics"),
      );
      const changed = await provider.resolveAnalysisProfile(target);
      if (!changed.ok) throw changed.error;
      expect(changed.value.profile?.digest).not.toBe(
        first.value.profile?.digest,
      );
    });

    it("fails before starting a provider after resolved extension bytes change", async () => {
      const { directory, root } = await installation();
      const extension = await inspect(root);
      await writeFile(join(root, "lib/extension.jar"), "changed analyzers");
      const spawn = vi.fn();
      const launcher = new GhidraHeadlessLauncher({
        environment: {},
        analyzeHeadlessPath: join(directory, "support/analyzeHeadless"),
        configurationDirectoryName: "ghidra_12.1.3_PUBLIC",
        javaHome: "/jdk-21",
        bridgeScriptPath: "/packaged/ReaGhidraBridge.java",
        ps2Extension: extension,
        spawnProcess: spawn,
      });
      const launched = await launcher.launch(
        {
          runtimeRoot: join(directory, "runtime"),
          transport: "unix-socket",
          endpointPath: join(directory, "socket"),
          token: "test-only-token",
          runId: "00000000-0000-4000-8000-000000000001",
          targetPath: target.path,
          targetSha256: target.sha256,
          providerVersion: "12.1.3",
          profileDigest: "b".repeat(64),
        },
        { resourceScope: new ArtifactResourceScope() },
      );
      expect(launched.ok).toBe(false);
      if (launched.ok)
        throw new Error("Changed extension reached provider startup");
      expect(String(launched.error.cause)).toContain(
        "Installed Emotion Engine content changed since profile resolution",
      );
      expect(spawn).not.toHaveBeenCalled();
    });

    it("reports a missing installation with the typed PS2 refusal", async () => {
      const { provider, root } = await installation();
      await rename(root, `${root}-removed`);
      const missing = await provider.resolveAnalysisProfile(target);
      expect(missing.ok).toBe(false);
      if (missing.ok) throw new Error("Missing installation was accepted");
      expect(missing.error._tag).toBe("AnalysisCapabilityUnavailableError");
      expect(missing.error.message).toContain("PS2_EXTENSION_UNAVAILABLE");
      expect(missing.error.message).toContain(
        "GHIDRA_INSTALL_DIR/Ghidra/Extensions",
      );
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "PS2 installed-extension components",
  () => {
    it("refuses an installation Ghidra would recompile in place", async () => {
      const { root } = await installation();
      await expect(inspect(root)).resolves.toMatchObject({
        id: "ghidra-emotionengine-reloaded",
      });
      const future = new Date(Date.now() + 60_000);
      await utimes(join(root, SOURCES, "eecore.sinc"), future, future);
      await expect(inspect(root)).rejects.toThrow(
        "r5900.sla is older than eecore.sinc",
      );
    });

    it("refuses a compiled language in another SLEIGH format", async () => {
      const { root } = await installation();
      await writeFile(
        join(root, `${SOURCES}r5900.sla`),
        Buffer.from("sla\x03older format"),
      );
      await expect(inspect(root)).rejects.toThrow("SLEIGH format-4");
    });

    it.each([
      `${SOURCES}r5900.sla`,
      `${SOURCES}r5900.slaspec`,
      `${SOURCES}emotionengine.ldefs`,
      "Module.manifest",
    ])("requires the installed component %s", async (component) => {
      const { root } = await installation();
      await rename(join(root, component), join(root, `${component}.removed`));
      await expect(inspect(root)).rejects.toThrow(
        `Missing installed Emotion Engine component: ${component}`,
      );
    });

    it("requires the extension's ELF extension JAR", async () => {
      const { root } = await installation();
      await rename(
        join(root, "lib/extension.jar"),
        join(root, "lib/extension.removed"),
      );
      await expect(inspect(root)).rejects.toThrow("no ELF extension JAR");
    });

    it.each([
      ["name=ghidra-allegrex\nversion=12.1.3\n", "does not match"],
      [
        "name=ghidra-emotionengine-reloaded\nversion=12.1.4\n",
        "does not match",
      ],
    ])(
      "rejects mismatched extension metadata %s",
      async (properties, reason) => {
        const { root } = await installation();
        await writeFile(join(root, "extension.properties"), properties);
        await expect(inspect(root)).rejects.toThrow(reason);
      },
    );

    it("does not broaden the separately verified host platforms", async () => {
      const { config } = await installation();
      for (const platform of ["darwin", "win32"] as const) {
        const provider = new GhidraProvider(
          config,
          silentLogger,
          {},
          { ...host, platform },
        );
        expect(provider.inspectTargetSupport(target).status).toBe(
          "unsupported",
        );
      }
    });

    it("rejects a caller-selected language override", async () => {
      const { directory } = await installation();
      const config = parseConfig({
        GHIDRA_INSTALL_DIR: directory,
        REA_GHIDRA_LANGUAGE_ID: "MIPS:LE:64:default",
      });
      if (!config.ok) throw config.error;
      const provider = new GhidraProvider(config.value, silentLogger, {}, host);
      const result = await provider.resolveAnalysisProfile(target);
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("Conflicting override was accepted");
      expect(result.error.message).toContain(
        "PS2 Emotion Engine profile does not accept REA_GHIDRA_LANGUAGE_ID",
      );
    });

    it("keeps the PS2 limitations owned by the profile", () => {
      expect(GHIDRA_PS2_LIMITATIONS.join(" ")).toContain(
        "MMI and VU0 macro-mode",
      );
      expect(GHIDRA_PS2_LIMITATIONS.join(" ")).toContain("0x20000000");
    });
  },
);

/**
 * Header-only ELF32 images for the real target reader. The n32 image carries a
 * PT_MIPS_ABIFLAGS record with the bytes GNU readelf printed for the PS2SDK
 * fixture; the legacy image declares no ABI record or section table.
 */
const ps2ElfBytes = (variant: "ps2sdk" | "legacy"): Buffer => {
  const record = variant === "ps2sdk";
  const abiOffset = 4096;
  const bytes = Buffer.alloc(record ? abiOffset + 24 : 52 + 32);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1]);
  bytes.writeUInt16LE(2, 16); // ET_EXEC
  bytes.writeUInt16LE(8, 18); // EM_MIPS
  bytes.writeUInt32LE(1, 20);
  bytes.writeUInt32LE(0x100000, 24);
  bytes.writeUInt32LE(52, 28); // e_phoff
  bytes.writeUInt32LE(record ? 0x20920025 : 0x20924001, 36);
  bytes.writeUInt16LE(52, 40);
  bytes.writeUInt16LE(32, 42);
  bytes.writeUInt16LE(1, 44);
  if (record) {
    bytes.writeUInt32LE(0x70000003, 52); // PT_MIPS_ABIFLAGS
    bytes.writeUInt32LE(abiOffset, 56);
    bytes.writeUInt32LE(24, 68);
    bytes.writeUInt32LE(24, 72);
    bytes.set(
      Buffer.from("000003000202000206000000000000000100000000000000", "hex"),
      abiOffset,
    );
  } else {
    bytes.writeUInt32LE(1, 52); // PT_LOAD over the header bytes
    bytes.writeUInt32LE(0, 56);
    bytes.writeUInt32LE(0x100000, 60);
    bytes.writeUInt32LE(0x100000, 64);
    bytes.writeUInt32LE(bytes.length, 68);
    bytes.writeUInt32LE(bytes.length, 72);
    bytes.writeUInt32LE(5, 76);
    bytes.writeUInt32LE(0x1000, 80);
  }
  return bytes;
};

describe.skipIf(process.platform === "win32")(
  "PS2 declarations through the real target reader",
  () => {
    it.each(["ps2sdk", "legacy"] as const)(
      "admits the %s declaration shape after inspection",
      async (variant) => {
        const { directory, provider } = await installation();
        const path = join(directory, `${variant}.elf`);
        await writeFile(path, ps2ElfBytes(variant));
        const parsed = await parseBinaryTarget(path);
        if (!parsed.ok) throw parsed.error;
        if (
          parsed.value.kind !== "executable" ||
          parsed.value.architecture !== "mips"
        )
          throw new Error("PS2 ELF was not recognized as MIPS");
        expect(parsed.value.mips.abiFlags).toEqual(
          variant === "ps2sdk" ? ps2AbiFlags : null,
        );
        expect(isGhidraPs2Target(parsed.value)).toBe(true);
        expect(provider.inspectTargetSupport(parsed.value).status).toBe(
          "supported",
        );
        const profile = await provider.resolveAnalysisProfile(parsed.value);
        if (!profile.ok) throw profile.error;
        expect(profile.value.profile?.parameters.ps2_abi_declaration).toBe(
          variant === "ps2sdk" ? "n32" : "eabi64",
        );
      },
    );

    it("does not treat unavailable section headers as a recordless legacy image", async () => {
      const { directory, provider } = await installation();
      const bytes = ps2ElfBytes("legacy");
      bytes.writeUInt32LE(bytes.length + 64, 32); // e_shoff beyond the file
      bytes.writeUInt16LE(40, 46);
      bytes.writeUInt16LE(2, 48);
      const path = join(directory, "legacy-carved.elf");
      await writeFile(path, bytes);
      const parsed = await parseBinaryTarget(path);
      if (!parsed.ok) throw parsed.error;
      expect(isGhidraPs2Target(parsed.value)).toBe(true);
      expect(provider.inspectTargetSupport(parsed.value).status).toBe(
        "unsupported",
      );
      const result = await provider.resolveAnalysisProfile(parsed.value);
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("Incomplete inspection was admitted");
      expect(result.error.message).toContain(
        "MIPS ABI declaration inspection is incomplete",
      );
    });

    it.each([
      ["a truncated ELF header", ps2ElfBytes("ps2sdk").subarray(0, 40)],
      [
        "a .elf name without ELF magic",
        Buffer.from("SLUS_000.00 is a name, not an executable"),
      ],
    ])("never admits %s as a PS2 target", async (_, bytes) => {
      const { directory } = await installation();
      const path = join(directory, "SLUS_000.00.elf");
      await writeFile(path, bytes);
      const parsed = await parseBinaryTarget(path);
      expect(parsed.ok && isGhidraPs2Target(parsed.value)).toBe(false);
    });
  },
);

describe("PS2 explicit loader boundary", () => {
  const paths = {
    projectRoot: "/project",
    targetPath: "/target.elf",
    bridgeScriptPath: "/bridge/Rea.java",
    descriptorPath: "/session",
    ghidraLogPath: "/log",
    scriptLogPath: "/scriptlog",
  };

  it("forces the ELF loader and R5900 language only for the selected profile", () => {
    expect(ghidraHeadlessArguments({ ...paths, ps2: true })).toEqual(
      expect.arrayContaining([
        "-loader",
        "ElfLoader",
        "-processor",
        "r5900:LE:32:default",
        "-cspec",
        "default",
      ]),
    );
    expect(ghidraHeadlessArguments(paths)).not.toContain("r5900:LE:32:default");
    expect(ghidraHeadlessArguments({ ...paths, psp: true })).not.toContain(
      "r5900:LE:32:default",
    );
  });

  it("keeps PS2, PSP, raw-binary and override launch paths mutually exclusive", () => {
    expect(() =>
      ghidraHeadlessArguments({ ...paths, ps2: true, psp: true }),
    ).toThrow("cannot be combined with a PS2 ELF import");
    expect(() =>
      ghidraHeadlessArguments({
        ...paths,
        ps2: true,
        languageOverride: { languageId: "MIPS:LE:32:default" },
      }),
    ).toThrow("PS2 ELF import cannot be combined");
    expect(() =>
      ghidraHeadlessArguments({ ...paths, ps2: true, mipsSoftFloat: true }),
    ).toThrow("generic MIPS ELF import");
  });
});
