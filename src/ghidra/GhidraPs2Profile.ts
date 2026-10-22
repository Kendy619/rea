import type {
  BinaryTarget,
  MipsElfMetadata,
} from "../domain/binaryTargetTypes.js";
import { ghidraMipsIncompleteDeclarationsReason } from "./GhidraMipsProfile.js";

/** EF_MIPS_MACH_5900: the Toshiba R5900 (Emotion Engine) machine declaration. */
const MIPS_MACH_5900 = 0x00920000;
const MIPS_ARCH_3 = 0x20000000;
const MIPS_ET_EXEC = 2;
const MIPS_ABI2 = 0x20;
const MIPS_ABI_EABI64 = 0x4000;
/** Assembler hints the lane accepts: EF_MIPS_NOREORDER and EF_MIPS_CPIC. */
const MIPS_ACCEPTED_HINTS = 0x1 | 0x4;
/** Afl_ext value GNU binutils assigns to the Toshiba R5900 ISA extension. */
const MIPS_AFL_EXT_5900 = 6;

/** The ELF machine declaration, not a filename, entry address or opcode guess. */
export const isGhidraPs2Target = (target: BinaryTarget): boolean =>
  target.kind === "executable" &&
  target.format === "elf" &&
  target.architecture === "mips" &&
  target.mips !== undefined &&
  (target.mips.flags & 0x00ff0000) === MIPS_MACH_5900;

/** The verified ABI declaration shape of an admitted PS2 target. */
export type GhidraPs2AbiDeclaration = "n32" | "eabi64";

const ps2AbiDeclaration = (flags: number): GhidraPs2AbiDeclaration | null =>
  (flags & (0x0000f000 | MIPS_ABI2)) === MIPS_ABI2
    ? "n32"
    : (flags & (0x0000f000 | MIPS_ABI2)) === MIPS_ABI_EABI64
      ? "eabi64"
      : null;

/** The ABI declaration committed for an admitted PS2 target. */
export const ghidraPs2AbiDeclaration = (
  target: BinaryTarget,
): GhidraPs2AbiDeclaration | null =>
  isGhidraPs2Target(target) && target.architecture === "mips"
    ? ps2AbiDeclaration(target.mips.flags)
    : null;

const gnuAttributesReason = (metadata: MipsElfMetadata): string | null => {
  const attributes = metadata.gnuAttributes;
  if (attributes === undefined)
    return "GNU MIPS ABI attribute inspection is unavailable; provider selection cannot treat it as absent.";
  if (attributes === null) return null;
  if (attributes.msa !== null && attributes.msa !== 0)
    return "The GNU MIPS MSA ABI attribute declares an unsupported or unknown vector argument ABI.";
  if (
    attributes.fpAbi !== null &&
    attributes.fpAbi !== 0 &&
    attributes.fpAbi !== 2
  )
    return "The PS2 Emotion Engine profile requires a single-precision or unspecified GNU floating-point ABI attribute; other declarations are not inferred.";
  return null;
};

/**
 * Admit the declarations independently observed from ps2dev GNU tools: modern
 * PS2SDK n32 executables with their R5900 ABI flags record, and the legacy
 * EABI64 header shape, with or without that record. Everything else is refused.
 */
export const ghidraPs2UnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (target.kind !== "executable" || target.architecture !== "mips")
    return null;
  const metadata = target.mips;
  if (target.format !== "elf" || metadata === undefined)
    return "PS2 analysis requires ELF metadata.";
  const attributes = gnuAttributesReason(metadata);
  if (attributes !== null) return attributes;
  const incomplete = ghidraMipsIncompleteDeclarationsReason(metadata);
  if (incomplete !== null) return incomplete;
  if (metadata.elfClass !== 32 || metadata.byteOrder !== "little")
    return "The PS2 Emotion Engine profile requires little-endian ELF32.";
  if (metadata.type !== MIPS_ET_EXEC)
    return "The PS2 Emotion Engine profile supports static ET_EXEC only; IRX/ERX modules, relocatable and shared images require separate verification.";
  const flags = metadata.flags;
  if (
    (flags & 0xf0000000) !== MIPS_ARCH_3 ||
    (flags & 0x0f000000) !== 0 ||
    (flags & 0x00000fff & ~(MIPS_ACCEPTED_HINTS | MIPS_ABI2)) !== 0
  )
    return "The PS2 Emotion Engine profile requires an R5900 MIPS III header without ASE, PIC, FP64, NAN2008 or other unverified flags.";
  const abiDeclaration = ps2AbiDeclaration(flags);
  if (abiDeclaration === null)
    return "The PS2 Emotion Engine profile admits the n32 (EF_MIPS_ABI2) or EABI64 header declarations only; o32, o64, EABI32 and mixed declarations are not inferred.";
  const abi = metadata.abiFlags;
  if (abi === undefined)
    return "The MIPS ABI flags record was not inspected; its absence is not inferred.";
  if (abi === null)
    return abiDeclaration === "eabi64"
      ? null
      : "A PS2 n32 header requires the separate MIPS ABI flags record that PS2SDK emits; missing declarations are not inferred.";
  // ps2dev v2.0.0: GNU readelf 2.45.1 reports MIPS III, 64-bit GPR and CPR1,
  // single-precision hard float, the Toshiba R5900 extension and flags1=1.
  // This is a bounded producer declaration, not a claim about MMI/VU0 semantics.
  if (
    abi.version !== 0 ||
    abi.isaLevel !== 3 ||
    abi.isaRevision !== 0 ||
    abi.gprSize !== 2 ||
    abi.cpr1Size !== 2 ||
    abi.cpr2Size !== 0 ||
    abi.fpAbi !== 2 ||
    abi.isaExtension !== MIPS_AFL_EXT_5900 ||
    abi.ases !== 0 ||
    abi.flags1 !== 1 ||
    abi.flags2 !== 0
  )
    return "The separate MIPS ABI flags record does not match the verified PS2SDK R5900 declaration (MIPS III, 64-bit registers, single float, R5900 extension); other declarations require separate verification.";
  return null;
};

/** The language and loader the PS2 profile imports with. */
export const GHIDRA_PS2_LANGUAGE_ID = "r5900:LE:32:default";
export const GHIDRA_PS2_COMPILER_SPEC_ID = "default";
export const GHIDRA_PS2_LOADER = "ElfLoader";

/** Propagated with every PS2 observation, including successful decompilation. */
export const GHIDRA_PS2_LIMITATIONS = [
  "PS2 Emotion Engine analysis uses the caller-installed ghidra-emotionengine-reloaded extension (language r5900:LE:32:default). ELF declarations and selected instruction checks are not proof of runtime semantics.",
  "MMI and VU0 macro-mode instructions are decoded by the extension; their decompiled form uses extension-defined operations and is not an execution oracle. VU0/VU1 microprograms, DMA, VIF, GIF and GS behavior are not analyzed.",
  "This PS2 profile covers static Emotion Engine ELF32 ET_EXEC only. IOP modules (IRX), disc images, overlays loaded at runtime and PS2 emulation are outside this verified lane.",
  "The extension's single R5900 compiler specification models 64-bit-register EABI/n32 argument passing; the ELF ABI declaration is retained but does not select a different calling convention.",
  "The extension adds PS2 memory blocks that are not file content: hardware registers, VU0/VU1 memory, GS registers, IOP RAM, scratchpad, BIOS and byte-mapped main-RAM mirrors at 0x20000000 (uncached) and 0x30100000 (uncached accelerated). Searches can report the same file bytes at mirror addresses.",
] as const;

/** Extra Evidence for a legacy header without an ABI flags record. */
export const ghidraPs2Limitations = (
  target: BinaryTarget,
): readonly string[] =>
  isGhidraPs2Target(target) &&
  target.architecture === "mips" &&
  target.mips.abiFlags === null
    ? [
        "The EABI64 header has no MIPS ABI flags record in the completely examined declaration tables; register widths and the floating-point ABI are not declared by the file.",
      ]
    : [];
