import assert from "node:assert/strict";
import { it } from "vitest";
import { expectedMipsElfProfile } from "./mips-checks.mjs";
import { parsePs2ProbeObjdump, parsePs2ReadelfMips } from "./ps2-fixture.mjs";

// GNU readelf/objdump 2.45.1 output from the maintained ps2dev v2.0.0 fixtures
// (tests/conformance/ps2). These parser checks do not establish a Ghidra run.
const legacyReadelf = `ELF Header:
  Class:                             ELF32
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           MIPS R3000
  Flags:                             0x20924001, noreorder, 5900, eabi64, mips3
  Number of section headers:         7

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .text             PROGBITS        00100000 001000 000148 00  AX  0   0  8
  [ 2] .rodata           PROGBITS        00100148 001148 00001d 00   A  0   0  8
  [ 3] .data             PROGBITS        00100168 001168 000004 00  WA  0   0  4
  [ 4] .symtab           SYMTAB          00000000 00116c 0000d0 10      5   4  4
  [ 5] .strtab           STRTAB          00000000 00123c 00006a 00      0   0  1
  [ 6] .shstrtab         STRTAB          00000000 0012a6 00002f 00      0   0  1
Key to Flags:
`;

const ps2sdkAbi = `Attribute Section: gnu
File Attributes
  Tag_GNU_MIPS_ABI_FP: Hard float (single precision)

MIPS ABI Flags Version: 0

ISA: MIPS3
GPR size: 64
CPR1 size: 64
CPR2 size: 0
FP ABI: Hard float (single precision)
ISA Extension: Toshiba R5900
ASEs:
\tNone
FLAGS 1: 00000001
FLAGS 2: 00000000
`;

// Captured header and ABI output with a constructed section-table subset.
const ps2sdkReadelf = `ELF Header:
  Class:                             ELF32
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           MIPS R3000
  Flags:                             0x20920025, noreorder, cpic, abi2, 5900, mips3
  Number of section headers:         3

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .MIPS.abiflags    MIPS_ABIFLAGS   00120fe0 021060 000018 18   A  0   0  8
  [ 2] .gnu.attributes   GNU_ATTRIBUTES  00000000 024712 000010 00      0   0  1
Key to Flags:
${ps2sdkAbi}`;

const legacyObjdump = `
rea_ps2_legacy.elf:     file format elf32-littlemips


Disassembly of section .text:

00100128 <rea_ps2_probe>:
  100128:\t24021234 \tli\tv0,4660
  10012c:\t70851808 \tpaddw\tv1,a0,a1
  100130:\t70621b89 \tpcpyld\tv1,v1,v0
  100134:\t00851018 \tmult\tv0,a0,a1
  100138:\t4be31068 \tvadd.xyzw\t$vf1xyzw,$vf2xyzw,$vf3xyzw
  10013c:\t03e00008 \tjr\tra
  100140:\t00000000 \tnop
`;

const ps2AbiFlags = {
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

it("reads the PS2SDK n32 R5900 declaration independently", () => {
  assert.deepEqual(parsePs2ReadelfMips(ps2sdkReadelf, "ps2sdk"), {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    flags: 0x20920025,
    abiFlags: ps2AbiFlags,
    gnuAttributes: { fpAbi: 2, msa: null },
  });
});

it("reads the legacy EABI64 control as an inspected record absence", () => {
  const mips = parsePs2ReadelfMips(legacyReadelf, "legacy");
  assert.deepEqual(mips, {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    flags: 0x20924001,
    abiFlags: null,
    gnuAttributes: null,
  });
  assert.deepEqual(expectedMipsElfProfile(mips), {
    elf_class: 32,
    byte_order: "little",
    type: 2,
    flags: 0x20924001,
    gnu_attributes: null,
    abi_flags: null,
  });
});

it.each([
  ["another machine", "0x20920025, noreorder", "0x10a23001, noreorder"],
  ["another ISA extension", "Toshiba R5900", "None"],
  [
    "another FP ABI",
    "FP ABI: Hard float (single precision)",
    "FP ABI: Soft float",
  ],
  ["another GPR width", "GPR size: 64", "GPR size: 32"],
])("refuses a PS2SDK declaration with %s", (_, from, to) => {
  assert.throws(() =>
    parsePs2ReadelfMips(ps2sdkReadelf.replace(from, to), "ps2sdk"),
  );
});

it("refuses a legacy control that still carries an ABI record", () => {
  assert.throws(
    () => parsePs2ReadelfMips(`${legacyReadelf}${ps2sdkAbi}`, "legacy"),
    /unexpectedly has ABI flags/u,
  );
});

it("binds probe encodings and mnemonics to GNU objdump, in file byte order", () => {
  assert.deepEqual(
    parsePs2ProbeObjdump(legacyObjdump, "0x100128").map(
      ({ address, bytes, gnu_mnemonic }) => [address, bytes, gnu_mnemonic],
    ),
    [
      ["0x100128", "34120224", "li"],
      ["0x10012c", "08188570", "paddw"],
      ["0x100130", "891b6270", "pcpyld"],
      ["0x100134", "18108500", "mult"],
      ["0x100138", "6810e34b", "vadd.xyzw"],
    ],
  );
  assert.throws(() =>
    parsePs2ProbeObjdump(
      legacyObjdump.replace("70851808", "70851809"),
      "0x100128",
    ),
  );
});
