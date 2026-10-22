# PS2 Emotion Engine static ELF analysis through Ghidra

This specialization builds on [generic MIPS support](ghidra-mips.md) and follows
the [PSP profile](ghidra-psp.md) pattern. It reuses REA's existing CLI/MCP,
Ghidra bridge, Evidence and snapshot workflows. R5900 instruction decoding, MMI
and VU0 macro-mode semantics, EE memory blocks and the calling convention remain
owned by
[Ghidra Emotion Engine: Reloaded](https://github.com/chaoticgd/ghidra-emotionengine-reloaded).

## Initial boundary

The profile is limited to Linux x64 hosts and little-endian ELF32 `ET_EXEC`
`EM_MIPS` images whose header declares the Toshiba R5900 machine
(`EF_MIPS_MACH_5900`, `0x00920000`) and MIPS III. Only `EF_MIPS_NOREORDER` and
`EF_MIPS_CPIC` hints are accepted besides the ABI selector; PIC, ASE, FP64,
NAN2008 and unknown bits are refused. Two ABI declaration shapes are admitted:

| Header                                  | Producer evidence                                                                         | ABI flags record                                                                                                                                                       |
| --------------------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| n32 (`EF_MIPS_ABI2`), e.g. `0x20920025` | ps2dev v2.0.0 PS2SDK, GNU binutils 2.45.1                                                 | Required: version 0, MIPS III rev 0, 64-bit GPR and CPR1, no CPR2, single-precision hard float (`fpAbi=2`), ISA extension R5900 (`6`), no ASEs, `flags1=1`, `flags2=0` |
| EABI64, e.g. `0x20924001`               | Legacy-SDK header shape, reproduced with the same toolchain (`-mabi=eabi`, `elf32lr5900`) | Optional; when present it must match the record above                                                                                                                  |

A recordless EABI64 header is admitted only after every ABI declaration source
was examined; register widths and the floating-point ABI then remain undeclared
and Evidence says so. A recordless n32 header, an uninspected record, a
contradictory GNU floating-point attribute, an incomplete (carved) section table
and every other combination are refused. Header flags are declarations, not
proof of every instruction's semantics.

The R5900 machine declaration, not a filename such as `SLUS_*.elf` or an entry
address, selects this profile. Generic MIPS, PSP/Allegrex and IOP (R3000) ELF
files keep their existing lanes or refusals. IRX/ERX modules, relocatable and
shared images, disc images, overlays loaded at runtime, VU microprograms, DMA,
VIF, GIF, GS and PS2 emulation are outside this profile. Combined EE+IOP
analysis and static recompilation (for example PS2Recomp) are not provided.

## Bring your own compatible extension

Install the release that declares your Ghidra version at
`$GHIDRA_INSTALL_DIR/Ghidra/Extensions/ghidra-emotionengine-reloaded`, with
`Module.manifest`, `extension.properties`, `data/languages/*` and
`lib/ghidra-emotionengine-reloaded.jar`. User-home installations are not
searched because REA uses an isolated analysis home. REA never downloads,
installs, rebuilds or vendors the extension.

Release archives ship SLEIGH sources only. Ghidra compiles a missing, stale or
wrong-format `r5900.sla` into the installation on first use, so REA requires a
precompiled file instead of letting analysis modify the installation:

```bash
"$GHIDRA_INSTALL_DIR/support/sleigh" -a \
  "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/ghidra-emotionengine-reloaded/data/languages"
```

REA refuses `r5900.sla` unless it starts with the SLEIGH format-4 header used
by Ghidra 12.1 and is not older than any `.slaspec` or `.sinc` file beside it.
Recompile after replacing the extension or its sources.

REA fingerprints installed extension files before resolving the analysis
profile and checks that identity again immediately before launch, with the same
bounds and refusals as the PSP extension: symlinks, nonregular files, missing
components and a `version` property that differs from the selected Ghidra are
refused. A content change yields a different profile; an old snapshot is not
silently reused. This is content identity, not a signature or a sandbox for
installed code. The extension's STABS analyzer runs its bundled `stdump`
executable for targets with `.mdebug` sections; disable it with
`REA_GHIDRA_DISABLED_ANALYZERS` if that is not acceptable.

## Ordinary public interfaces

```bash
rea analyze /absolute/path/to/ps2.elf --provider ghidra --json
rea function /absolute/path/to/ps2.elf function_name --provider ghidra --json
```

MCP uses `open_binary` with an absolute path and `provider_id: "ghidra"`, then
ordinary inventory, instruction, reference, string and function operations. The
import is explicitly loader `ElfLoader`, language `r5900:LE:32:default`,
compiler `default`; caller language overrides are refused. The handshake must
confirm the language and compiler before serving observations. Missing or
incompatible prerequisites return `PS2_EXTENSION_UNAVAILABLE` with a remedy; no
provider fallback or automatic installation occurs.

Evidence retains the `mips` architecture family, the ELF/ABI declaration
(`mips_elf`), `ps2_abi_declaration` (`n32` or `eabi64`), the support lane
`ps2-ee-elf32-exec-r5900-v1` and the extension content identity. Limitations
state that:

- MMI and VU0 macro-mode instructions decode to extension-defined operations;
  pseudocode is not an execution oracle.
- The extension's single R5900 compiler specification models 64-bit-register
  EABI/n32 argument passing whichever ABI the header declares.
- The extension adds memory blocks that are not file content: hardware
  registers, VU0/VU1 memory, GS registers, IOP RAM, scratchpad, BIOS, and
  byte-mapped main-RAM mirrors at `0x20000000` and `0x30100000`. String and
  byte searches can report the same file bytes at mirror addresses.

## Verification

Use the existing real MIPS verifier with its PS2 options. Required tools are
caller-supplied `make`, the ps2dev EE toolchain (`mips64r5900el-ps2-elf-gcc`,
`-ld`, `-readelf`, `-objdump`) on `PATH`, `PS2SDK`, `GHIDRA_INSTALL_DIR` and a
compatible `JAVA_HOME`.

```bash
npm run build:cached
node scripts/verify-real-ghidra-mips.mjs --ps2
# In a Ghidra installation without the extension, test the public refusals:
node scripts/verify-real-ghidra-mips.mjs --ps2-missing-extension
```

The maintained fixtures build from `tests/conformance/ps2/`, are never executed
and contain no commercial game data: `rea_ps2_fixture.elf` is a standard PS2SDK
n32 executable (crt0, linkfile, libc) and `rea_ps2_legacy.elf` is a freestanding
EABI64 control without an ABI record. GNU readelf and objdump independently
supply the header, ABI record bytes, symbols and probe encodings; REA's parsed
target and saved snapshot must agree with them. Through public MCP and CLI the
verifier checks the observed loader/language, known functions, a direct call,
the leaf's caller and call-site cross-reference, the immediate `0x1234` and the
exact bytes and mnemonics of MMI `PADDW`/`PCPYLD`, the R5900 three-operand
`MULT` and VU0 macro `VADD.xyzw`, a global word, the marker string (allowing its
RAM mirrors), Evidence limitations, snapshot reopening, and for the PS2SDK
fixture an A-B-A target switch with different global contents at the same
address. Cleanup must finish before success is reported.

The build maps its directory out of debug information, including the PS2SDK
libraries' link-time optimization units, so the output does not depend on where
it is built. With ps2dev v2.0.0 the default build produced SHA-256
`e312d08bf615af1dcfae47091109d2a64fa42fcebeec301762a0a7895b30e650`
(`rea_ps2_fixture.elf`) and
`dcc503dac0d30eef83fb7c43c448e9455a98b8bf66be0afffa3219a30337f787`
(`rea_ps2_legacy.elf`) in two different directories. Other toolchain versions
are expected to produce different bytes; the verifier derives its expectations
from the build it inspects rather than from these digests.

The first compatibility run used Ghidra **12.1.3**, extension **v2.1.38**
(the release built for 12.1.3), ps2dev **v2.0.0** (GCC 15.2.0, binutils 2.45.1)
and Temurin JDK 21 on Linux x64 (WSL2 Ubuntu 24.04). Carved PS2 images and
commercial or legacy-SDK-produced executables were not verified; the legacy
control reproduces their documented header shape, not their producer. These
checks are selected static facts, not full behavioral equivalence, VU semantics
or arbitrary PS2 compatibility.
