import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { parseMipsReadelfSectionTypes } from "./mips-checks.mjs";

const execute = promisify(execFile);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const TOOL = "mips64r5900el-ps2-elf-";

/** Source-owned probe encodings, in file byte order, from GNU objdump words. */
export const PS2_PROBE_ENCODINGS = [
  { word: "24021234", mnemonic: "li|addiu" },
  { word: "70851808", mnemonic: "paddw" },
  { word: "70621b89", mnemonic: "pcpyld" },
  { word: "00851018", mnemonic: "mult" },
  { word: "4be31068", mnemonic: "vadd\\.xyzw" },
];

/** Independent expectations for each maintained build variant. */
export const PS2_VARIANTS = {
  ps2sdk: {
    file: "rea_ps2_fixture.elf",
    flags: 0x20920025,
    flagsText: "0x20920025",
    abiDeclaration: "n32",
  },
  legacy: {
    file: "rea_ps2_legacy.elf",
    flags: 0x20924001,
    flagsText: "0x20924001",
    abiDeclaration: "eabi64",
  },
};

/** Build one maintained PS2 fixture with caller-supplied ps2dev tools; never execute it. */
export async function buildPs2Fixture(directory, variant, globalValue = 7) {
  assert.ok(variant === "ps2sdk" || variant === "legacy");
  assert.ok(globalValue === 7 || globalValue === 11);
  assert.ok(process.env.PS2SDK, "Missing prerequisite: caller-supplied PS2SDK");
  const expected = PS2_VARIANTS[variant];
  const options = {
    cwd: directory,
    env: { ...process.env, LC_ALL: "C", LANG: "C" },
    timeout: 10000,
    maxBuffer: 1024 * 1024,
  };
  const versions = {};
  for (const command of [
    "make",
    `${TOOL}gcc`,
    `${TOOL}ld`,
    `${TOOL}readelf`,
    `${TOOL}objdump`,
  ])
    versions[command] = (
      await execute(command, ["--version"], options)
    ).stdout.trim();
  const sourceDigests = {};
  for (const name of [
    "main.c",
    "probe.S",
    "start.c",
    "legacy.ld",
    "Makefile",
  ]) {
    const source = new URL(`../ps2/${name}`, import.meta.url);
    sourceDigests[name] = sha256(await readFile(source));
    await copyFile(source, join(directory, name));
  }
  const build = await execute(
    "make",
    [`REA_PS2_GLOBAL=${globalValue}`, expected.file],
    { ...options, timeout: 120000 },
  );
  const path = join(directory, expected.file);
  const bytes = await readFile(path);
  assert.ok(bytes.length >= 52);
  assert.equal(bytes.toString("hex", 0, 6), "7f454c460101");
  assert.equal(bytes.readUInt16LE(16), 2);
  assert.equal(bytes.readUInt16LE(18), 8);
  assert.equal(bytes.readUInt32LE(36), expected.flags);
  const readelf = await execute(
    `${TOOL}readelf`,
    ["-h", "-A", "-S", "-sW", path],
    { ...options, maxBuffer: 16 * 1024 * 1024 },
  );
  assert.equal(readelf.stderr.trim(), "");
  const mips = parsePs2ReadelfMips(readelf.stdout, variant);
  let abiRecordHexDump = null;
  if (variant === "ps2sdk") {
    const abiDump = await execute(
      `${TOOL}readelf`,
      ["-x", ".MIPS.abiflags", path],
      options,
    );
    assert.equal(abiDump.stderr.trim(), "");
    const abiWords = abiDump.stdout
      .split("\n")
      .filter((line) => /^\s*0x[0-9a-f]+\s/u.test(line))
      .flatMap((line) => line.match(/\b[0-9a-f]{8}\b/gu) ?? []);
    assert.equal(
      abiWords.join(""),
      "000003000202000206000000000000000100000000000000",
      "PS2SDK ABI bytes differ from independently inspected build intent",
    );
    abiRecordHexDump = abiDump.stdout;
  }
  const symbols = {};
  for (const [name, type] of [
    ["rea_ps2_entry", "FUNC"],
    ["rea_ps2_leaf", "FUNC"],
    ["rea_ps2_probe", "FUNC"],
    ["rea_ps2_global", "OBJECT"],
    ["rea_ps2_marker", "OBJECT"],
  ]) {
    const rows = readelf.stdout
      .split("\n")
      .map((line) => line.trim().split(/\s+/u))
      .filter((row) => row.length === 8 && row[7] === name);
    assert.equal(rows.length, 1, `Expected one defined PS2 symbol: ${name}`);
    const row = rows[0];
    assert.match(row[1], /^[0-9a-fA-F]{8}$/u);
    assert.equal(row[3], type);
    assert.equal(row[4], "GLOBAL");
    assert.match(row[6], /^\d+$/u);
    symbols[name] = `0x${Number.parseInt(row[1], 16).toString(16)}`;
  }
  const objdump = await execute(
    `${TOOL}objdump`,
    ["-d", "--disassemble=rea_ps2_probe", path],
    { ...options, maxBuffer: 16 * 1024 * 1024 },
  );
  assert.equal(objdump.stderr.trim(), "");
  const probe = parsePs2ProbeObjdump(objdump.stdout, symbols.rea_ps2_probe);
  return {
    variant,
    path,
    sha256: sha256(bytes),
    source_sha256: sourceDigests,
    symbols,
    flags: expected.flagsText,
    abi_declaration: expected.abiDeclaration,
    mips,
    abi_record_hex_dump: abiRecordHexDump,
    probe,
    global_value: globalValue,
    versions,
    objdump: objdump.stdout,
    build_stderr: build.stderr,
  };
}

/** The probe's first five instructions exactly as GNU objdump decodes them. */
export function parsePs2ProbeObjdump(text, probeAddress) {
  const start = BigInt(probeAddress);
  const rows = text
    .split("\n")
    .map((line) => line.match(/^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)/u))
    .filter((match) => match !== null)
    .map((match) => ({
      address: BigInt(`0x${match[1]}`),
      word: match[2],
      mnemonic: match[3],
    }));
  return PS2_PROBE_ENCODINGS.map((expected, index) => {
    const address = start + BigInt(index * 4);
    const row = rows.find((candidate) => candidate.address === address);
    assert.ok(row, `GNU objdump did not decode probe+${index * 4}`);
    assert.equal(row.word, expected.word);
    assert.match(row.mnemonic, new RegExp(`^(?:${expected.mnemonic})$`, "u"));
    return {
      address: `0x${address.toString(16)}`,
      // Little-endian file order, as REA reports instruction bytes.
      bytes: Buffer.from(expected.word, "hex").reverse().toString("hex"),
      gnu_mnemonic: row.mnemonic,
      mnemonic: expected.mnemonic,
    };
  });
}

/** Complete independent fields for the pinned ps2dev fixtures, not REA's parser. */
export function parsePs2ReadelfMips(text, variant) {
  const expected = PS2_VARIANTS[variant];
  assert.ok(expected, `Unknown PS2 fixture variant: ${variant}`);
  const field = (expression, label) => {
    const matches = [...text.matchAll(expression)];
    assert.equal(
      matches.length,
      1,
      `Missing or ambiguous PS2 readelf ${label}`,
    );
    return matches[0][1].trim();
  };
  assert.equal(field(/^\s*Class:\s*(.+)$/gmu, "class"), "ELF32");
  assert.equal(
    field(/^\s*Data:.*?,\s*(little|big) endian\s*$/gmu, "byte order"),
    "little",
  );
  assert.match(field(/^\s*Type:\s*(.+)$/gmu, "type"), /^EXEC\b/u);
  assert.match(
    field(/^\s*Flags:\s*(.+)$/gmu, "flags"),
    new RegExp(`^${expected.flagsText}\\b`, "u"),
  );
  const types = parseMipsReadelfSectionTypes(text);
  const hasRecord = /^MIPS ABI Flags Version:/mu.test(text);
  if (variant === "legacy") {
    // The legacy control discards every ABI declaration section at link time.
    assert.equal(hasRecord, false, "Legacy control unexpectedly has ABI flags");
    assert.ok(!types.includes("MIPS_ABIFLAGS"));
    assert.ok(!types.includes("GNU_ATTRIBUTES"));
    return {
      elfClass: 32,
      byteOrder: "little",
      type: 2,
      flags: expected.flags,
      abiFlags: null,
      gnuAttributes: null,
    };
  }
  const width = (name) => {
    const bits = Number(
      field(new RegExp(`^${name} size:\\s*(\\d+)\\s*$`, "gmu"), name),
    );
    assert.ok(bits === 0 || bits === 64, `Unverified PS2 ${name} width`);
    return bits === 64 ? 2 : 0;
  };
  assert.equal(
    field(/^FP ABI:\s*(.+)$/gmu, "FP ABI"),
    "Hard float (single precision)",
  );
  assert.equal(
    field(/^ISA Extension:\s*(.+)$/gmu, "ISA extension"),
    "Toshiba R5900",
  );
  assert.equal(field(/^ASEs:\s*\n[ \t]*(.+)$/gmu, "ASEs"), "None");
  const abi = {
    version: Number(
      field(/^MIPS ABI Flags Version:\s*(\d+)\s*$/gmu, "ABI version"),
    ),
    isaLevel: Number(field(/^ISA:\s*MIPS(\d+)\s*$/gmu, "ISA")),
    isaRevision: 0,
    gprSize: width("GPR"),
    cpr1Size: width("CPR1"),
    cpr2Size: width("CPR2"),
    fpAbi: 2,
    // GNU binutils AFL_EXT_5900, printed above as "Toshiba R5900".
    isaExtension: 6,
    ases: 0,
    flags1: Number.parseInt(
      field(/^FLAGS 1:\s*([\da-f]+)\s*$/gmu, "flags1"),
      16,
    ),
    flags2: Number.parseInt(
      field(/^FLAGS 2:\s*([\da-f]+)\s*$/gmu, "flags2"),
      16,
    ),
  };
  assert.deepEqual(
    abi,
    {
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
    },
    "PS2SDK ABI declaration differs from independently inspected build intent",
  );
  return {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    flags: expected.flags,
    abiFlags: abi,
    gnuAttributes: parsePs2GnuAttributes(text, types),
  };
}

// The PS2SDK fixture is single-float. Refuse other tags, vendors or scopes
// rather than confusing an unsupported declaration with absence.
function parsePs2GnuAttributes(text, types) {
  const count = types.filter((type) => type === "GNU_ATTRIBUTES").length;
  const headers = [...text.matchAll(/^Attribute Section: (.+)$/gmu)];
  if (count === 0) {
    assert.equal(
      headers.length,
      0,
      "GNU attributes without a declared section",
    );
    return null;
  }
  assert.equal(count, 1, "Ambiguous GNU attributes sections");
  assert.equal(headers.length, 1, "Missing or ambiguous GNU attributes output");
  const header = headers[0];
  assert.equal(header[1].trim(), "gnu", "Unsupported GNU attributes vendor");
  const tail = text.slice(header.index + header[0].length);
  const end = tail.search(/^MIPS ABI Flags Version:/mu);
  const lines = (end < 0 ? tail : tail.slice(0, end))
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
  assert.deepEqual(
    lines,
    ["File Attributes", "Tag_GNU_MIPS_ABI_FP: Hard float (single precision)"],
    "Unsupported or incomplete PS2 GNU attributes declaration",
  );
  return { fpAbi: 2, msa: null };
}

/** Observations from Ghidra, not an echo of the requested profile. */
export function assertPs2LoadedImage(image, targetSha256) {
  assert.equal(image.executable_format, "Executable and Linking Format (ELF)");
  assert.equal(image.language_id, "r5900:LE:32:default");
  assert.equal(image.compiler_spec_id, "default");
  assert.equal(image.source_files.length, 1);
  assert.equal(image.source_files[0].original_sha256, targetSha256);
}

/** Fixed source encodings and the independently chosen immediate, not pseudocode. */
export function assertPs2Probe(instructions, probe) {
  assert.equal(instructions.length, probe.length);
  instructions.forEach((instruction, index) => {
    const expected = probe[index];
    assert.equal(
      instruction.status,
      "decoded",
      `probe+${index * 4} not decoded`,
    );
    assert.equal(instruction.length, 4);
    assert.equal(instruction.bytes, expected.bytes);
    assert.match(
      instruction.mnemonic,
      new RegExp(`^(?:${expected.mnemonic})$`, "iu"),
      `Unexpected Ghidra mnemonic at probe+${index * 4}`,
    );
  });
  assert.ok(
    instructions[0].operands.some((operand) =>
      operand.components.some(
        (part) =>
          part.kind === "immediate" &&
          part.value !== null &&
          BigInt(part.value) === 0x1234n,
      ),
    ),
    "ADDIU immediate 0x1234 not recovered",
  );
}
