// Convert an ask-rea.mjs export into the reversa God Hand evidence layout.
// Usage: node to-reversa-evidence.mjs <answers.json> <SLUS_215.03> <overview.json> <out-dir>
//
// answers.json must hold, for each function, `info-<addr>`, `instructions-<addr>`
// and `incoming-<addr>` answers plus one `batch_decompile` over the same set
// (see round7-questions.json). overview.json is an investigate-godhand.mjs
// summary from a session with the same ELF and seeds (procedure count).
// Writes <addr>.c files and analysis.json (schema god-hand-ghidra-focused-v1),
// plus rea-provenance.json. Every listing is checked against the ELF bytes: one
// instruction per 4 body bytes, addresses inside the body and each `jal` target
// equal to the decoded word.
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const [answersPath, elfPath, overviewPath, outDir] = process.argv.slice(2);
if (!outDir)
  throw new Error(
    "usage: to-reversa-evidence.mjs <answers.json> <elf> <overview.json> <out-dir>",
  );
const answers = JSON.parse(await readFile(answersPath, "utf8")).answers;
const elf = await readFile(elfPath);
const overview = JSON.parse(await readFile(overviewPath, "utf8"));
const sha256 = createHash("sha256").update(elf).digest("hex");

const phoff = elf.readUInt32LE(28);
const segments = [];
for (let i = 0; i < elf.readUInt16LE(44); i++) {
  const o = phoff + 32 * i;
  if (elf.readUInt32LE(o) === 1)
    segments.push({
      offset: elf.readUInt32LE(o + 4),
      vaddr: elf.readUInt32LE(o + 8),
      size: elf.readUInt32LE(o + 16),
    });
}
const word = (va) => {
  const s = segments.find((x) => x.vaddr <= va && va + 4 <= x.vaddr + x.size);
  if (!s) throw new Error(`0x${va.toString(16)} is not file-backed`);
  return elf.readUInt32LE(s.offset + va - s.vaddr);
};

const hex8 = (value) => BigInt(value).toString(16).padStart(8, "0");
const value = (id) => {
  const a = answers.find((x) => x.id === id);
  if (!a?.answer.ok)
    throw new Error(`${id}: ${a ? a.answer.error : "missing"}`);
  return a.answer.value;
};
// One or more batch_decompile answers (export-subsystem.mjs writes chunks).
const decompiled = answers
  .filter((a) => a.tool === "batch_decompile")
  .flatMap((a) => a.answer.value.items);

// Ghidra listing text as the reversa exporter writes it: "mnemonic op1,op2".
const listing = (text) => text.replace(/, /gu, ",");

await mkdir(outDir, { recursive: true });
const functions = [];
for (const item of decompiled) {
  const requested = item.address;
  const info = value(`info-${requested}`);
  const body = info.body.ranges;
  const inBody = (a) =>
    body.some((r) => BigInt(r.start) <= a && a <= BigInt(r.end));
  const instructions = value(`instructions-${requested}`).instructions.map(
    (line) => {
      const m = /^(0x[0-9a-f]+): (.*)$/u.exec(line);
      if (!m)
        throw new Error(`${requested}: unexpected instruction line ${line}`);
      const address = BigInt(m[1]);
      if (!inBody(address))
        throw new Error(`${requested}: ${m[1]} outside the body`);
      const jal = /^_?jal 0x([0-9a-f]+)$/u.exec(m[2]);
      if (jal) {
        const w = word(Number(address));
        const target =
          ((Number(address) + 4) & 0xf0000000) | ((w & 0x03ffffff) << 2);
        if (w >>> 26 !== 3 || target >>> 0 !== Number.parseInt(jal[1], 16))
          throw new Error(
            `${requested}: ${m[1]} listing ${m[2]} disagrees with ELF word ${w.toString(16)}`,
          );
      }
      return { address: hex8(address), assembly: listing(m[2]) };
    },
  );
  if (instructions.length * 4 !== info.body.total_bytes)
    throw new Error(
      `${requested}: ${instructions.length} instructions for ${info.body.total_bytes} bytes`,
    );
  const entry = BigInt(info.entrypoint);
  const incoming = value(`incoming-${requested}`)
    .references.filter((r) => BigInt(r.target_address) === entry)
    .map((r) => ({
      from: hex8(r.source_address),
      type: r.kind?.type ?? "UNKNOWN",
    }));
  const file = `${hex8(entry)}.c`;
  await writeFile(join(outDir, file), `${item.pseudocode ?? ""}\n`);
  functions.push({
    requestedAddress: hex8(requested),
    entry: hex8(entry),
    exactEntry: BigInt(requested) === entry,
    name: info.name,
    bodyBytes: info.body.total_bytes,
    incomingReferences: incoming,
    incomingReferenceCount: incoming.length,
    incomingTruncated: false,
    instructions,
    instructionsTruncated: false,
    decompileCompleted: item.status === "ok" && Boolean(item.pseudocode),
    decompilerMessage: item.status === "ok" ? "" : String(item.status),
    pseudocodeFile: file,
  });
}

const procedures =
  overview.overview?.procedure_count ??
  overview.overview?.procedures?.count ??
  null;
const analysis = {
  schema: "god-hand-ghidra-focused-v1",
  sha256,
  language: "r5900:LE:32:default",
  compilerSpec: "default",
  functionCountInDatabase: procedures,
  scope:
    "Selected static functions exported through REA MCP; not a runtime observation or a complete decompilation",
  analysisCompleteness:
    "Ghidra default auto-analysis completed in the REA session before any answer (REA serves no partial analysis); see rea-provenance.json",
  functions,
};
await writeFile(
  join(outDir, "analysis.json"),
  `${JSON.stringify(analysis, null, 2)}\n`,
);
await writeFile(
  join(outDir, "rea-provenance.json"),
  `${JSON.stringify(
    {
      producer:
        "REA MCP (experiments/godhand/ask-rea.mjs + to-reversa-evidence.mjs)",
      rea_lane: "ps2-ee-elf32-exec-r5900-v1",
      seeds: overview.seeds ?? null,
      answers_sha256: createHash("sha256")
        .update(await readFile(answersPath))
        .digest("hex"),
      checks:
        "instruction count = body bytes / 4; addresses inside the body; every jal target equal to the ELF word",
      limitations: [
        "Pseudocode is Ghidra's decompiler output and can omit floating-point call arguments passed in FPU registers.",
        "Incoming references are those Ghidra records to the exact entry; untyped pointer tables add none.",
      ],
    },
    null,
    2,
  )}\n`,
);
console.log(
  `${functions.length} functions, ${functions.reduce((n, f) => n + f.instructions.length, 0)} instructions, procedures=${procedures}`,
);
