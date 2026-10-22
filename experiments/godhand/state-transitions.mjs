// Static cEm00 state-transition graph from two independent sources.
// Usage: node state-transitions.mjs <SLUS_215.03> <round3.json> <round5.json> <symbol_addrs.txt> <out.json>
//
// For each behaviour-table entry (mode tables at 0x3bf1c8 / 0x3bf738 / 0x3bf878):
// - "pseudocode": constant writes to +0x2f5 in REA's decompiled body, paired with
//   a constant +0x2f4 write within three lines (else the mode is unchanged);
// - "machine": `sb rt, 0x2f5(base)` instructions between the entry and the next
//   decomp symbol, whose rt was loaded with `addiu/ori rt, $zero, imm` within the
//   previous eight instructions ($zero stores 0), paired with a `sb` to 0x2f4 within
//   eight instructions. Each machine edge keeps its instruction address.
// Writes done inside called helpers are not seen by either source.
import { readFile, writeFile } from "node:fs/promises";

const [elfPath, round3Path, round5Path, symbolsPath, outPath] =
  process.argv.slice(2);
if (!outPath)
  throw new Error(
    "usage: state-transitions.mjs <elf> <round3.json> <round5.json> <symbol_addrs.txt> <out.json>",
  );
const elf = await readFile(elfPath);
const TABLES = [
  { mode: "0/3", base: 0x3bf1c8, count: 174 },
  { mode: "1", base: 0x3bf738, count: 40 },
  { mode: "2", base: 0x3bf878, count: 5 },
];

// ELF loadable segments.
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
  if (!s) throw new Error(`0x${va.toString(16)} not file-backed`);
  return elf.readUInt32LE(s.offset + va - s.vaddr);
};

const starts = [];
for (const line of (await readFile(symbolsPath, "utf8")).split("\n")) {
  const m = /^\S+\s*=\s*0x([0-9A-Fa-f]+);\s*\/\/.*type:func/u.exec(line);
  if (m) starts.push(Number.parseInt(m[1], 16));
}
starts.sort((a, b) => a - b);
const nextStart = (a) => starts.find((s) => s > a) ?? a + 0x4000;

const decompiled = new Map();
for (const path of [round3Path, round5Path]) {
  const data = JSON.parse(await readFile(path, "utf8"));
  for (const answer of data.answers.filter((a) => a.tool === "batch_decompile"))
    for (const item of answer.answer.value.items)
      if (item.procedure?.address)
        decompiled.set(
          Number(BigInt(item.procedure.address)),
          item.pseudocode ?? "",
        );
}

const constant = (text) => {
  const t = text.trim();
  if (/^'\\x([0-9a-f]{2})'$/u.test(t))
    return Number.parseInt(t.slice(3, 5), 16);
  if (/^'\\0'$/u.test(t)) return 0;
  if (/^'\\[abtnvfr]'$/u.test(t))
    return { a: 7, b: 8, t: 9, n: 10, v: 11, f: 12, r: 13 }[t[2]];
  if (/^'.'$/u.test(t)) return t.charCodeAt(1);
  if (/^(0x[0-9a-f]+|\d+)$/u.test(t)) return Number(t);
  return null;
};
const fieldWrite = (line, field) => {
  const m = new RegExp(`\\+ ${field}\\) = ([^;]+);`, "u").exec(line);
  return m ? constant(m[1]) : undefined;
};

const fromPseudocode = (code) => {
  const lines = code.split("\n");
  const edges = [];
  lines.forEach((line, i) => {
    const phase = fieldWrite(line, "0x2f5");
    if (phase === undefined || phase === null) return;
    let mode = null;
    for (
      let j = Math.max(0, i - 3);
      j <= Math.min(lines.length - 1, i + 3);
      j++
    ) {
      const m = fieldWrite(lines[j], "0x2f4");
      if (m !== undefined && m !== null) mode = m;
    }
    edges.push({ mode, phase });
  });
  return edges;
};

// Constant loaded into `rt` by `addiu/ori rt, $zero, imm` within eight
// instructions before `pc` ($zero is 0); null when rt is redefined first.
const loadedConstant = (pc, rt, entry) => {
  if (rt === 0) return 0;
  for (let back = pc - 4; back >= Math.max(entry, pc - 32); back -= 4) {
    const v = word(back);
    const op = v >>> 26;
    if (((v >>> 16) & 31) !== rt) continue;
    if ((op === 0x09 || op === 0x0d) && ((v >>> 21) & 31) === 0)
      return v & 0xffff;
    if (op !== 0x28 && op !== 0x29 && op !== 0x2b) return null; // not a store: rt redefined
  }
  return null;
};
// `sb rt, offset(base)` stores whose value is a known constant.
const constantStore = (pc, offset, entry) => {
  const w = word(pc);
  if (w >>> 26 !== 0x28 || (w & 0xffff) !== offset) return null;
  return loadedConstant(pc, (w >>> 16) & 31, entry);
};

const fromMachine = (entry) => {
  const end = nextStart(entry);
  const edges = [];
  for (let pc = entry; pc < end; pc += 4) {
    const phase = constantStore(pc, 0x2f5, entry);
    if (phase === null) continue;
    let mode = null;
    for (
      let near = Math.max(entry, pc - 32);
      mode === null && near <= Math.min(end - 4, pc + 32);
      near += 4
    )
      mode = constantStore(near, 0x2f4, entry);
    edges.push({ mode, phase, at: `0x${pc.toString(16).padStart(8, "0")}` });
  }
  return edges;
};

const key = (e) => `${e.mode ?? "same"}:${e.phase}`;
const SIZE = { 0: 174, 1: 40, 2: 5, 3: 174 };
// A target is possible only when its phase exists in the target mode's table.
const possible = (to, fromMode) => {
  const [m, ph] = to.split(":");
  const modes = m === "same" ? fromMode.split("/") : [m];
  return modes.every((x) => SIZE[x] !== undefined && Number(ph) < SIZE[x]);
};
const nodes = [];
for (const table of TABLES) {
  for (let phase = 0; phase < table.count; phase++) {
    const entry = word(table.base + 8 * phase + 4);
    const code = decompiled.get(entry);
    const pseudo =
      code === undefined ? null : [...new Set(fromPseudocode(code).map(key))];
    const machine = fromMachine(entry);
    const machineKeys = [...new Set(machine.map(key))];
    nodes.push({
      from: `${table.mode}:${phase}`,
      function: `0x${entry.toString(16).padStart(8, "0")}`,
      pseudocode: pseudo,
      machine: machine.map((e) => ({ to: key(e), at: e.at })),
      agree:
        pseudo === null
          ? null
          : pseudo.filter((k) => machineKeys.includes(k)).length,
      only_pseudocode:
        pseudo === null ? null : pseudo.filter((k) => !machineKeys.includes(k)),
      only_machine:
        pseudo === null
          ? machineKeys
          : machineKeys.filter((k) => !pseudo.includes(k)),
    });
    const node = nodes.at(-1);
    // Merged edges: confidence "both" > "machine" (instruction anchor) > "pseudocode".
    const edges = new Map();
    for (const to of pseudo ?? [])
      edges.set(to, { to, source: "pseudocode", at: [] });
    for (const e of node.machine) {
      const prior = edges.get(e.to);
      if (prior) {
        prior.source = prior.source === "machine" ? "machine" : "both";
        prior.at.push(e.at);
      } else edges.set(e.to, { to: e.to, source: "machine", at: [e.at] });
    }
    node.edges = [...edges.values()].map((e) => ({
      ...e,
      possible: possible(e.to, table.mode),
    }));
  }
}
const totals = {
  entries: nodes.length,
  decompiled: nodes.filter((n) => n.pseudocode !== null).length,
  pseudocode_targets: nodes.reduce(
    (s, n) => s + (n.pseudocode?.length ?? 0),
    0,
  ),
  machine_targets: nodes.reduce(
    (s, n) => s + new Set(n.machine.map((e) => e.to)).size,
    0,
  ),
  agreeing_targets: nodes.reduce((s, n) => s + (n.agree ?? 0), 0),
  merged_edges: nodes.reduce((s, n) => s + n.edges.length, 0),
  merged_by_source: nodes
    .flatMap((n) => n.edges)
    .reduce((c, e) => ({ ...c, [e.source]: (c[e.source] ?? 0) + 1 }), {}),
  impossible_edges: nodes.flatMap((n) =>
    n.edges
      .filter((e) => !e.possible)
      .map((e) => `${n.from}->${e.to}:${e.source}`),
  ),
  entries_without_constant_writes: nodes.filter(
    (n) => (n.pseudocode?.length ?? 0) === 0 && n.machine.length === 0,
  ).length,
};
await writeFile(
  outPath,
  `${JSON.stringify({ schema: "rea-godhand-cem00-transitions-v1", note: "mode 'same' = +0x2f4 not written nearby; helper writes are not seen", totals, nodes }, null, 1)}\n`,
);
console.log(JSON.stringify(totals));
