// Machine-level reading of MIPS switch jump tables in REA instruction listings.
// Usage: node jump-tables.mjs <answers.json> <SLUS_215.03> <procedure address> <out.json>
//
// For each `jr <reg>` (not ra) in the procedure's REA listing, recognise
//   l[hbw][u] idx, OFF(base) ; addiu idx, idx, -MIN ; sltiu c, idx, N ;
//   beq c, zero, DEFAULT ; lui t, HI ; sll ; addiu t, t, LO ; addu ; lw r, 0(..) ; jr r
// read the N targets from the ELF, then follow each target through straight-line
// code (delay slots executed, unconditional branches taken, calls stepped over)
// until a conditional branch, a return or an indirect jump. Constant stores to
// +0x2f4 (mode) / +0x2f5 (phase) on that path are recorded with their address.
// This certifies case -> first block -> first decision; it does not evaluate the
// conditions, so later writes behind a conditional branch are not claimed.
import { readFile, writeFile } from "node:fs/promises";

const [answersPath, elfPath, procedure, outPath] = process.argv.slice(2);
if (!outPath)
  throw new Error(
    "usage: jump-tables.mjs <answers.json> <elf> <procedure> <out.json>",
  );
const answers = JSON.parse(await readFile(answersPath, "utf8")).answers;
const listing = answers.find((a) => a.id === `instructions-${procedure}`)
  ?.answer?.value?.instructions;
if (!listing) throw new Error(`no instructions-${procedure} answer`);
const elf = await readFile(elfPath);
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

// Parse "0xADDR: [_]mnemonic op, op, op".
const code = new Map();
for (const line of listing) {
  const m = /^0x([0-9a-f]+): (_?)(\S+)\s*(.*)$/u.exec(line);
  if (!m) continue;
  code.set(Number.parseInt(m[1], 16), {
    text: `${m[2]}${m[3]} ${m[4]}`.trim(),
    op: m[3],
    args: m[4] ? m[4].split(/,\s*/u) : [],
  });
}
const at = (n) => `0x${n.toString(16).padStart(8, "0")}`;
const num = (s) => {
  const neg = s.startsWith("-");
  const v = Number.parseInt(
    neg ? s.slice(1) : s,
    s.replace("-", "").startsWith("0x") ? 16 : 10,
  );
  return neg ? -v : v;
};

const STORE = /^(sb|sh|sw|sd|sq|swc1|sdc1|sqc2)$/u;
const COND =
  /^(beq|bne|blez|bgtz|bltz|bgez|beql|bnel|blezl|bgtzl|bltzl|bgezl|bc1t|bc1f|bc1tl|bc1fl|bltzal|bgezal)$/u;
const CLOBBERED_BY_CALL = [
  "at",
  "v0",
  "v1",
  "a0",
  "a1",
  "a2",
  "a3",
  "t0",
  "t1",
  "t2",
  "t3",
  "t4",
  "t5",
  "t6",
  "t7",
  "t8",
  "t9",
  "ra",
];

const step = (pc, regs) => {
  const ins = code.get(pc);
  if (!ins) return;
  const [d, s, t] = ins.args;
  if (ins.op === "move" && s === "zero") regs.set(d, 0);
  else if (
    (ins.op === "addiu" || ins.op === "ori" || ins.op === "daddiu") &&
    s === "zero"
  )
    regs.set(d, num(t));
  else if (ins.op === "li") regs.set(d, num(s));
  else if (
    !STORE.test(ins.op) &&
    !COND.test(ins.op) &&
    d &&
    /^[a-z][a-z0-9]$/u.test(d)
  )
    regs.delete(d);
};

// Apply the instruction at `p` to a path: record a constant +0x2f4/+0x2f5 store,
// then update the known register constants.
const execute = (p, path) => {
  const i = code.get(p);
  const m =
    i?.op === "sb" ? /^(0x2f[45])\((\w+)\)$/u.exec(i.args[1] ?? "") : null;
  if (m)
    path.writes.push({
      field: m[1] === "0x2f4" ? "mode" : "phase",
      value: path.regs.has(i.args[0]) ? path.regs.get(i.args[0]) : null,
      at: at(p),
    });
  step(p, path.regs);
};
const fork = (path, condition) => ({
  regs: new Map(path.regs),
  writes: [...path.writes],
  calls: [...path.calls],
  conditions: [...path.conditions, condition],
  seen: new Set(path.seen),
});
const isJump = (ins) =>
  ins.op === "b" ||
  ins.op === "j" ||
  (ins.op === "beq" && ins.args[0] === "zero" && ins.args[1] === "zero");

// Explore both sides of conditional branches from `start`, up to `depth`
// branches and `limit` paths. Each path keeps the branch conditions it assumed
// (taken or not, by instruction address), its constant state writes, its calls
// and its end. Depth 0 gives the first block up to its first decision.
const explore = (start, depth = 10, limit = 256) => {
  const paths = [];
  const finish = (path, end) => {
    const { conditions, writes, calls } = path;
    paths.push({ conditions, writes, calls, end });
  };
  const walk = (startPc, path) => {
    let pc = startPc;
    for (let n = 0; n < 600 && paths.length < limit; n++) {
      const ins = code.get(pc);
      if (path.seen.has(pc) || !ins)
        return finish(path, {
          kind: ins ? "loop" : "left-listing",
          at: at(pc),
        });
      path.seen.add(pc);
      if (ins.op === "jr") {
        execute(pc + 4, path);
        return finish(path, {
          kind: ins.args[0] === "ra" ? "return" : "indirect",
          at: at(pc),
        });
      }
      if (isJump(ins)) {
        execute(pc + 4, path);
        pc = Number.parseInt(ins.args.at(-1), 16);
        continue;
      }
      if (COND.test(ins.op)) {
        const likely = ins.op.endsWith("l") && !/^bc1[tf]$/u.test(ins.op);
        if (path.conditions.length >= depth) {
          if (!likely) execute(pc + 4, path);
          return finish(path, {
            kind: depth === 0 ? "conditional" : "depth-limit",
            at: at(pc),
            text: ins.text,
          });
        }
        const taken = fork(path, { at: at(pc), text: ins.text, taken: true });
        execute(pc + 4, taken); // the delay slot runs when the branch is taken
        walk(Number.parseInt(ins.args.at(-1), 16), taken);
        const fallThrough = fork(path, {
          at: at(pc),
          text: ins.text,
          taken: false,
        });
        if (!likely) execute(pc + 4, fallThrough); // likely branches nullify it otherwise
        return walk(pc + 8, fallThrough);
      }
      if (ins.op === "jal") {
        execute(pc + 4, path);
        path.calls.push(ins.args[0]);
        for (const r of CLOBBERED_BY_CALL) path.regs.delete(r);
        pc += 8;
        continue;
      }
      execute(pc, path);
      pc += 4;
    }
    if (paths.length < limit) finish(path, { kind: "step-limit", at: at(pc) });
  };
  walk(start, {
    regs: new Map([["zero", 0]]),
    writes: [],
    calls: [],
    conditions: [],
    seen: new Set(),
  });
  return { paths, truncated: paths.length >= limit };
};
const trace = (start) => explore(start, 0).paths[0];
// Reachable (mode:phase) states per path, the last constant write of each field.
const states = (explored) => {
  const found = new Map();
  for (const p of explored.paths) {
    const mode = p.writes.filter((w) => w.field === "mode").at(-1);
    const phase = p.writes.filter((w) => w.field === "phase").at(-1);
    const key = phase
      ? `${mode ? (mode.value ?? "?") : "same"}:${phase.value ?? "?"}`
      : `no-state-write/${p.end.kind}`;
    const entry = found.get(key) ?? {
      state: key,
      paths: 0,
      example: p.conditions.map((c) => `${c.at}${c.taken ? "+" : "-"}`),
      anchors: [mode?.at, phase?.at].filter(Boolean),
    };
    entry.paths++;
    found.set(key, entry);
  }
  return [...found.values()];
};

const tables = [];
for (const [pc, ins] of code) {
  if (ins.op !== "jr" || ins.args[0] === "ra") continue;
  const back = [];
  for (let p = pc - 4; p >= pc - 48; p -= 4)
    if (code.has(p)) back.push([p, code.get(p)]);
  const find = (re) => back.find(([, i]) => re.test(i.op));
  const lui =
    find(/^_?lui$/u) ?? back.find(([, i]) => i.text.startsWith("_lui"));
  const lo = back.find(
    ([, i]) =>
      i.op === "addiu" &&
      lui &&
      i.args[0] === lui[1].args[0] &&
      i.args[1] === lui[1].args[0],
  );
  const bound = find(/^sltiu$/u);
  const guard = back.find(
    ([, i]) => i.op === "beq" && bound && i.args[0] === bound[1].args[0],
  );
  if (!lui || !lo || !bound || !guard) {
    tables.push({ jr: at(pc), recognised: false });
    continue;
  }
  const index = bound[1].args[1];
  const bias = back.find(
    ([p, i]) =>
      p < bound[0] &&
      i.op === "addiu" &&
      i.args[0] === index &&
      i.args[1] === index,
  );
  const load = back.find(
    ([p, i]) =>
      p < (bias ?? bound)[0] && /^l[bhw]u?$/u.test(i.op) && i.args[0] === index,
  );
  const base = ((num(lui[1].args[1]) << 16) + num(lo[1].args[2])) >>> 0;
  const count = num(bound[1].args[2]);
  const min = bias ? -num(bias[1].args[2]) : 0;
  const defaultTarget = Number.parseInt(guard[1].args.at(-1), 16);
  const cases = [];
  for (let i = 0; i < count; i++) {
    const target = word(base + 4 * i);
    cases.push({
      value: min + i,
      target: at(target),
      default: target === defaultTarget,
    });
  }
  const outcomes = {};
  for (const target of new Set([
    ...cases.map((c) => c.target),
    at(defaultTarget),
  ])) {
    const explored = explore(Number.parseInt(target, 16));
    outcomes[target] = {
      first_block: trace(Number.parseInt(target, 16)),
      truncated: explored.truncated,
      reachable: states(explored),
    };
  }
  tables.push({
    jr: at(pc),
    recognised: true,
    index: load ? `${load[1].op} ${load[1].args[1]}` : `register ${index}`,
    table: at(base),
    min,
    count,
    default: at(defaultTarget),
    cases: cases
      .filter((c) => !c.default)
      .map(({ value, target }) => ({ value, target })),
    outcomes,
  });
}
await writeFile(outPath, `${JSON.stringify({ procedure, tables }, null, 1)}\n`);
const ok = tables.filter((t) => t.recognised);
console.log(
  `${tables.length} indirect jumps, ${ok.length} tables recognised, ${ok.filter((t) => /0x46\(/u.test(t.index)).length} on +0x46`,
);
