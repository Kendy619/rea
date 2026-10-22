// Compare REA procedure_callees (from investigate-godhand.mjs output) with direct
// calls in god-hand-decomp matched C (decomp_calls.py output).
// Usage: node compare-calls.mjs <investigation-dir> <decomp-calls.json> <symbol_addrs.txt>
import { readFile } from "node:fs/promises";
import { join } from "node:path";
const [dir, callsPath, symbolsPath] = process.argv.slice(2);
const oracle = JSON.parse(await readFile(callsPath, "utf8"));
const byName = new Map();
for (const line of (await readFile(symbolsPath, "utf8")).split("\n")) {
  const m = /^(\S+)\s*=\s*0x([0-9A-Fa-f]+);\s*\/\/.*type:func/u.exec(line);
  if (m && !byName.has(m[1])) byName.set(m[1], Number.parseInt(m[2], 16));
}
const address = (n) =>
  byName.get(n) ??
  (/^func_[0-9A-Fa-f]{8}$/u.test(n)
    ? Number.parseInt(n.slice(5), 16)
    : undefined);
{
}
const rows = [];
for (const id of ["damage", "collision", "enemy", "animation"]) {
  const data = JSON.parse(await readFile(join(dir, `${id}.json`), "utf8"));
  for (const [name, edge] of Object.entries(data.edges)) {
    const c = oracle[name];
    if (!c || !edge.callees.ok) {
      rows.push({ id, name, oracle: c ? "yes" : "no C source" });
      continue;
    }
    const rea = new Set(edge.callees.value.map((a) => Number(BigInt(a))));
    const expected = c.calls.map((n) => [n, address(n)]);
    const missing = expected.filter(([, a]) => !rea.has(a)).map(([n]) => n);
    const extra = [...rea]
      .filter((a) => !expected.some(([, e]) => e === a))
      .map((a) => `0x${a.toString(16)}`);
    rows.push({
      id,
      name,
      c_calls: expected.length,
      rea_callees: rea.size,
      matched: expected.length - missing.length,
      missing,
      extra,
    });
  }
}
console.log(JSON.stringify(rows, null, 1));
