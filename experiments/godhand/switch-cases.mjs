// Tabulate the switch statements of REA pseudocode by case value.
// Usage: node switch-cases.mjs <ask-rea answers.json> <procedure address> <selector regex> <out.json>
// Example selector for God Hand's reaction id: "\\+ 0x46\\)"
//
// For every `switch (...)` whose expression matches the selector, each group of
// consecutive case labels gets the effects found in its body up to the next label
// at the same depth: constant writes to +0x2f4/+0x2f5 (enemy mode/phase), other
// constant field writes, float/integer locals assigned from constants, named calls
// and unresolved gotos. Bodies are read as text: gotos are reported, not followed,
// and the pseudocode can omit floating-point call arguments.
import { readFile, writeFile } from "node:fs/promises";

const [answersPath, procedure, selector, outPath] = process.argv.slice(2);
if (!outPath)
  throw new Error(
    "usage: switch-cases.mjs <answers.json> <procedure> <selector regex> <out.json>",
  );
const data = JSON.parse(await readFile(answersPath, "utf8"));
const item = data.answers
  .filter((a) => a.tool === "batch_decompile")
  .flatMap((a) => a.answer.value.items)
  .find((i) => i.procedure?.address === procedure || i.address === procedure);
if (!item) throw new Error(`no decompiled body for ${procedure}`);
const lines = item.pseudocode.split("\n");
const select = new RegExp(selector, "u");

const effectsOf = (body) => {
  const effects = { state: [], fields: [], locals: [], calls: [], gotos: [] };
  for (const raw of body) {
    const line = raw.trim();
    let m = /\+ (0x2f[45])\) = ([^;]+);/u.exec(line);
    if (m) effects.state.push(`${m[1] === "0x2f4" ? "mode" : "phase"}=${m[2]}`);
    else if (
      (m =
        /\*\([^)]*\)\(\w+ \+ (0x[0-9a-f]+)\) = (-?(?:0x[0-9a-f]+|\d+(?:\.\d+)?));/u.exec(
          line,
        ))
    )
      effects.fields.push(`+${m[1]}=${m[2]}`);
    else if ((m = /^(\w+) = (-?\d+(?:\.\d+)?|0x[0-9a-f]+);$/u.exec(line)))
      effects.locals.push(`${m[1]}=${m[2]}`);
    for (const c of line.matchAll(/\b([A-Za-z_]\w*)\s*\(/gu))
      if (
        !/^(if|while|for|switch|return|SQRT|code)$/u.test(c[1]) &&
        !c[1].startsWith("_")
      )
        effects.calls.push(c[1]);
    if ((m = /goto (\w+);/u.exec(line))) effects.gotos.push(m[1]);
  }
  for (const key of Object.keys(effects))
    effects[key] = [...new Set(effects[key])];
  return effects;
};

const switches = [];
for (let i = 0; i < lines.length; i++) {
  const head = /^(\s*)switch\((.*)\) \{$/u.exec(lines[i]);
  if (!head || !select.test(head[2])) continue;
  // Find the matching closing brace.
  let depth = 0;
  let end = i;
  for (let j = i; j < lines.length; j++) {
    depth +=
      (lines[j].match(/\{/gu) ?? []).length -
      (lines[j].match(/\}/gu) ?? []).length;
    if (depth === 0) {
      end = j;
      break;
    }
  }
  const labelIndent = head[1].length; // Ghidra indents case labels like the switch
  const groups = [];
  let current = null;
  for (let j = i + 1; j < end; j++) {
    const label = /^(\s*)(case (-?(?:0x[0-9a-f]+|\d+))|default):$/u.exec(
      lines[j],
    );
    if (label && label[1].length === labelIndent) {
      if (!current || current.body.length > 0)
        groups.push((current = { cases: [], body: [] }));
      current.cases.push(label[3] === undefined ? "default" : Number(label[3]));
    } else if (current) current.body.push(lines[j]);
  }
  // Enclosing context: the nearest lines at each smaller indentation going up,
  // keeping conditions, loop heads, case labels and else branches.
  const context = [];
  let indent = head[1].length;
  for (let j = i - 1; j >= 0 && indent > 2; j--) {
    const m = /^(\s*)(\S.*)$/u.exec(lines[j]);
    if (!m || m[1].length >= indent) continue;
    indent = m[1].length;
    if (/^(if|else|while|do|for|case|default|switch|\} else)/u.test(m[2]))
      context.unshift(`${j + 1}: ${m[2]}`);
  }
  switches.push({
    line: i + 1,
    context,
    expression: head[2],
    groups: groups.map((g) => ({ cases: g.cases, ...effectsOf(g.body) })),
  });
}
await writeFile(
  outPath,
  `${JSON.stringify({ procedure, selector, lines: lines.length, switches }, null, 1)}\n`,
);
console.log(
  `${switches.length} switches, ${switches.reduce((n, s) => n + s.groups.length, 0)} case groups`,
);
