// Tag cEm00 behaviour-table entries by named callees (output of behaviour-features.mjs).
// Usage: node classify-behaviours.mjs <features.json>
import { readFile } from "node:fs/promises";
const rows = JSON.parse(await readFile(process.argv[2], "utf8"));
const RULES = [
  ["grab", (n) => n.has("cEmManage_CkPlCatched")],
  ["sorry", (n) => n.has("cEmManage_CkPlSorry")],
  ["throw", (n) => n.has("EmThrower_throwHeld")],
  ["heat", (n) => n.has("cHeatSys_AddHeatGage")],
  ["camera", (n) => [...n].some((x) => /Camera/u.test(x))],
  ["line-of-sight", (n) => n.has("ChkLine")],
  [
    "turn",
    (n) =>
      ["cGameObj_SetTgtTurn", "Turn_dest", "Adjust_theta"].some((x) =>
        n.has(x),
      ),
  ],
  [
    "random",
    (n) => ["irand", "fRand1_1", "fRand0_1", "Rnd"].some((x) => n.has(x)),
  ],
  ["difficulty", (n) => n.has("cCoreSave_getGameLevel")],
  [
    "attack",
    (n) => [...n].some((x) => /DamageColl|startHitUnitAim|BigHitEff/u.test(x)),
  ],
];
const tags = (row) =>
  RULES.filter(([, test]) => test(new Set(row.named))).map(([t]) => t);
// Table split observed in the mode dispatchers (+0x2f5 bounds 0xad and 4).
const GROUPS = [
  ["mode0/3 AI", 0, 174],
  ["mode1 damage", 174, 214],
  ["mode2", 214, 219],
];
for (const [group, start, end] of GROUPS) {
  const part = rows.slice(start, end);
  const count = {};
  for (const row of part)
    for (const t of tags(row)) count[t] = (count[t] ?? 0) + 1;
  console.log(group, `${part.length} decompiled`, JSON.stringify(count));
  for (const row of part) {
    const t = tags(row).filter((x) =>
      ["grab", "sorry", "throw", "heat", "camera", "attack"].includes(x),
    );
    if (t.length > 0)
      console.log(
        `  ${row.index - start}\t${row.address}\t${row.name}\t${t.join(",")}`,
      );
  }
}
