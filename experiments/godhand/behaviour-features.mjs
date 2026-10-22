// Summarize decompiled behaviour-table entries: named callees and string-like features.
// Usage: node behaviour-features.mjs <round3.json> <table-addresses.json?>
import { readFile } from "node:fs/promises";
const r = JSON.parse(await readFile(process.argv[2], "utf8"));
const items = r.answers
  .filter((a) => a.tool === "batch_decompile")
  .flatMap((a) => a.answer.value.items);
const rows = items.map((it, index) => {
  const code = it.pseudocode ?? "";
  const calls = [...code.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu)].map(
    (m) => m[1],
  );
  const named = [
    ...new Set(
      calls.filter(
        (c) =>
          !/^(FUN_|func_|if|while|for|switch|return|sizeof|SQRT|_[a-z]|code|CONCAT)/u.test(
            c,
          ) && c !== it.procedure?.name,
      ),
    ),
  ];
  const placeholders = new Set(calls.filter((c) => /^(FUN_|func_)/u.test(c)))
    .size;
  return {
    index,
    address: it.procedure?.address,
    name: it.procedure?.name,
    lines: code.split("\n").length,
    named,
    placeholders,
  };
});
console.log(JSON.stringify(rows));
