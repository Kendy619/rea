// Check through REA's MCP server that enemy-seeds.py output is applied as expected.
// Usage: node verify-enemy-seeds.mjs <SLUS_215.03> <enemy-seeds.tsv> <out.json>
// Env: REPO (built REA checkout), GHIDRA_INSTALL_DIR; REA_GHIDRA_SEED_FILE must be
// the same absolute seed file. Exits non-zero when an assertion fails.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

const [elfPath, seedPath, outPath] = process.argv.slice(2);
if (!outPath)
  throw new Error("usage: verify-enemy-seeds.mjs <elf> <seeds.tsv> <out.json>");
assert.equal(
  process.env.REA_GHIDRA_SEED_FILE,
  resolve(seedPath),
  "REA_GHIDRA_SEED_FILE must be the seed file",
);
const repo = process.env.REPO;
const { requireMcpOperationResult } = await import(
  `${repo}/scripts/lib/mcp-verifier-results.mjs`
);

// Expectations come from the seed file alone.
const functions = new Map();
const labels = new Map();
for (const line of (await readFile(seedPath, "utf8")).split("\n")) {
  const [address, kind, name] = line.split("\t");
  if (!address?.startsWith("0x")) continue;
  (kind === "label" ? labels : functions).set(BigInt(address), name);
}
const tableNames = [...functions].filter(([, n]) =>
  /^cEm00_(m\d_s\d{3}|dispatchMode\d)$/u.test(n),
);

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [`${repo}/scripts/rea.mjs`, "mcp"],
  env: { ...process.env, REA_LOG_LEVEL: "silent" },
  stderr: "pipe",
});
const client = new Client({ name: "rea-enemy-seeds", version: "1" });
await client.connect(transport);
const call = async (name, args = {}) =>
  requireMcpOperationResult(
    await client.callTool({ name, arguments: args }, { timeout: 1_800_000 }),
    name,
  );

const out = { checks: {} };
const started = Date.now();
try {
  await call("open_binary", { path: elfPath, provider_id: "ghidra" });
  const procedures = await call("list_procedures");
  const byAddress = new Map(
    procedures.map((p) => [BigInt(p.address), p.value]),
  );
  const wrong = tableNames.filter(([a, n]) => byAddress.get(a) !== n);
  out.checks.table_function_names = {
    expected: tableNames.length,
    wrong: wrong.map(([a, n]) => [
      `0x${a.toString(16)}`,
      n,
      byAddress.get(a) ?? null,
    ]),
  };
  assert.equal(
    wrong.length,
    0,
    "table function names missing in list_procedures",
  );
  // Other seeds are the decomp's own; report any that Ghidra did not keep.
  const table = new Set(tableNames.map(([a]) => a));
  const changed = [...functions].filter(
    ([a, n]) => !table.has(a) && byAddress.get(a) !== n,
  );
  out.checks.other_seed_names = {
    expected: functions.size - tableNames.length,
    differing: changed.map(([a, n]) => [
      `0x${a.toString(16)}`,
      n,
      byAddress.get(a) ?? null,
    ]),
  };

  out.checks.labels = {};
  for (const [address, name] of labels) {
    const observed = await call("address_name", {
      address: `0x${address.toString(16)}`,
    });
    out.checks.labels[name] = observed;
    assert.match(
      JSON.stringify(observed),
      new RegExp(name, "u"),
      `label ${name} not applied`,
    );
  }

  const modes = await call("search_procedures", {
    pattern: "^cEm00_m1_s",
    mode: "regex",
  });
  out.checks.mode1_search = Array.isArray(modes) ? modes.length : modes;

  const decompiled = await call("batch_decompile", {
    addresses: ["func_00208BE0", "cEm00_dispatchMode1"],
  });
  const [tick, mode1] = decompiled.items.map((i) => i.pseudocode ?? "");
  out.checks.tick_uses_mode_group =
    /cEm00_ModeDispatchers/u.test(tick) && /0x2f4/u.test(tick);
  out.checks.mode1_uses_table =
    /cEm00_Mode1Behaviours/u.test(mode1) && /0x27 < /u.test(mode1);
  out.tick_excerpt = tick
    .split("\n")
    .filter((l) => /cEm00_ModeDispatchers|0x2f4|CkHitStop|ChkHit/u.test(l))
    .slice(0, 20);
  assert.ok(
    out.checks.tick_uses_mode_group,
    "enemy tick does not index cEm00_ModeDispatchers by +0x2f4",
  );
  assert.ok(
    out.checks.mode1_uses_table,
    "mode 1 dispatcher does not bound and index cEm00_Mode1Behaviours",
  );
  await call("close_binary");
  out.status = "passed";
} catch (cause) {
  out.status = "failed";
  out.error = String(cause?.stack ?? cause).slice(0, 3000);
  process.exitCode = 1;
} finally {
  out.total_ms = Date.now() - started;
  await writeFile(outPath, `${JSON.stringify(out, null, 2)}\n`);
  await client.close().catch(() => {});
  await transport.close().catch(() => {});
  console.error(out.status, out.total_ms, "ms");
}
