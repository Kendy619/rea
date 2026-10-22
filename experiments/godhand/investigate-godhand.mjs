// Agent-style investigation of God Hand subsystems through REA's public MCP server.
// Usage: node investigate-godhand.mjs <SLUS_215.03> <out-dir>
// Env: REPO (built REA checkout), GHIDRA_INSTALL_DIR, optional REA_GHIDRA_SEED_FILE.
// Opens the caller-owned ELF once, asks a fixed set of questions per subsystem and
// writes each raw MCP answer plus a cost ledger (elapsed time, response bytes).
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

const [elfPath, outDir] = process.argv.slice(2);
if (!elfPath || !outDir)
  throw new Error("usage: investigate-godhand.mjs <elf> <out-dir>");
const repo = process.env.REPO;
const { requireMcpOperationResult } = await import(
  `${repo}/scripts/lib/mcp-verifier-results.mjs`
);
await mkdir(outDir, { recursive: true });

// Each subsystem: entry functions named by god-hand-decomp, decompiled together, plus
// callers/callees per entry and optional call-graph walks.
const SUBSYSTEMS = {
  damage: {
    search: "^(cDamage(Manage|Unit|Give|Take)_|DmgObj_|DamageObj_)",
    decompile: [
      "cDamageManage_CreateDamageGive",
      "cDamageManage_CreateDamageTake",
      "cDamageManage_ReleaseDamageGive",
      "cDamageManage_CkHitStop",
      "cDamageUnit_AddDamageCollSphere",
      "cDamageUnit_AddDamageCollCylinder",
      "cDamageUnit_SetDamageCollActive",
      "cDamageUnit_SetDamageCollOffset",
      "cDamageGive_SetDmgGiveHitVec",
    ],
    graphs: [
      ["cDamageManage_CreateDamageGive", "backward"],
      ["cDamageManage_CkHitStop", "backward"],
    ],
  },
  collision: {
    search: "^(cCollision|ChkColl|HitBox_|cArea_HitCheck)",
    decompile: [
      "cCollisionSolidManage_CreateUnit",
      "cCollisionSolidManage_CreateSphere",
      "cCollisionSolidManage_ChkHit",
      "cCollisionSolidManage_SetActive",
      "cCollisionSolidManage_SetPriority",
      "HitBox_containsPoint",
    ],
    graphs: [["cCollisionSolidManage_ChkHit", "forward"]],
  },
  enemy: {
    search: "^cEm00_",
    decompile: [
      "cEm00_idleChooseNext",
      "cEm00_hitReaction",
      "cEm00_stepHitStun",
      "cEm00_ckDown",
      "cEm00_stepChargePlayer",
    ],
    graphs: [["cEm00_hitReaction", "backward"]],
  },
  animation: {
    search: "(Motion|Anim)",
    decompile: [
      "setMotionInfo",
      "moveMotion",
      "SetMotionStep",
      "MotionGetParam",
      "MotionIsHaveParam",
    ],
    graphs: [["setMotionInfo", "backward"]],
  },
};

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [`${repo}/scripts/rea.mjs`, "mcp"],
  env: { ...process.env, REA_LOG_LEVEL: "silent" },
  stderr: "pipe",
});
let stderr = "";
transport.stderr?.on("data", (c) => (stderr = (stderr + c).slice(-20000)));
const client = new Client({ name: "rea-godhand-investigation", version: "1" });
await client.connect(transport);

const ledger = [];
const call = async (name, args = {}, timeout = 1_800_000) => {
  const t0 = Date.now();
  const reply = await client.callTool({ name, arguments: args }, { timeout });
  const ms = Date.now() - t0;
  // Bytes of the text an agent would receive; tokens are only estimated from it.
  const bytes = (reply.content ?? []).reduce(
    (n, part) => n + Buffer.byteLength(part.text ?? ""),
    0,
  );
  ledger.push({
    tool: name,
    args,
    ms,
    response_bytes: bytes,
    is_error: reply.isError === true,
  });
  console.error(
    `${name} ${JSON.stringify(args).slice(0, 80)} ${ms}ms ${bytes}B`,
  );
  return requireMcpOperationResult(reply, name);
};
const save = (file, value) =>
  writeFile(join(outDir, file), `${JSON.stringify(value, null, 2)}\n`);
const attempt = async (name, args) => {
  try {
    return { ok: true, value: await call(name, args) };
  } catch (cause) {
    return { ok: false, error: String(cause?.message ?? cause).slice(0, 2000) };
  }
};

const started = Date.now();
const summary = {
  elf: elfPath,
  seeds: process.env.REA_GHIDRA_SEED_FILE ?? null,
  subsystems: {},
};
try {
  const t0 = Date.now();
  await call("open_binary", { path: elfPath, provider_id: "ghidra" });
  summary.open_ms = Date.now() - t0;
  summary.overview = await call("binary_overview");
  for (const [id, spec] of Object.entries(SUBSYSTEMS)) {
    const found = await attempt("search_procedures", {
      pattern: spec.search,
      mode: "regex",
      detail: "summary",
    });
    const decompiled = await attempt("batch_decompile", {
      addresses: spec.decompile,
    });
    const edges = {};
    for (const name of spec.decompile) {
      edges[name] = {
        callers: await attempt("procedure_callers", { procedure: name }),
        callees: await attempt("procedure_callees", { procedure: name }),
      };
    }
    const graphs = {};
    for (const [name, direction] of spec.graphs) {
      graphs[`${name}:${direction}`] = await attempt("get_call_graph", {
        address: name,
        direction,
      });
    }
    await save(`${id}.json`, { search: found, decompiled, edges, graphs });
    summary.subsystems[id] = {
      search_ok: found.ok,
      decompile_ok: decompiled.ok,
    };
  }
  await call("close_binary");
  summary.status = "completed";
} catch (cause) {
  summary.status = "failed";
  summary.error = String(cause?.stack ?? cause).slice(0, 4000);
  summary.mcp_stderr_tail = stderr.slice(-4000);
} finally {
  summary.total_ms = Date.now() - started;
  summary.ledger = ledger;
  await save("summary.json", summary);
  await client.close().catch(() => {});
  await transport.close().catch(() => {});
}
