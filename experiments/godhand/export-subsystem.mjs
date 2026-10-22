// Export a God Hand subsystem through REA MCP in one session, for to-reversa-evidence.mjs.
// Usage: node export-subsystem.mjs <SLUS_215.03> <out answers.json>
// Env: REPO (built REA checkout), GHIDRA_INSTALL_DIR, optional REA_GHIDRA_SEED_FILE.
//
// Roots: every cEm00 mode-table entry (read from the ELF), the enemy tick and
// reaction selectors, and procedures whose names match ROOT_NAMES. The set is
// then closed over one level of direct callees. For each function the answer file
// holds info-, instructions- and incoming- answers plus batch_decompile chunks,
// in the shape ask-rea.mjs writes.
import { readFile, writeFile } from "node:fs/promises";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

const [elfPath, outPath] = process.argv.slice(2);
if (!outPath) throw new Error("usage: export-subsystem.mjs <elf> <out.json>");
const repo = process.env.REPO;
const { requireMcpOperationResult } = await import(
  `${repo}/scripts/lib/mcp-verifier-results.mjs`
);

const ROOT_ADDRESSES = [
  0x208be0, 0x20a178, 0x20dcf0, 0x20e480, 0x20ef08, 0x20da18, 0x20cac8,
  0x20d398, 0x20cd00, 0x20d140, 0x20f3c0, 0x24c0f0, 0x25e600,
];
const ROOT_NAMES =
  "^(cEm00_|cEmManage_|cEmWrap_|cEmSetParam_|cDamage|DamageObj_|DmgObj_|cCollision|cHeatSys_|moveMotion$|setMotionInfo$|SetMotionStep$|Motion)";
const TABLES = [
  [0x3bf1c8, 174],
  [0x3bf738, 40],
  [0x3bf878, 5],
];
const DECOMPILE_CHUNK = 40;

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

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [`${repo}/scripts/rea.mjs`, "mcp"],
  env: { ...process.env, REA_LOG_LEVEL: "silent" },
  stderr: "pipe",
});
const client = new Client({ name: "rea-godhand-export", version: "1" });
await client.connect(transport);
let bytes = 0;
const ask = async (tool, args) => {
  const reply = await client.callTool(
    { name: tool, arguments: args },
    { timeout: 1_800_000 },
  );
  bytes += (reply.content ?? []).reduce(
    (n, part) => n + Buffer.byteLength(part.text ?? ""),
    0,
  );
  try {
    return { ok: true, value: requireMcpOperationResult(reply, tool) };
  } catch (cause) {
    return { ok: false, error: String(cause?.message ?? cause).slice(0, 1500) };
  }
};

const hex = (n) => `0x${n.toString(16)}`;
const out = { elf: elfPath, answers: [], phases: {} };
const started = Date.now();
try {
  await ask("open_binary", { path: elfPath, provider_id: "ghidra" });
  const roots = new Set(ROOT_ADDRESSES);
  for (const [base, count] of TABLES)
    for (let i = 0; i < count; i++) roots.add(word(base + 8 * i + 4));
  const named = await ask("search_procedures", {
    pattern: ROOT_NAMES,
    mode: "regex",
  });
  if (!named.ok) throw new Error(named.error);
  for (const p of named.value) roots.add(Number(BigInt(p.address)));
  const all = new Set(roots);
  for (const root of roots) {
    const callees = await ask("procedure_callees", { procedure: hex(root) });
    const direct = callees.ok
      ? callees.value.filter((a) => a.startsWith("0x"))
      : [];
    for (const a of direct) all.add(Number(BigInt(a)));
  }
  const list = [...all].sort((a, b) => a - b).map(hex);
  out.roots = roots.size;
  out.functions = list.length;
  console.error(`roots ${roots.size}, with callees ${list.length}`);
  for (let i = 0; i < list.length; i += DECOMPILE_CHUNK) {
    const chunk = list.slice(i, i + DECOMPILE_CHUNK);
    out.answers.push({
      id: `decompile-${i}`,
      tool: "batch_decompile",
      args: { addresses: chunk },
      answer: await ask("batch_decompile", { addresses: chunk }),
    });
  }
  for (const f of list) {
    out.answers.push({
      id: `info-${f}`,
      tool: "procedure_info",
      answer: await ask("procedure_info", { procedure: f }),
    });
    out.answers.push({
      id: `instructions-${f}`,
      tool: "read_function_instructions",
      answer: await ask("read_function_instructions", { procedure: f }),
    });
    out.answers.push({
      id: `incoming-${f}`,
      tool: "procedure_references",
      answer: await ask("procedure_references", {
        procedure: f,
        direction: "incoming",
      }),
    });
  }
  await ask("close_binary", {});
  out.status = "completed";
} catch (cause) {
  out.status = "failed";
  out.error = String(cause?.stack ?? cause).slice(0, 4000);
} finally {
  out.total_ms = Date.now() - started;
  out.response_bytes = bytes;
  await writeFile(outPath, `${JSON.stringify(out)}\n`);
  await client.close().catch(() => {});
  await transport.close().catch(() => {});
  console.error(out.status, out.total_ms, "ms", bytes, "bytes");
}
