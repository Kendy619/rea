// Run a caller-authored list of REA MCP queries in one session, as an agent would.
// Usage: node ask-rea.mjs <elf> <questions.json> <out.json>
// questions.json: [{"id": "...", "why": "...", "tool": "xrefs", "args": {...}}, ...]
// "containing": true resolves each returned address (first 40) to its procedure.
// Env: REPO (built REA checkout), GHIDRA_INSTALL_DIR, optional REA_GHIDRA_SEED_FILE.
// Each answer keeps its parsed value (or error) plus elapsed time and response bytes.
import { readFile, writeFile } from "node:fs/promises";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

const [elfPath, questionsPath, outPath] = process.argv.slice(2);
if (!outPath)
  throw new Error("usage: ask-rea.mjs <elf> <questions.json> <out.json>");
const repo = process.env.REPO;
const { requireMcpOperationResult } = await import(
  `${repo}/scripts/lib/mcp-verifier-results.mjs`
);
const questions = JSON.parse(await readFile(questionsPath, "utf8"));

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [`${repo}/scripts/rea.mjs`, "mcp"],
  env: { ...process.env, REA_LOG_LEVEL: "silent" },
  stderr: "pipe",
});
const client = new Client({ name: "rea-ask", version: "1" });
await client.connect(transport);

const ask = async (tool, args) => {
  const started = Date.now();
  const reply = await client.callTool(
    { name: tool, arguments: args },
    { timeout: 1_800_000 },
  );
  const cost = {
    ms: Date.now() - started,
    response_bytes: (reply.content ?? []).reduce(
      (n, part) => n + Buffer.byteLength(part.text ?? ""),
      0,
    ),
  };
  console.error(`${tool} ${cost.ms}ms ${cost.response_bytes}B`);
  try {
    return { ok: true, ...cost, value: requireMcpOperationResult(reply, tool) };
  } catch (cause) {
    return {
      ok: false,
      ...cost,
      error: String(cause?.message ?? cause).slice(0, 1500),
    };
  }
};

const out = { elf: elfPath, answers: [] };
const started = Date.now();
try {
  out.open = await ask("open_binary", { path: elfPath, provider_id: "ghidra" });
  for (const q of questions) {
    const answer = await ask(q.tool, q.args);
    if (q.containing && answer.ok && Array.isArray(answer.value)) {
      answer.containing = {};
      for (const address of answer.value
        .filter((a) => a.startsWith("0x"))
        .slice(0, 40)) {
        const r = await ask("resolve_containing_procedure", { address });
        answer.containing[address] = r.ok ? r.value : { error: r.error };
      }
    }
    out.answers.push({ ...q, answer });
  }
  await ask("close_binary", {});
  out.status = "completed";
} catch (cause) {
  out.status = "failed";
  out.error = String(cause?.stack ?? cause).slice(0, 4000);
} finally {
  out.total_ms = Date.now() - started;
  await writeFile(outPath, `${JSON.stringify(out, null, 2)}\n`);
  await client.close().catch(() => {});
  await transport.close().catch(() => {});
}
