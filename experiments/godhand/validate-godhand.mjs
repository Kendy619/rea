// Initial REA/Ghidra validation of the caller-owned God Hand (USA) boot ELF.
// Usage: node validate-godhand.mjs <SLUS_215.03> <god-hand-decomp checkout> <out.json>
// Env: REPO (built REA checkout), GHIDRA_INSTALL_DIR, optional REA_GHIDRA_SEED_FILE.
// Reads the ELF in place; never copies or modifies it. Oracles are independent of
// Ghidra: the ELF header, raw JAL encodings decoded here, and the decomp's
// objdiff-matched functions (names, sizes) with their splat symbol addresses.
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

const [elfPath, decompRoot, outPath] = process.argv.slice(2);
const repo = process.env.REPO;
const { parseBinaryTarget } = await import(
  `${repo}/dist/application/BinaryTargetResolver.js`
);
const { requireMcpOperationResult } = await import(
  `${repo}/scripts/lib/mcp-verifier-results.mjs`
);
const started = Date.now();
const elapsed = () => Math.round((Date.now() - started) / 1000);
const log = (...a) => console.error(`[${elapsed()}s]`, ...a);

// --- Independent facts --------------------------------------------------
const bytes = await readFile(elfPath);
const sha256 = createHash("sha256").update(bytes).digest("hex");
const versions = JSON.parse(
  await readFile(join(decompRoot, "config/versions.json"), "utf8"),
);
const expectedSha = versions.versions.us.elf_sha256;
const entry = bytes.readUInt32LE(24);
const flags = bytes.readUInt32LE(36);
// One PT_LOAD covers .text; decode every JAL in the loaded text range.
const phoff = bytes.readUInt32LE(28);
const loadOffset = bytes.readUInt32LE(phoff + 4);
const loadVaddr = bytes.readUInt32LE(phoff + 8);
const textSize = Number.parseInt(versions.versions.us.text_size, 16);
const jalTargets = new Map();
for (let off = 0; off < textSize; off += 4) {
  const word = bytes.readUInt32LE(loadOffset + off);
  if (word >>> 26 !== 0x03) continue;
  const pc = loadVaddr + off;
  const target = (((pc + 4) & 0xf0000000) | ((word & 0x03ffffff) << 2)) >>> 0;
  const list = jalTargets.get(target) ?? [];
  list.push(pc);
  jalTargets.set(target, list);
}
const symbols = new Map();
for (const line of (
  await readFile(join(decompRoot, "config/symbol_addrs.txt"), "utf8")
).split("\n")) {
  const m = /^(\S+)\s*=\s*0x([0-9A-Fa-f]+);\s*\/\/.*type:func/u.exec(line);
  if (m) symbols.set(m[1], Number.parseInt(m[2], 16));
}
const report = JSON.parse(
  await readFile(join(decompRoot, "progress/report.json"), "utf8"),
);
const matched = report.units
  .flatMap((unit) => unit.functions ?? [])
  .filter((f) => f.fuzzy_match_percent === 100 && symbols.has(f.name))
  .map((f) => ({
    name: f.name,
    address: symbols.get(f.name),
    size: Number(f.size),
  }));
log("independent:", {
  sha256,
  flags: flags.toString(16),
  entry: entry.toString(16),
  jal_targets: jalTargets.size,
  decomp_funcs: symbols.size,
  matched: matched.length,
});

// --- Public MCP workflow ------------------------------------------------
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [`${repo}/scripts/rea.mjs`, "mcp"],
  env: { ...process.env, REA_LOG_LEVEL: "silent" },
  stderr: "pipe",
});
let stderr = "";
transport.stderr?.on("data", (c) => (stderr = (stderr + c).slice(-20000)));
const client = new Client({ name: "rea-godhand-validation", version: "1" });
await client.connect(transport);
const call = async (name, args = {}, timeout = 1_800_000) => {
  const t0 = Date.now();
  const reply = await client.callTool({ name, arguments: args }, { timeout });
  const value = requireMcpOperationResult(reply, name);
  log(`${name} ${Math.round((Date.now() - t0) / 1000)}s`);
  return value;
};
const out = {
  elf: {
    path: elfPath,
    sha256,
    sha256_matches_decomp: sha256 === expectedSha,
    flags: `0x${flags.toString(16)}`,
    entry: `0x${entry.toString(16)}`,
  },
};
try {
  const resolved = await parseBinaryTarget(elfPath);
  out.target = resolved.ok
    ? { architecture: resolved.value.architecture, mips: resolved.value.mips }
    : { error: String(resolved.error) };

  const openStart = Date.now();
  const opened = await call("open_binary", {
    path: elfPath,
    provider_id: "ghidra",
  });
  out.open_seconds = Math.round((Date.now() - openStart) / 1000);
  out.opened = { architecture: opened.architecture, sha256: opened.sha256 };
  const image = await call("inspect_native_load_image");
  const obs = image.observations ?? image;
  out.loaded = {
    language_id: obs.language_id,
    compiler_spec_id: obs.compiler_spec_id,
    executable_format: obs.executable_format,
    source_sha256: obs.source_files?.[0]?.original_sha256,
  };

  const procedures = await call("list_procedures");
  const byAddress = new Map(
    procedures.map((p) => [Number(BigInt(p.address)), p]),
  );
  out.procedures = procedures.length;
  const decompAddrs = [...new Set(symbols.values())];
  const found = decompAddrs.filter((a) => byAddress.has(a));
  out.decomp_function_starts_recovered = {
    total: decompAddrs.length,
    found: found.length,
    percent: +((100 * found.length) / decompAddrs.length).toFixed(2),
  };
  // Names: STABS-derived names should agree for named decomp functions.
  const named = [...symbols].filter(
    ([n]) => !/^func_[0-9A-Fa-f]{8}$/u.test(n) && !/_[0-9A-F]{6}$/u.test(n),
  );
  const exactName = named.filter(([n, a]) => byAddress.get(a)?.value === n);
  out.names = {
    decomp_named: named.length,
    exact_name_at_address: exactName.length,
    samples: named.slice(0, 8).map(([n, a]) => ({
      decomp: n,
      address: `0x${a.toString(16)}`,
      rea: byAddress.get(a)?.value ?? null,
    })),
  };

  // Entry function: disassembly + pseudocode.
  const entryProc = byAddress.get(entry);
  out.entry_function = entryProc ? entryProc.value : null;
  const entryAsm = await call("procedure_assembly", {
    procedure: `0x${entry.toString(16)}`,
  });
  out.entry_assembly_head = String(entryAsm).split("\n").slice(0, 12);

  // Matched functions: body size vs objdiff size, deterministic sample.
  const sample = matched
    .filter((f) => f.size >= 64)
    .sort((a, b) => a.address - b.address)
    .filter((_, i, arr) => i % Math.max(1, Math.floor(arr.length / 25)) === 0)
    .slice(0, 25);
  out.matched_sample = [];
  for (const f of sample) {
    if (!byAddress.has(f.address)) {
      out.matched_sample.push({
        name: f.name,
        address: `0x${f.address.toString(16)}`,
        objdiff_size: f.size,
        ghidra_bytes: null,
        missing_in_ghidra: true,
      });
      continue;
    }
    const dossier = await call(
      "analyze_function",
      { procedure: `0x${f.address.toString(16)}` },
      600_000,
    );
    out.matched_sample.push({
      name: f.name,
      address: `0x${f.address.toString(16)}`,
      objdiff_size: f.size,
      ghidra_bytes: dossier.procedure?.body?.total_bytes ?? null,
      ghidra_name: dossier.procedure?.name,
      pseudocode_lines: (dossier.pseudocode ?? "").split("\n").length,
    });
  }
  out.matched_missing_in_ghidra = matched.filter(
    (f) => !byAddress.has(f.address),
  ).length;
  const agree = out.matched_sample.filter(
    (s) => s.ghidra_bytes === s.objdiff_size,
  ).length;
  out.matched_size_agreement = `${agree}/${out.matched_sample.length}`;

  // Cross-references: callers vs raw JAL sites for the most-called matched functions.
  const hot = matched
    .filter((f) => byAddress.has(f.address))
    .map((f) => ({ ...f, jal: jalTargets.get(f.address)?.length ?? 0 }))
    .sort((a, b) => b.jal - a.jal)
    .slice(0, 5);
  out.xrefs = [];
  for (const f of hot) {
    const xrefs = await call("xrefs", {
      address: `0x${f.address.toString(16)}`,
    });
    const sites = new Set(jalTargets.get(f.address));
    const reaSites = xrefs
      .filter((x) => x.startsWith("0x"))
      .map((x) => Number(BigInt(x)));
    out.xrefs.push({
      name: f.name,
      raw_jal_sites: sites.size,
      rea_xrefs: reaSites.length,
      jal_sites_in_rea: reaSites.filter((s) => sites.has(s)).length,
    });
  }
  const pseudo = await call(
    "analyze_function",
    { procedure: `0x${hot[0].address.toString(16)}` },
    600_000,
  );
  out.hot_function_pseudocode_head = (pseudo.pseudocode ?? "")
    .split("\n")
    .slice(0, 25);

  const snapshot = join(
    dirname(resolve(outPath)),
    `godhand-${Date.now()}.snapshot.json`,
  );
  const saved = await call("close_binary", { snapshot_path: snapshot });
  out.snapshot = { evidence_records: saved.evidence_records };
  const reopenStart = Date.now();
  await call("open_binary", {
    path: elfPath,
    provider_id: "ghidra",
    snapshot_path: snapshot,
  });
  out.snapshot.reopen_seconds = Math.round((Date.now() - reopenStart) / 1000);
  const again = await call("list_procedures");
  out.snapshot.same_inventory = again.length === procedures.length;
  await call("close_binary");
  out.status = "completed";
} catch (cause) {
  out.status = "failed";
  out.error = String(cause?.stack ?? cause).slice(0, 4000);
  out.mcp_stderr_tail = stderr.slice(-4000);
} finally {
  out.total_seconds = elapsed();
  await client.close().catch(() => {});
  await transport.close().catch(() => {});
  await writeFile(outPath, `${JSON.stringify(out, null, 2)}\n`);
  log("done", out.status);
}
