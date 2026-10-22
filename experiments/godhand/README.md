# God Hand (SLUS_215.03) through REA

Fork-only lab for the [PS2 Emotion Engine profile](../../docs/ghidra-ps2.md).
It checks REA's static analysis of a commercial PS2 executable against the
independent [god-hand-decomp](https://github.com/LucasPicoli/god-hand-decomp)
project, then uses REA through MCP the way an agent would to study game
systems.

No game data is stored here. Every script reads a caller-owned boot ELF in
place and writes results under a caller-chosen directory; keep those outside
the repository (`results/` is ignored).

## Inputs

- The US boot ELF `SLUS_215.03` from your own disc. Its SHA-256 must equal
  `versions.us.elf_sha256` in the decomp's `config/versions.json`.
- A god-hand-decomp checkout (`config/symbol_addrs.txt`,
  `progress/report.json`, `src/`).
- A built REA checkout (`npm run build:cached`) on Linux x64 with
  `GHIDRA_INSTALL_DIR` pointing at Ghidra 12.1.3 plus a compatible
  ghidra-emotionengine-reloaded with precompiled `r5900.sla`
  ([setup](../../docs/ghidra-ps2.md#bring-your-own-compatible-extension)).

The MCP scripts import `@modelcontextprotocol/client` and REA's verifier
helpers, so run them from a location that resolves the REA checkout's
`node_modules`, with `REPO` set to that checkout.

## Scripts

| Script                    | Purpose                                                                                                                                                                    |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `seeds.py`                | Convert decomp `type:func` symbols into an `REA_GHIDRA_SEED_FILE` (`0x<addr>\tfunction\t<name>`).                                                                          |
| `validate-godhand.mjs`    | Identity, function-start recovery, names, objdiff sizes and raw-JAL call sites versus REA through MCP, then snapshot reopen.                                               |
| `investigate-godhand.mjs` | One MCP session asking fixed questions about damage, collision, enemy and animation code; records time and response bytes per call.                                        |
| `ask-rea.mjs`             | Run a JSON list of follow-up MCP queries in one session (optionally resolving returned addresses to their procedures).                                                     |
| `behaviour-features.mjs`  | Named callees per decompiled entry from an `ask-rea.mjs` answer file.                                                                                                      |
| `classify-behaviours.mjs` | Tag the enemy behavior-table entries (grab, throw, heat, camera, attack...) per mode table.                                                                                |
| `enemy-seeds.py`          | Decomp seeds plus labels for the cEm00 mode tables and position names (`cEm00_m<mode>_s<sub>`) for their unnamed entries; refuses a different table layout.                |
| `verify-enemy-seeds.mjs`  | Assert through MCP that those names and labels are applied and that the enemy tick indexes the mode group by `+0x2f4`.                                                     |
| `state-transitions.mjs`   | Static `mode:phase` transition graph of the 219 table entries from REA pseudocode and from `sb` instructions in the ELF, cross-checked and bounded by table sizes.         |
| `switch-cases.mjs`        | Tabulate pseudocode `switch` statements by case value (state writes, constants, calls, gotos, enclosing conditions).                                                       |
| `to-reversa-evidence.mjs` | Convert an `ask-rea.mjs` export (`round7-questions.json`) into the reversa project's `god-hand-ghidra-focused-v1` evidence folder, checking every listing against the ELF. |
| `decomp_calls.py`         | Independent oracle: direct calls in the decomp's matched C, from source and `symbol_addrs.txt` only.                                                                       |
| `compare-calls.mjs`       | Compare REA `procedure_callees` with that oracle.                                                                                                                          |

```bash
python3 seeds.py "$DECOMP/config/symbol_addrs.txt" "$OUT/godhand-seeds.tsv"
# or, with the enemy table names:
python3 enemy-seeds.py "$ELF" "$DECOMP/config/symbol_addrs.txt" "$OUT/godhand-seeds.tsv"
export REA_GHIDRA_SEED_FILE="$OUT/godhand-seeds.tsv"   # omit for an unseeded run
node validate-godhand.mjs "$ELF" "$DECOMP" "$OUT/validation.json"
node investigate-godhand.mjs "$ELF" "$OUT/investigation"
node ask-rea.mjs "$ELF" round2-questions.json "$OUT/investigation/round2.json"  # also round3..5
node behaviour-features.mjs "$OUT/investigation/round3.json" > "$OUT/features.json"
node classify-behaviours.mjs "$OUT/features.json"
node verify-enemy-seeds.mjs "$ELF" "$OUT/godhand-seeds.tsv" "$OUT/enemy-seeds-check.json"
python3 decomp_calls.py "$DECOMP" <function names...> > "$OUT/decomp-calls.json"
node compare-calls.mjs "$OUT/investigation" "$OUT/decomp-calls.json" "$DECOMP/config/symbol_addrs.txt"
```

## Agent setup

Register REA's MCP server in WSL/Linux with `REA_ANALYSIS_PROVIDER=ghidra`,
`GHIDRA_INSTALL_DIR` and `REA_GHIDRA_SEED_FILE`, then call `open_binary` with
the absolute ELF path and `provider_id: "ghidra"`. The first query runs Ghidra
auto-analysis (about 2.5 minutes for this ELF); later queries reuse the open
session. Reopening a snapshot re-runs the analysis.

## Results

See [RESULTS.md](RESULTS.md).
