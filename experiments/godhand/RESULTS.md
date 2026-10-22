# God Hand results (2026-10-22)

Environment: WSL2 Ubuntu 24.04 (Linux x64), Ghidra 12.1.3, ghidra-emotionengine-reloaded
v2.1.38 with precompiled `r5900.sla`, Temurin JDK 21, REA branch
`feat/ghidra-ps2-emotion-engine`, god-hand-decomp `5d81ad5`. Times are wall
clock; memory is peak RSS of the largest process. Token figures are not
measured; response bytes are reported instead.

## Target identity

| Fact                       | Observed                                                    |
| -------------------------- | ----------------------------------------------------------- |
| SHA-256                    | equal to decomp `versions.us.elf_sha256`                    |
| ELF header flags           | `0x20924001` (R5900, MIPS III, EABI64), no ABI flags record |
| REA lane / Ghidra language | `ps2-ee-elf32-exec-r5900-v1` / `r5900:LE:32:default`        |
| `.mdebug.eabi64`           | size 0: the retail ELF carries no STABS names               |

## Validation against the decomp (`validate-godhand.mjs`)

| Check                                                | Unseeded                                    | Seeded (10,122 decomp functions)   |
| ---------------------------------------------------- | ------------------------------------------- | ---------------------------------- |
| Ghidra procedures                                    | 9,618                                       | 10,526                             |
| Decomp function starts found                         | 9,215 / 10,122                              | 10,122 / 10,122                    |
| Decomp names at the exact address                    | 36 / 2,922                                  | 2,922 / 2,922                      |
| Body size equal to objdiff size (25-function sample) | 22 / 25                                     | 23 / 25 (two bodies 4 bytes short) |
| Call sites vs raw `jal` decoding, five most-called   | 902/902, 853/855, 738/738, 695/695, 624/626 | same                               |
| Snapshot reopen                                      | same inventory                              | same inventory                     |
| Analysis per open                                    | ~150 s, 1.15 GB                             | ~150 s, 1.15 GB                    |

## Call edges against the decomp's C (`compare-calls.mjs`)

For the 19 investigated functions that have matched C in the decomp, REA's
`procedure_callees` contains exactly the direct calls in that C: 85 / 85, no
missing and no extra edge. Six extra edges in a first comparison were calls to
`func_<address>` names absent from `symbol_addrs.txt`; the oracle now resolves
those placeholders. Six further functions (`cCollisionSolidManage_ChkHit`,
`cEm00_ckDown`, `setMotionInfo`, `moveMotion`, `MotionGetParam`,
`MotionIsHaveParam`) have no C yet; for them REA's pseudocode is the only
readable form.

## What an agent learned through MCP

Observed in REA output, checked against the decomp's C or the ELF bytes where
noted. Readings of intent are inferences.

**Damage.** `cDamageManage_CreateDamageGive` / `CreateDamageTake` allocate a
record and bind it to an owner (`SetObjTargetAndActivate_1FD2C0`,
`SetTarget_1FD530`). `cDamageUnit` keeps its volumes in a linked list at
`+0x3c` (next at `+0x24`); `AddDamageCollSphere` / `Cylinder` append to it, and
`SetDamageCollActive` toggles bit 1 of each volume's flags. Pseudocode and
callees match the decomp's C.

**Hit stop.** `cDamageManage_CkHitStop` returns `manager+0xACD0 != 0`.
`ModeDispatch_tickWithHitStop` passes the global manager `0x574380` and skips
the whole object tick while hit stop is set. Otherwise it clears hits, stores
`cEmManage_GetSpeedRate(0x5864f0)` at `+0x5a8`, and calls the mode handler
selected by the byte at `+0x2f4` from a pointer-to-member table at `0x3bdcc0`.
`0x574380` has 315 code references.

**Solid collision (no decomp C yet).** `cCollisionSolidManage_ChkHit`:

1. Skips objects whose flags at `+0x5a0` have bit 2 or 3 set.
2. Builds each unit's bounding box from its shapes (seeded with ±10000).
3. Tests every other unit with an axis-aligned box overlap (`func_00135250`).
4. Dispatches by shape type to a narrow phase:
   - sphere–sphere: `func_00134CB0`
   - sphere–type 3: `func_00134E18`
   - type 3–type 3: `func_00135040`
5. Marks hit shapes with bit 1, records up to 32 hit owners and returns 1 on
   any hit.

`cCollisionSolid_constructSphere` sets type 1, radius `+0x70` and center
`+0x50`/`+0x60`. The sphere test compares only X and Z. Overlap pushes the
object horizontally by the penetration depth along the separating direction
(`sceVu0SubVector`, `Normalize`, `ScaleVector`). The push is weighted by
comparing the two units' priorities, with a per-unit share at `+0xc` on ties.
Type 3 uses a shape at `+0x180` and helpers `func_00137670` and
`func_00136A88`; a capsule or cylinder is a hypothesis.

**Enemy behavior.** `cEm00_hitReaction` has no code or data references in
Ghidra. The ELF bytes contain its address once, at `0x3bf77c`, inside a table of
218 `{short delta = 0, short index = -1, pfn}` entries starting at `0x3bf1c8`.
That is the GCC 2.x pointer-to-member layout, so this is a `cEm00` method
table. `hitReaction` is entry 182; 206 of the 218 entries still have only `func_`
names in the decomp. `cEm00_hitReaction` compares the value at `+0x564` with
`0x260`–`0x266`. Ghidra does not type the table, so static call graphs miss
this dispatch; an agent must search for the pointer bytes (`search_bytes`).

**Animation.** `moveMotion` (no decomp C) advances by
`+0x444 × +0x440 × DAT_00747a14`, halving the global scale when
`DAT_00747a09 == 1`. 32 code sites in 23 functions read the scale and 21 sites
read the flag, including `cEmManage_GetSpeedRate`. A global slow-motion
mechanism is a hypothesis.

## Cost of the agent workflow

Round 1 (`investigate-godhand.mjs`, seeded): 66 calls, 160 s total, of which
156 s is the analysis triggered by the first query. Every later call took
7–715 ms.

| Tool                | Calls | Response bytes | Notes                                   |
| ------------------- | ----- | -------------- | --------------------------------------- |
| `procedure_callers` | 25    | 153,749        | ~5.6 KB each, mostly repeated Evidence  |
| `procedure_callees` | 25    | 142,724        | same                                    |
| `get_call_graph`    | 5     | 324,727        | one backward graph of 518 nodes: 259 KB |
| `batch_decompile`   | 4     | 127,611        |                                         |
| `search_procedures` | 4     | 30,909         | `detail: summary`                       |
| total               | 66    | 799,878        |                                         |

Round 2 (`ask-rea.mjs`, run alongside the real PS2 verifier) made about 100
calls: 4 `xrefs`, 1 `batch_decompile` and 93 `resolve_containing_procedure`,
each of the latter about 5.6 KB. Total 171 s, 1.1 GB peak.

Observations for REA, not specific to PS2:

- Each primitive response repeats the complete analysis profile and every
  session limitation (~5 KB). The PS2 profile's own share was cut from 1,110
  to 753 bytes on the feature branch.
- In `get_call_graph`, three distinct limitation texts repeat on every node:
  83% of the 518-node graph (253 KB → 43 KB without repetition).
- An unknown procedure name returned a 38 KB error that embeds Ghidra's whole
  launch stdout.
- Reopening a snapshot re-runs auto-analysis (~150 s).
