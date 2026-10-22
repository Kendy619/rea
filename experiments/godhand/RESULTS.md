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
Ghidra: it is reached only through untyped method tables. The ELF bytes
contain its address once, at `0x3bf77c`. Rounds 3–5 (`ask-rea.mjs`) recovered
the state machine around it:

- `func_00208BE0` (the enemy tick that also calls `cDamageManage_CkHitStop`
  and `cCollisionSolidManage_ChkHit`) selects a dispatcher by the mode byte
  `+0x2f4` from a group of GCC 2.x pointers-to-member
  (`{short delta, short index = -1, pfn}`) at `0x3bf198`.
- Each dispatcher indexes its own table of the same layout by the sub-state
  byte `+0x2f5`, resetting out-of-range values to 0; `+0x2f6` counts steps
  inside a sub-state.

| Mode    | Dispatcher                                                                                  | Table      | Entries |
| ------- | ------------------------------------------------------------------------------------------- | ---------- | ------- |
| 0 and 3 | `func_0020F3C0`: positioning around the player, difficulty and attacker throttling          | `0x3bf1c8` | 174     |
| 1       | `func_0024C0F0`: drops held weapons and effects, then runs damage reactions                 | `0x3bf738` | 40      |
| 2       | `func_0025E600`: same cleanup; its last entry turns the damage volume off and plays a sound | `0x3bf878` | 5       |

`cEm00_hitReaction` is mode 1, entry 8. Named callees in the decompiled entries
(`classify-behaviours.mjs`):

- 14 mode-0 behaviors check `cEmManage_CkPlCatched`, 11 of them also `CkPlSorry`.
- 4 mode-0 behaviors throw held objects.
- 9 mode-1 reactions call `cHeatSys_AddHeatGage`.
- 207 of the 219 entries have only `func_` names in the decomp.

`+0x564` is the enemy type: the dispatcher and `cEm00_hitReaction` switch on
values `0x205`–`0x27e`, and `cEm00_stepMotionByEmNo` uses it. This corrects
an earlier reading as a damage ID.

In mode 0 (inferred from pseudocode):

- `+0x16d8` holds `cEmManage_countEmNearerPlayer` adjusted per enemy type.
- On game levels 1 and 2 it drives a 150-unit timer (`+0x175c`, advanced by
  the speed rate) that starts a 90-unit cooldown (`+0x1760`).
- Every eighth frame (`(+0x17d0 ^ frame) & 7`) an enemy picks one of 3, 5 or 7
  slots around the player depending on the level, checks line of sight
  (`ChkLine`) and updates its approach target.

Ghidra types none of these tables, so static call graphs miss the dispatch;
an agent has to find them through `search_bytes` or the dispatchers'
`xrefs`.

**Agent-ready enemy names.** `enemy-seeds.py` turns the map above into
seeds:

- labels `cEm00_ModeDispatchers` (`0x3bf1a0`) and
  `cEm00_Mode{0,1,2}Behaviours`;
- `cEm00_dispatchMode{0,1,2}`;
- `cEm00_m<mode>_s<sub>` for the 207 entries that had only placeholders.

These names state table positions, not behavior. `verify-enemy-seeds.mjs`
passed in 3:19 (1.0 GB peak):

- all 210 names appear in `list_procedures`;
- `address_name` returns the 4 labels;
- `search_procedures ^cEm00_m1_s` returns 36 entries (40 minus 4 decomp
  names);
- the decompiled `func_00208BE0` reads
  `&cEm00_ModeDispatchers + (+0x2f4) * 8`, and `cEm00_dispatchMode1` bounds
  `+0x2f5` by `0x27` before indexing `cEm00_Mode1Behaviours`.

Three decomp placeholder seeds outside the tables (`0x100248`, `0x31de70`,
`0x3b6818`) are listed under other placeholder names. It is not checked
whether this also happens with the decomp seeds alone.

**State transitions and reaction selection.** `state-transitions.mjs`
compares constant `+0x2f4`/`+0x2f5` writes in REA pseudocode with `sb`
instructions in the ELF over all 219 phases.

- Of 221 merged edges, 185 come from both sources, 27 only from machine code
  (writes through a variable in the pseudocode) and 9 only from pseudocode.
  Five edges fall outside table bounds and are flagged.
- The known `0x71 → 0:3` path is found at instruction `0x0023f204`.
- No phase writes `1:0` or `1:7`. A whole-ELF scan of mode-1 writes points to
  `func_0020A178`: REA shows it is called only by the enemy tick `0x208be0`
  and is the only caller of four sub-selectors (`0x20dcf0`, `0x20e480`,
  `0x20ef08`, `0x20da18`).
- `switch-cases.mjs` tabulates their 9 + 6 switches on the hit record's
  reaction id (`*(+0x698)+0x46`).

**Export for the parallel reimplementation project.** `round7-questions.json`
plus `to-reversa-evidence.mjs` produced its evidence layout for 17 functions:
14,297 instructions with no truncation (`0x21a538`: 5,638), every `jal`
checked against the ELF. The first 1,200 instructions of `0x208be0` are
identical to that project's own truncated export.

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

Rounds 3–5 (`ask-rea.mjs`) each paid the ~150–235 s analysis again, because
every round is a new session. Decompiling all 218 table entries took five
`batch_decompile` calls of 44 functions: 25 s and 1.8 MB of responses.

Observations for REA, not specific to PS2:

- Each primitive response repeats the complete analysis profile and every
  session limitation (~5 KB). The PS2 profile's own share was cut from 1,110
  to 753 bytes on the feature branch.
- In `get_call_graph`, three distinct limitation texts repeat on every node:
  83% of the 518-node graph (253 KB → 43 KB without repetition).
- An unknown procedure name returned a 38 KB error that embeds Ghidra's whole
  launch stdout.
- Reopening a snapshot re-runs auto-analysis (~150 s).
