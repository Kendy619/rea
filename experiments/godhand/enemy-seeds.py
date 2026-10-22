"""Write REA Ghidra seeds that name God Hand's cEm00 mode dispatch tables.

Usage: python3 enemy-seeds.py <SLUS_215.03> <god-hand-decomp>/config/symbol_addrs.txt <out.tsv>

Writes the decomp's function seeds (as seeds.py does) plus:
- labels for the mode-dispatcher group and the three behaviour tables;
- for each table entry whose decomp name is only a placeholder (func_/FUN_),
  the position name cEm00_m<mode>_s<sub-state>, e.g. cEm00_m1_s008.

The table addresses and sizes come from the dispatchers' pseudocode (sub-state
bounds 0xad, 0x27 and 4 at +0x2f5); the ELF supplies the entries. Every entry
must be a GCC 2.x pointer-to-member {delta 0, index -1, pfn in .text}, or the
script refuses, so a different executable never gets these names silently.
Names describe table position only; behaviour is not inferred.
"""

import re
import struct
import sys

FUNC = re.compile(r"^(\S+)\s*=\s*0x([0-9A-Fa-f]+);\s*//.*type:func")
PLACEHOLDER = re.compile(r"^(func|FUN)_[0-9A-Fa-f]{8}$")
NON_VIRTUAL = 0xFFFF0000  # short delta = 0, short index = -1
# (label, address, entries, mode) observed in func_00208BE0 / dispatchers.
GROUP = ("cEm00_ModeDispatchers", 0x3BF1A0, 4)
TABLES = [
    ("cEm00_Mode0Behaviours", 0x3BF1C8, 174, 0),
    ("cEm00_Mode1Behaviours", 0x3BF738, 40, 1),
    ("cEm00_Mode2Behaviours", 0x3BF878, 5, 2),
]
DISPATCHERS = {0x20F3C0: "cEm00_dispatchMode0", 0x24C0F0: "cEm00_dispatchMode1", 0x25E600: "cEm00_dispatchMode2"}


def loadable(elf: bytes):
    phoff = struct.unpack_from("<I", elf, 28)[0]
    count = struct.unpack_from("<H", elf, 44)[0]
    for i in range(count):
        kind, offset, vaddr, _, filesz, _, flags, _ = struct.unpack_from("<8I", elf, phoff + 32 * i)
        if kind == 1:
            yield offset, vaddr, filesz, flags


def reader(elf: bytes):
    segments = list(loadable(elf))
    text = [(v, v + s) for _, v, s, f in segments if f & 1]

    def word(address: int) -> int:
        for offset, vaddr, size, _ in segments:
            if vaddr <= address and address + 4 <= vaddr + size:
                return struct.unpack_from("<I", elf, offset + address - vaddr)[0]
        sys.exit(f"0x{address:x} is not file-backed loadable data")

    def is_text(address: int) -> bool:
        return any(start <= address < end for start, end in text)

    return word, is_text


def entries(word, is_text, base: int, count: int) -> list[int]:
    out = []
    for i in range(count):
        tag, pfn = word(base + 8 * i), word(base + 8 * i + 4)
        if tag != NON_VIRTUAL or not is_text(pfn) or pfn % 4:
            sys.exit(f"0x{base:x}[{i}] is not a non-virtual pointer-to-member: {tag:08x} {pfn:08x}")
        out.append(pfn)
    return out


def main(elf_path: str, symbols_path: str, out_path: str) -> None:
    with open(elf_path, "rb") as handle:
        elf = handle.read()
    word, is_text = reader(elf)
    names: dict[int, str] = {}
    with open(symbols_path, encoding="utf-8") as handle:
        for line in handle:
            match = FUNC.match(line)
            if match:
                names.setdefault(int(match.group(2), 16), match.group(1))

    group = entries(word, is_text, GROUP[1], GROUP[2])
    if sorted(set(group)) != sorted(DISPATCHERS):
        sys.exit(f"unexpected mode dispatchers: {[hex(a) for a in group]}")
    renamed: dict[int, str] = {}
    for address, name in DISPATCHERS.items():
        if PLACEHOLDER.match(names.get(address, "func_00000000")):
            renamed[address] = name
    for _, base, count, mode in TABLES:
        for sub, pfn in enumerate(entries(word, is_text, base, count)):
            current = names.get(pfn, f"func_{pfn:08X}")
            if PLACEHOLDER.match(current) and pfn not in renamed:
                renamed[pfn] = f"cEm00_m{mode}_s{sub:03d}"
    names.update(renamed)

    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("# god-hand-decomp function seeds plus cEm00 table names (enemy-seeds.py)\n")
        for address in sorted(names):
            handle.write(f"0x{address:x}\tfunction\t{names[address]}\n")
        handle.write(f"0x{GROUP[1]:x}\tlabel\t{GROUP[0]}\n")
        for label, base, _, _ in TABLES:
            handle.write(f"0x{base:x}\tlabel\t{label}\n")
    print(f"{len(names)} function seeds ({len(renamed)} table names), {1 + len(TABLES)} labels")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
