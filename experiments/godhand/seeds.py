"""Convert god-hand-decomp symbol_addrs.txt function symbols into REA Ghidra seeds.

Usage: python3 seeds.py <god-hand-decomp>/config/symbol_addrs.txt <out.tsv>

Writes REA_GHIDRA_SEED_FILE lines (format rea-ghidra-seeds-v1):
``0x<address><TAB>function<TAB><name>``. Only ``type:func`` entries are used;
the first name declared for an address wins. Data symbols are skipped because
almost all of them are generated ``D_<address>`` names.
"""

import re
import sys

FUNC = re.compile(r"^(\S+)\s*=\s*0x([0-9A-Fa-f]+);\s*//.*type:func")


def main(src: str, out: str) -> None:
    seen: set[int] = set()
    rows: list[tuple[int, str]] = []
    with open(src, encoding="utf-8") as handle:
        for line in handle:
            match = FUNC.match(line)
            if not match:
                continue
            name, address = match.group(1), int(match.group(2), 16)
            if address in seen:
                continue
            seen.add(address)
            rows.append((address, name))
    with open(out, "w", encoding="utf-8") as handle:
        handle.write("# Function seeds from god-hand-decomp config/symbol_addrs.txt\n")
        for address, name in sorted(rows):
            handle.write(f"0x{address:x}\tfunction\t{name}\n")
    print(len(rows), "seeds")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
