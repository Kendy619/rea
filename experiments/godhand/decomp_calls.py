"""Independent call oracle: direct calls in god-hand-decomp matched C source.

Usage: python3 decomp_calls.py <god-hand-decomp> <name> [<name>...]
Prints JSON {name: {"file": path, "calls": [known function names]}} using only
the decomp's own source and symbol_addrs.txt, never REA output.
"""

import json
import os
import re
import sys

FUNC = re.compile(r"^(\S+)\s*=\s*0x([0-9A-Fa-f]+);\s*//.*type:func")
CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
# Undeclared splat placeholders still name their address.
PLACEHOLDER = re.compile(r"^func_[0-9A-Fa-f]{8}$")


def symbols(root: str) -> set[str]:
    with open(os.path.join(root, "config", "symbol_addrs.txt"), encoding="utf-8") as h:
        return {m.group(1) for m in map(FUNC.match, h) if m}


def body(text: str, name: str) -> str | None:
    # A definition: name( ... ) { at statement level, not a call or prototype.
    for m in re.finditer(rf"(?m)^[^\n;=]*\b{re.escape(name)}\s*\(", text):
        i = text.find(")", m.end())
        j = text.find("{", i)
        if j < 0 or text[i + 1 : j].strip() not in ("",):
            continue
        depth = 0
        for k in range(j, len(text)):
            depth += {"{": 1, "}": -1}.get(text[k], 0)
            if depth == 0:
                return text[j : k + 1]
    return None


def main(root: str, names: list[str]) -> None:
    known = symbols(root)
    found: dict[str, dict] = {}
    for base, _, files in os.walk(os.path.join(root, "src")):
        for file in files:
            if not file.endswith(".c"):
                continue
            path = os.path.join(base, file)
            with open(path, encoding="utf-8", errors="replace") as h:
                text = h.read()
            for name in names:
                if name in found or name not in text:
                    continue
                code = body(text, name)
                if code is None:
                    continue
                calls = sorted({c for c in CALL.findall(code) if (c in known or PLACEHOLDER.match(c)) and c != name})
                found[name] = {"file": os.path.relpath(path, root).replace(os.sep, "/"), "calls": calls}
    print(json.dumps(found, indent=2))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
