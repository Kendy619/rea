#!/bin/bash
# REA MCP server (PS2 Emotion Engine profile) for Windows clients through wsl.exe.
# Usage: rea-mcp.sh [godhand]   "godhand" adds the God Hand function/table seeds.
#
# Expects under $REA_PS2_ENV (default $HOME/rea-ps2-env):
#   node/ jdk/            Node.js and a Ghidra-compatible JDK
#   ghidra-ee/            Ghidra with ghidra-emotionengine-reloaded and a precompiled r5900.sla
#   rea-mcp/              a built REA checkout with the PS2 profile
#   bin/rea-mcp-wsl-proxy.mjs
#   godhand/enemy-seeds.tsv   (only for "godhand"; from enemy-seeds.py)
E=${REA_PS2_ENV:-$HOME/rea-ps2-env}
export PATH=$E/node/bin:$E/jdk/bin:$PATH JAVA_HOME=$E/jdk
[ -d "$E/libroot" ] && export LD_LIBRARY_PATH=$E/libroot/usr/lib/x86_64-linux-gnu
export GHIDRA_INSTALL_DIR=$E/ghidra-ee REA_ANALYSIS_PROVIDER=ghidra REA_LOG_LEVEL=silent
if [ "$1" = "godhand" ]; then export REA_GHIDRA_SEED_FILE=$E/godhand/enemy-seeds.tsv; fi
cd "$E/rea-mcp" || exit 1
exec node "$E/bin/rea-mcp-wsl-proxy.mjs" "$E/rea-mcp"
