# REA over MCP from Windows (Claude Code and Codex)

The PS2 profile runs on Linux x64 only. These two files let Windows agents use
it through WSL:

- `rea-mcp.sh` starts REA's MCP server with the PS2 Ghidra setup. With the
  `godhand` argument it also loads `REA_GHIDRA_SEED_FILE` with the God Hand
  seeds.
- `rea-mcp-wsl-proxy.mjs` rewrites Windows drive paths in `tools/call`
  arguments (`D:\x\y` → `/mnt/d/x/y`). Agents can pass paths as they see
  them; everything else passes through.

Seeds apply to every binary a session opens, so keep two servers: a generic
`rea-ps2` and a seeded `rea-godhand` used only for `SLUS_215.03`.

## Install (WSL)

Lay out `$REA_PS2_ENV` as listed in `rea-mcp.sh`, copy both files to
`$REA_PS2_ENV/bin/`, and build a dedicated REA checkout there
(`npm ci && npm run build:cached`). Keep it separate from a development
clone.

## Register (Windows)

```powershell
claude mcp add --scope user rea-ps2 -- wsl.exe -d Ubuntu -u <user> -- bash <env>/bin/rea-mcp.sh
claude mcp add --scope user rea-godhand -- wsl.exe -d Ubuntu -u <user> -- bash <env>/bin/rea-mcp.sh godhand
codex mcp add rea-ps2 -- wsl.exe -d Ubuntu -u <user> -- bash <env>/bin/rea-mcp.sh
codex mcp add rea-godhand -- wsl.exe -d Ubuntu -u <user> -- bash <env>/bin/rea-mcp.sh godhand
```

Codex stops tool calls after 60 s by default, but the first God Hand query
runs Ghidra's analysis (3–4 minutes). Add to each server in
`~/.codex/config.toml`:

```toml
startup_timeout_sec = 60
tool_timeout_sec = 1800
```

## Checked

- A Windows MCP client started `rea-godhand` through `wsl.exe` (220 tools,
  about 1 s to connect).
- `open_binary` with `D:\God Hand (USA)\God Hand (USA)\SLUS_215.03` opened
  `/mnt/d/...`; `address_name` returned `cEm00_hitReaction` and
  `cEm00_Mode1Behaviours` (206 s including analysis).
- `claude mcp get` reports both servers connected.
- `codex exec` listed 220 tools on `rea-ps2`.
