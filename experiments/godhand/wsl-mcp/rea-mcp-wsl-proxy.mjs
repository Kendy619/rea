// stdio proxy for REA's MCP server when the client runs on Windows and REA in WSL.
// Rewrites Windows drive paths in tools/call arguments ("D:\x\y" or "D:/x/y")
// to their WSL mounts ("/mnt/d/x/y"); everything else passes through unchanged.
// Usage: node rea-mcp-wsl-proxy.mjs <rea checkout>
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const repo = process.argv[2];
const child = spawn(process.execPath, [`${repo}/scripts/rea.mjs`, "mcp"], {
  stdio: ["pipe", "inherit", "inherit"],
  env: process.env,
});
const BACKSLASH = String.fromCharCode(92);
const isDrivePath = (s) =>
  /^[A-Za-z]:/u.test(s) && (s[2] === BACKSLASH || s[2] === "/");
const rewrite = (value) => {
  if (typeof value === "string") {
    if (!isDrivePath(value)) return value;
    const rest = value.slice(3).split(BACKSLASH).join("/");
    return `/mnt/${value[0].toLowerCase()}/${rest}`;
  }
  if (Array.isArray(value)) return value.map(rewrite);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, rewrite(v)]),
    );
  return value;
};
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on("line", (line) => {
  let out = line;
  try {
    const message = JSON.parse(line);
    if (message?.method === "tools/call" && message.params?.arguments) {
      message.params.arguments = rewrite(message.params.arguments);
      out = JSON.stringify(message);
    }
  } catch {
    // Not JSON: forward untouched and let the server report it.
  }
  child.stdin.write(`${out}\n`);
});
lines.on("close", () => child.stdin.end());
child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => child.kill(sig));
