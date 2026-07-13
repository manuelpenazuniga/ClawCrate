# Sample project

This is a benign fixture project the sandboxed MCP filesystem server is allowed
to read. When you point `@modelcontextprotocol/server-filesystem` at this
directory through `clawcrate mcp wrap --profile mcp-readonly`, the server can
list and read these files, but not the secret files planted alongside them.

- `docs/notes.md` — project notes.
- `src/index.js` — a trivial source file.

See the demo's top-level `README.md` for what the sandbox does and does not
allow.
