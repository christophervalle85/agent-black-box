# v0.4 MCP gateway: compatibility, security and operator guide

## What is implemented

A **real MCP stdio gateway** (`src/mcp-gateway.mjs`) that is launched by an MCP client as a child process. It launches a restricted downstream MCP server (`examples/mcp-notes-server.mjs`) as a separate process and forwards only policy-authorized `tools/call` requests. Both processes exchange actual newline-delimited UTF-8 JSON-RPC 2.0 messages.

```text
MCP host/client
    | stdio: initialize, tools/list, tools/call
    v
Agent Black Box gateway (child process)
    | deny unknown tool/method; validate schema; apply existing policies
    |  read_note: ALLOW / DENY
    |  write_note: REVIEW / DENY -> localhost approval controller, 90-second expiry
    |  audit JSONL before/after execution, grouped by stable approvalId
    v
Allowlisted downstream MCP server (separate child process)
    | read_note (real UTF-8 read)
    | write_note (new file only; O_EXCL + O_NOFOLLOW, 0600)
    v
Demo workspace
```

The existing dashboard on `127.0.0.1:4317` is the approval controller. All MCP lifecycle events appear in the same local audit file. Because the gateway runs in a separate process, the dashboard also polls its audit projection every 3 seconds; its Server-Sent Events channel covers events originating from the dashboard process only.

## Supported protocol scope

This gateway speaks the **legacy MCP stdio protocol version `2025-11-25`**. It supports `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`, and `notifications/cancelled`. It declares **only** the `tools` capability. It rejects resources, prompts, logging, sampling, roots, elicitation, task-augmented execution, unsolicited downstream requests, and other unsupported methods. It does not support the **2026-07-28 stateless** `server/discover` flow. An MCP client in legacy mode is required; an SDK v2 client with automatic negotiation may fall back depending on its configuration.

**This is a deliberately bounded JSON-RPC implementation, not the complete MCP SDK or a certification of protocol conformance.** For broad server compatibility, adopt the official `@modelcontextprotocol/server` and `@modelcontextprotocol/client` v2 SDKs, use the v2 `serveStdio` negotiation entry point, and add interoperability tests with real host applications. There are no new runtime npm dependencies in v0.4.

## Test it today

From the repository root (Node.js >=22):

```bash
npm test             # protocol parsing, real downstream stdio calls, approval, denial, cancellation, timeouts
npm start            # terminal 1: keep approval dashboard open
npm run mcp:smoke    # terminal 2: actual external MCP client; performs read and block tests
npm run mcp:approval # terminal 2: also requests note creation; approve/deny in dashboard
```

Open http://localhost:4317 in a browser. For the approval smoke test, select **Approvals** and review the exact generated filename/content. Do not approve unknown requests. The `demo-workspace` directory contains only harmless sample notes.

### MCP client configuration example

Configure an external MCP host that supports **stdio** with the following conceptual `mcpServers` entry. Replace the path with the **absolute** path on your machine and keep the dashboard server running to allow note creation:

```json
{
  "mcpServers": {
    "agent-black-box": {
      "command": "node",
      "args": ["/absolute/path/to/agent-black-box/src/mcp-gateway.mjs"]
    }
  }
}
```

MCP host configuration format and version negotiation differ by application. For an app using an MCP client SDK, connect via `StdioClientTransport` with the legacy handshake. Do not configure the downstream notes server as an MCP host directly: doing so bypasses this gateway.

### Local configuration

- `MCP_WORKSPACE_ROOT`: absolute path to benign demo workspace (defaults to `<repo>/demo-workspace`).
- `MCP_AUDIT_FILE`: audit JSONL file used by the dashboard (defaults to `<repo>/data/audit.jsonl`).
- `MCP_CONTROLLER_PORT`: dashboard port for approval requests (defaults to `4317`); matches dashboard's `PORT` when customized.
- `MCP_TOKEN_FILE`: dashboard-created, mode-0600 local bearer credential path (defaults to `<audit directory>/mcp-controller-token`).

Start the **dashboard first** so it can generate its ephemeral token. The token is regenerated on every restart; pending approvals fail closed if the dashboard goes away. Do not check in or expose the token. The token is not forwarded to the downstream child. The `data/` directory is gitignored.

## Security guardrails

1. **Allowlisted tool names**: Only `read_note` (`file.read`) and `write_note` (`file.write`) appear in `tools/list` and can be forwarded. Extra tools advertised by the downstream (e.g. `shell_command`) are hidden and denied even when called directly.
2. **Hard block before forwarding**: The gateway calls the original deterministic policy engine, rejects invalid arguments, unsafe filenames, `.env`, traversal, symlink escapes, and unsupported method families. The downstream also independently validates its filesystem operations.
3. **Time-limited explicit approval**: `write_note` pauses in the guarded callback, generates a unique ID, and submits the immutable filename/content to the localhost approval queue. Only a matching one-time approval permits the pending downstream `tools/call`. Denied, expired, disconnected, and unavailable approvals cannot authorize a write.
4. **Audit**: Events are appended with bounded, redacted input summaries. A request is represented by a stable `approvalId` and separate start/result records; the dashboard groups these into one visible request with a timeline. Audit payloads intentionally omit file contents and raw tool outputs.
5. **Process boundaries**: The gateway uses `spawn(process.execPath, [...], { shell:false })` to launch **only the bundled downstream**. The child receives a restricted environment that excludes the approval bearer token and other inherited secrets.
6. **Protocol limits**: 16 KiB inbound JSON-RPC message bound, 64 KiB outbound downstream request bound, 128 KiB downstream response bound, max eight in-flight calls, 12-second downstream deadline, and a 90-second approval deadline. Oversized frames and unexpected server-initiated requests close the downstream connection.
7. **Cancellation**: If the host cancels before forwarding, the approval request aborts and the callback is never invoked. Once forwarded, cancellation cannot guarantee rollback of a side effect; the gateway explicitly does not promise that.

## Known limitations (important)

- **No OS sandbox**: the downstream process runs with the same filesystem credentials as the local user. An app that bypasses the gateway can invoke the downstream directly. Policy enforcement is *routing-dependent*. Do not connect untrusted or privileged third-party servers yet.
- **Not modern MCP**: the 2026-07-28 protocol era has different initialization and per-request metadata. The gateway is a 2025-11-25-only educational adapter; latest SDK clients should use legacy fallback.
- **Not fully interoperable**: the custom narrow JSON-RPC implementation is tested with its own real stdio client/server pair, not with all commercial MCP hosts or the official SDK. This is not proof of general MCP conformance.
- **Same-user threat**: a local process running as the same OS user can read the controller token. The dashboard also lacks multi-user authentication. Never expose the controller over a network.
- **Race / filesystem semantics**: canonical-path checks are best-effort; a separate low-privilege OS sandbox, directory-fd confinement, and mount isolation are needed before operating on untrusted files.
- **Not exactly-once or crash-durable**: if a downstream call times out or the process dies after doing work, its effect may have happened. Approval state lives in memory; an abrupt process death may leave an orphaned pending audit event.
- **Logs not tamper-evident**: append-only application logic is not cryptographic integrity or durable transaction logging. External auditors should treat this as a development trace.
- **No multi-tenant policy engine**: tool names, process and argument schemas are fixed to the bundled demo. Generic upstream config, schema attestation, identity and least-privilege process isolation belong to a later milestone.

## Research references

- [MCP 2025-11-25 lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
- [MCP 2025-11-25 tool schemas, list and call](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP stdio transport and stdout restrictions](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP 2026-07-28 stateless transport semantics](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
- [Official TypeScript SDK v2, the stable release line](https://ts.sdk.modelcontextprotocol.io/v2/)
- [Official v2 protocol-era migration](https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28)
