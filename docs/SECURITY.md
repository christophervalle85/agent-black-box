# Security model and limitations

This is an **educational local-only MVP**, not a hardened security product.

## Enforcement boundary

`guardedToolCall` evaluates each request before it invokes the supplied `execute` callback. It protects **only callbacks routed through this function** and assumes that trusted adapters actually perform the operation described by the tool name. An untrusted or miswired adapter could violate policy even when metadata is approved. It does not monitor arbitrary Claude/Codex/MCP traffic, intercept host processes, sandbox models, or stop agents from bypassing the wrapper. The demo can perform a read of a harmless file in `demo-workspace`; its HTTP tool is **entirely simulated** and its shell tool is **always denied**.

## Audit logging

Events are written to `data/audit.jsonl`; no file contents or full URL query strings are intentionally logged. Only abbreviated tool names, argument summaries, policy decisions and result summaries are stored. Pattern-based redaction is best-effort; **never run on real secrets or untrusted production inputs**. Storage is local but not encrypted, authenticated or tamper-evident. A malicious host user can edit the log.

## Web interface

The server listens on loopback only, validates Host, requires a same-origin JSON request to start demos, limits SSE clients and uses CSP. This is not an authenticated multi-user dashboard; do not reverse-proxy it onto the public internet.

## Filesystem / race limitations

Reads are confined to a workspace using canonical path checks before execution, including symlink boundary checks. A write-capable adversary racing filesystem changes could undermine simple path checks. Real production containment needs an OS sandbox, file descriptor based confinement, privileges dropped, mount isolation, and resource limits.

## Next steps toward real-agent support

1. Introduce a single enforced tool dispatcher for a supported framework (e.g. OpenAI Agents SDK), including unique run IDs, schemas, and human approval.
2. For MCP tools, build a proper mediating client/proxy that handles protocol negotiation, full message semantics, authorization and backward compatibility. Do not claim production MCP support until tested.
3. Add schema validation, per-tool configurable policies, encrypted/tamper-evident storage, robust identity and authentication, rate limiting, durable ingestion, redaction filters, and observability telemetry.
4. Add a process sandbox for commands and network restrictions at OS/proxy level, not just application policy.

## v0.2 model-driven integration

The `src/agent.mjs` Ollama client sends task prompts, tool definitions and tool results to a **loopback-only** Ollama HTTP address. It accepts only explicit localhost/127.0.0.1/[::1] HTTP endpoints set by the local operator; users cannot point it at arbitrary network services from the web UI. Ollama is a separate process outside this project's control and may have its own logging or configuration. **Do not include confidential information in the workspace.**

The agent loop permits at most 6 model rounds and 12 requested tool calls; malformed arguments are passed through the fail-closed guard. Only a small fixed set of trusted adapter functions is available. The shell tool exists to demonstrate **denial**, not to execute commands. Network documentation responses are simulated. These are application-level restrictions, not operating system sandboxing or privilege separation.

Prompts and file contents might contain prompt injection; the system prompt tells the model to ignore instructions from files, but that text is not a sufficient defense by itself. Safety is enforced by the tool dispatcher and its trusted adapters. Logs deliberately omit file contents and model answers, but pattern-based data redaction is not comprehensive, and file contents are returned to the local model for reasoning. Use only benign demo data.

The UI is designed for a single trusted local operator. It is not authenticated, so never publish the port, embed the dashboard in other sites, or expose it via a reverse proxy. The Ollama endpoint should likewise remain local. Browser requests to start the agent require a matching `Origin` and JSON content type; network threats and local malware are not fully addressed by these checks.
