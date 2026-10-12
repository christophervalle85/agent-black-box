# Agent Black Box · v0.2

**Local AI agent security observability**: a model-driven agent whose every requested tool operation is checked by a deterministic policy engine **before execution**, logged to a local audit store, and displayed in a live dashboard.

![Status](https://img.shields.io/badge/MVP-v0.2-blue) ![Node](https://img.shields.io/badge/Node-22%2B-green) ![Runtime Dependencies](https://img.shields.io/badge/runtime_dependencies-0-brightgreen)

## Quick start

**Requirements:** Node.js 22+ for the web application; [Ollama](https://ollama.com/download) for the real AI agent. The scripted demo works even without Ollama.

```bash
# After installing and starting Ollama, download a model with tool support:
ollama pull qwen3:4b-instruct

# In the project folder:
npm start
# Open http://localhost:4317 in your browser
# Select "AI agent", enter a task, click "Run with local LLM"
```

On some systems Ollama runs as a desktop/background service; otherwise start it with `ollama serve` in a separate terminal. If the AI agent tab says Offline, check that http://127.0.0.1:11434/api/tags responds. Run `ollama list` to check that the selected model is installed.

**Suggested prompt:**

> Read notes.txt in the demo workspace and summarize the contents. Then request read_file on .env to demonstrate the security policy. Explain what was allowed and blocked.

A tool-capable model normally turns this into one or more calls; model behavior varies, so it may choose to answer without using a tool. The UI has three one-click prompt presets (workspace read, restricted file, denied shell). Every tool call the model actually requests is checked by policy; there is no predetermined successful/failed result for real agent runs.

**Alternative: CLI**

```bash
npm run agent -- 'Read notes.txt and summarize it.'
npm test                         # 19 unit and HTTP integration tests, no Ollama needed
node examples/instrument-tool.mjs
PORT=4400 npm start
OLLAMA_MODEL=qwen3:8b npm start # pull that model first
```

No cloud API key or npm dependency installation is required. The model download is a few gigabytes and needs sufficient memory. Data persists to the gitignored `data/audit.jsonl` file; Ctrl+C stops the server.

## Architecture

```text
UI task prompt                   Scripted demo
     |                                |
     v                                |
 Ollama /api/chat                     |
  (tool calling)                      |
     |                                |
     |  read_file / fetch_docs / run_shell
     v                                v
     +----> guardedToolCall(tool, args, execute)
                     |
                evaluatePolicy() ---- BLOCK ---> audit, no tool execution
                     |
                    ALLOW
                     v
              trusted adapter
           (local read / mock docs)
                     |
                     v
          AuditStore.add() -> data/audit.jsonl
                     |
                     +------ SSE /api/stream ------> Live dashboard
                     |
                     +------ tool result ----------> Next Ollama turn
```

The **only real side effect** from the agent tool adapters is reading eligible local files in `demo-workspace/`. Documentation fetches return a stubbed response; arbitrary shell commands are always blocked. No generated code is executed. The server and Ollama requests use loopback (`localhost`).

## Enforcement policies

| Rule | Behavior |
| --- | --- |
| `ALLOW_WORKSPACE_READ` | Read ordinary, in-workspace files |
| `DENY_PATH_ESCAPE` | Reject traversal, absolute paths and escaping symlinks |
| `DENY_SENSITIVE_FILE` | Reject typical credential and private key filenames |
| `ALLOW_MOCK_DOCS` | Permit **simulated** GETs to `docs.example.test` (no network) |
| `DENY_UNAPPROVED_EGRESS` | Reject other domains, methods and URL types |
| `DENY_SHELL` | Block *every* shell execution request |
| `DENY_UNKNOWN_TOOL` | Reject unregistered tools |
| `INVALID_INPUT` | Reject malformed tool-call arguments |

The model sees friendly function names (`read_file`, `fetch_docs`, `run_shell`), which are mapped to the existing guarded adapters (`file.read`, `network.fetch`, `shell.exec`). You can inspect the internal tool names and rules in the audit log.

## API endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | Service health and version |
| `GET /api/agent/status` | Ollama connectivity and configured model availability |
| `POST /api/agent/run` | Execute one model-driven task and return answer + audit records |
| `GET /api/events?limit=300&decision=block` | Recent audit events |
| `GET /api/stats` | Audit statistics |
| `GET /api/policies` | Rules presented in the UI |
| `GET /api/stream` | Live SSE audit stream |
| `POST /api/demo/run` | Run the original nine scripted scenarios |

The two POST endpoints require same-origin JSON. An agent task body looks like `{"prompt":"Read notes.txt"}`. The REST API intentionally has no public authentication and should not be exposed beyond localhost.

## Project layout

```text
src/agent.mjs          Ollama API, tool declarations and bounded reasoning loop
src/server.mjs         Local HTTP API, static assets, SSE
src/policy.mjs         Deterministic tool approval/denial rules
src/monitor.mjs        Pre-execution wrapper and redacted audit metadata
src/tools.mjs          Controlled read-only file and fake documentation adapters
src/audit.mjs          Append-only JSONL event storage
src/demo.mjs           Nine scripted regression scenarios
public/                Browser dashboard and real-agent prompt UI
examples/run-agent.mjs Run a real model-driven task from the command line
examples/instrument-tool.mjs  Standalone guarded tool example
tests/                 Mocked Ollama + agent loop + policy/API tests
docs/SECURITY.md       Threat boundaries and hardening gaps
```

## Real-model behavior vs automated tests

The repo has test coverage for the message protocol and security guard using *mocked* model outputs; no downloaded LLM is included. Tests verify that blocked tool calls never reach their execution callbacks and that the mocked agent can iteratively consume tool results. **The full inference experience is not validated here against an installed Ollama model.** Run it locally and adjust the selected model if its tool-calling quality is poor.

## What to build next

1. Human approval/denial workflow for sensitive actions (with audit history).
2. Real MCP mediating client/server with per-tool schemas, auth, and permissions.
3. Stronger security boundaries: hardened filesystem reads, cryptographically verifiable logs, identity, sandboxing and robust sensitive-data handling.
4. Rich run histories, per-agent timelines and container deployment.

## Security / privacy

See [docs/SECURITY.md](docs/SECURITY.md). This is an **educational prototype**, not a production security boundary. It does not intercept tools from other agent products. Ollama messages include local tool results and are sent to the *locally configured* Ollama instance; keep your workspace limited to non-sensitive test data. Generated agent text is displayed using safe text rendering rather than inserted as HTML.

## License

MIT.
