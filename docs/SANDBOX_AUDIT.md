# v0.6: OS sandboxing and audit integrity

## Official sources

- [Bubblewrap upstream manual](https://github.com/containers/bubblewrap/blob/main/bwrap.xml) — namespace options, `--ro-bind`, `--bind`, `--unshare-net`, `--new-session`, `--die-with-parent`.
- [Apple App Sandbox](https://developer.apple.com/documentation/security/app-sandbox) and [signed helpers](https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app) — a sandboxed macOS helper requires signing and entitlements. An arbitrary child process launched by Node is **not** equivalent.
- [NIST FIPS 198-1 HMAC](https://csrc.nist.gov/pubs/fips/198-1/final) and [Node.js `crypto.createHmac`](https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options) — keyed SHA-256 authentication.
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) — restricted storage, tamper detection, verification and log safety.

## OS sandbox: explicit modes

`MCP_SANDBOX=off` (default): The downstream is **not OS-sandboxed**. The existing path validation, tool allowlist and human approval still apply. This is the compatible local demo mode on macOS.

`MCP_SANDBOX=required`: **Linux only**, requires Bubblewrap at `/usr/bin/bwrap`, or `MCP_BWRAP_PATH=/absolute/path/to/bwrap`. Fails on macOS, missing Bubblewrap, or denied kernel namespace isolation. There is **no fallback to unsandboxed spawn**. Install with the system package manager and validate the Linux kernel/user namespaces allow operation.

The Bubblewrap process uses separate user/PID/IPC/UTS/network namespaces, a new session, die-with-parent, a private `/tmp`, minimal `/proc` and `/dev`; exposes the runtime and the specific bundled program and necessary system libraries read-only, and mounts only `demo-workspace` with write permission. No inherited `NODE_OPTIONS`, HOME, service token or audit secrets are passed to the child. It cannot access the host project's `data/` by these mounts. This is a **mount namespace isolation prototype**, not seccomp, a container security suite, or a defense against kernel bugs.

### Linux manual check

```bash
sudo apt-get install bubblewrap     # Debian/Ubuntu example
MCP_SANDBOX=required npm run mcp:smoke
MCP_SANDBOX=required npm run mcp:modern
```

Both commands must pass. In particular, merely seeing `bwrap --version` succeed does **not** prove user namespaces can be created. An actual MCP call must succeed. If it fails, do **not** silently switch to `off` for untrusted servers; investigate OS namespace policy first.

### macOS users

Apple documents an official App Sandbox for signed applications and helpers using `com.apple.security.app-sandbox` entitlements. A shell-launched Node subprocess does not acquire those entitlements from this project. v0.6 therefore **does not claim a macOS OS sandbox**, and `MCP_SANDBOX=required` refuses to run on macOS. A future signed Xcode/XPC helper should be treated as a separate, carefully tested platform integration. Avoid relying on undocumented `sandbox-exec` profile syntax as a supported production boundary.

## Integrity files and enrollment

`data/audit.jsonl` stays in its existing readable JSONL format. The store maintains these private mode `0600` companions:

- `data/audit.jsonl.hmac.key`: randomly generated 32-byte key encoded as hex. **Never commit, expose via MCP or share**.
- `data/audit.jsonl.mac.jsonl`: each entry has monotonically increasing `seq`, prior MAC (`prev`), and HMAC-SHA256 (`mac`) authenticating the exact JSONL line and sequence.
- `data/audit.jsonl.anchor.json`: durable sequence/head-MAC checkpoint used to detect deletion of the signed tail.

For a **new empty** data store, initial signing is automatic. For an existing nonempty v0.5 log, the server refuses to run until you explicitly seal it:

```bash
# Run only after you trust and have reviewed the old local history.
npm run audit:seal
npm run audit:verify
```

Sealing preserves the original bytes at `data/audit.jsonl.pre-v06.jsonl` (exclusive creation; refuses to overwrite a previous backup) and signs the original history. **Events before sealing are not retroactively proven authentic.** Never rerun sealing to ignore an integrity failure; do not delete the chain/key/checkpoint to reset it.

On restart and before reads or tool adapters, the store verifies every line and its corresponding HMAC/checkpoint; failures **fail closed**. `GET /api/audit/integrity` returns current verification results; the dashboard's protection panel displays the status. The writer uses a directory lock across the dashboard and gateway processes. A crash while holding the lock leaves a stale `data/audit.jsonl.writer.lock` directory: verify all processes have exited and investigate storage integrity before clearing it. Crash between the three writes may also leave an inconsistent log; restore the last known-good verified backup or repair only through a controlled incident-recovery process. No unverified automatic repair is provided.

### Integrity threat model

Detects offline modification, truncation, deletion of individual signed events, wrong checkpoints, missing companion metadata, and mismatched sequence. Protects file contents from accidental exposure via mode `0600`; avoids logging raw note contents.

**Does not** protect against a malicious or compromised same-user process that can read the key, create alternate signatures and replace the checkpoint; an attacker who can erase *all* local state; root/admin compromise; disk rollback including key and checkpoint; replay of independently copied whole snapshots; log confidentiality against same-user processes; or physical hardware failures. For independently verifiable, immutable evidence, sign/export periodic checkpoint heads to a separately administered storage or transparency service, run under a different OS identity, and deploy proper key management.

Verification reads the chain (bounded to 64 MiB) and therefore has linear I/O/CPU cost. At scale, use an indexed append-only store and secure remote attestations rather than this local prototype. No unsafe automatic repair is attempted after partial writes. A full event is fsynced before its MAC is appended; the MAC is fsynced before the checkpoint is atomically replaced.
