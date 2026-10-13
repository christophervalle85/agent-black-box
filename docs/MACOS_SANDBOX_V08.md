# v0.8 design gate: native macOS App Sandbox and XPC isolation

**Status: feasibility research and native boundary probe, NOT a production MCP sandbox.**
`main` continues to ship stable v0.7 until acceptance on real macOS.
The `feature/v0.8-macos-sandbox` branch may change substantially.

## Official Apple references reviewed

- [Configuring the macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox): kernel-enforced sandbox with separately configured filesystem and networking rights.
- [Protecting user data with App Sandbox](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox): sandbox limits the impact of compromised code.
- [Discovering and diagnosing App Sandbox violations](https://developer.apple.com/documentation/security/discovering-and-diagnosing-app-sandbox-violations): components needing distinct access rights use XPC, login items, or a helper app—not a plain inherited child sandbox.
- [Embedding a command-line tool in a sandboxed app](https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app): signing, entitlements, the `inherit` caveat, and why XPC is often preferable.
- [Creating XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html): per-service sandbox and lifecycle management. Apple calls XPC the preferred way to achieve privilege separation.
- [Accessing files from the macOS App Sandbox](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox): the app container, user-selected documents, and operating system permission constraints.
- [Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac/): inspect and audit executable entitlements before shipping.

## Threat model and intended architecture

**Trust boundary:** The existing Node gateway retains HMAC-protected audit history, signed receipts, MCP message validation, deterministic policy authorization and human approvals. A **separately entitled native worker/XPC service** processes only allowlisted file operations. The worker must be unable to read the gateway's audit keys, the host's unrelated user data, or establish outbound connections. It should write only inside its own sandbox container. Workspaces used by the unsandboxed Node demo are not silently exposed to the worker; a user-controlled import/export or explicit approved workspace mechanism must be designed.

**Untrusted inputs:** MCP tool names/arguments, crafted JSON-RPC messages, file names, symlinks, poisoned workspace files, dropped IPC connections, child failure, malicious native-worker payloads. The parent gateway is not itself protected from other malicious processes running under the same macOS user.

**Out of scope:** root/administrator compromise, kernel exploit chains, physically immutable logs, key compromise under the same OS user, generic unrestricted MCP servers, notarized production distribution. The initial probe is not an XPC service. It has no authority to claim isolation of the current Node downstream server.

**Failure policy:** When `MCP_SANDBOX=required` on macOS, the gateway MUST continue refusing unprotected execution until a separately signed/enforced native worker is integrated and Mac acceptance tests pass. Do not substitute `sandbox-exec`, environment sanitization, codesign output or an unsigned Node subprocess for genuine OS-enforced isolation.

## Phase 1 — OS behavior probe (current)

The opt-in macOS-only script:

```sh
npm run mcp:mac-probe
```

uses Apple's `xcrun swiftc` to compile `native/macos/SandboxProbe.swift`, ad-hoc signs the throwaway executable using `codesign` and the `com.apple.security.app-sandbox` entitlement with **no network privileges**, verifies the signature/entitlement, then runs it while:

1. The parent confirms it can read a disposable marker under the user's home. The helper must be unable to read it.
2. The parent opens an accessible 127.0.0.1 TCP listener and establishes a baseline connection. The helper's connect attempt must be rejected with `EACCES` or `EPERM`, **not** `ECONNREFUSED`/timeout.
3. The helper must write and remove a disposable file inside its reported sandbox home.

All three must pass. The script cleans up its temporary code and marker, and prints a failure if compiler or signing tools are missing. An ad-hoc signature is suitable only for local feasibility; Apple signing/entitlement rules for an embedded tool, app bundle and independent XPC service still need a separate implementation. This probe can also show a **negative** result: for example, if macOS does not create a usable sandbox container for an independently launched CLI, we must move directly to an Xcode app/XPC host without misreporting success.

**Mac prerequisites:** `xcrun --find swiftc` and `codesign --version`, typically provided by Xcode/Command Line Tools. This test is not run by Linux CI: Swift/macOS kernel policy cannot be emulated reliably there.


### If code signing succeeds but the native helper exits without a status

Node's synchronous child-process API reports `status: null` for a signal-terminated process; status alone does **not** tell us whether the OS denied execution, the binary trapped, or it timed out. The probe's native launch now uses asynchronous `spawn` with an explicit 12-second deadline, and prints `status`, `signal`, `timedOut`, `error`, `stderr` and elapsed time when something fails.

For relevant Apple sandbox diagnostics, use the **Console** app and search for `type:error`, subsystem `com.apple.sandbox.reporting`, and category `violation`, as described in [Apple's App Sandbox violation guide](https://developer.apple.com/documentation/security/discovering-and-diagnosing-app-sandbox-violations). A `SIGTRAP` or `SIGKILL` is not itself evidence that the intended restrictions work. Apple's engineering team also describes a specific `libsystem_secinit` entitlement conflict when an **embedded tool** attempts to start a new sandbox instead of inheriting its parent's; our standalone test is different, so do not assume that explanation without diagnostics ([Apple Developer Forums](https://developer.apple.com/forums/thread/679940)). Do not disable SIP, Gatekeeper, or App Sandbox to make the probe pass.

## Phase 2 — native XPC worker architecture (not yet implemented)

- Build a dedicated sandboxed XPC service inside a minimal signed macOS host app, separated from the existing unsandboxed Node control plane. Model its IPC as a fixed set of `read_note`/`write_note` operations; never forward arbitrary tool names, paths, file descriptors or commands.
- Choose an app-owned workspace with explicit user-approved import/export. Keep the Node gateway's data directory and signing keys inaccessible to the XPC worker.
- Add supervisor and lifecycle integration (timeouts, cancellations, terminated XPC service, crashed worker) without treating partial or unknown execution outcomes as success.
- Prove the subprocess's actual sandbox (file access denied, loopback networking denied, allowed app-container writes) with native negative tests.
- Gate `MCP_SANDBOX=required` on successful entitlement/signature verification, worker handshake and runtime acceptance. Never fall back to the unsandboxed Node server.

## v0.8 release acceptance

Native macOS file and network denial **from the production worker**, not merely from this probe; safe positive workspace operation; Mac required-mode MCP legacy/modern protocol tests; approvals and audit chain remain intact; Linux Bubblewrap 7/7 acceptance preserved; CI and manual signature verification documented. No merge to `main` until user Mac results establish those claims.
