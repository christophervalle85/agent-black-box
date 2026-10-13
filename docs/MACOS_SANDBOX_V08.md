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

### Observed on Apple Silicon — diagnostic investigation, 13 Oct 2026

The signed standalone Swift CLI passed compiler and `codesign` entitlement checks, then terminated with `SIGTRAP` before any JSON result (`status:null`, `signal:"SIGTRAP"`, `timedOut:false`, ~289 ms, empty stderr/stdout). **No macOS isolation success has been established.** App Sandbox policy or container initialization is a possible cause, but only the crash's termination reason and faulting thread can establish which subsystem trapped. Apple [explains the fields in a crash report](https://developer.apple.com/documentation/xcode/examining-the-fields-in-a-crash-report) and provides a [sandbox-violation investigation guide](https://developer.apple.com/documentation/security/discovering-and-diagnosing-app-sandbox-violations).

After reproducing the failure, run `npm run mcp:mac-crash` on the Mac to summarize the newest matching `.ips` or `.crash` report without printing the entire diagnostic file. If no report appears, open macOS Console > Crash Reports and locate `blackbox-sandbox-probe`, or use Console's `type:error`, `subsystem:com.apple.sandbox.reporting` and `category:violation` filters. Prefer sharing the summary only, not a raw user crash report (which can contain private paths and environment details).

**Architectural recommendation:** regardless of this ad-hoc standalone CLI failure, favor a bundled XPC service with independently configured permissions and `launchd` lifecycle for the actual MCP tool worker, following [Apple's XPC documentation](https://developer.apple.com/documentation/xpc). Do not add `com.apple.security.inherit` to a standalone process launched by an unsandboxed Node parent: inheritance cannot create a protected parent context. Never disable SIP or Gatekeeper for this project.

### Phase-1b: sign the same probe inside a macOS .app bundle (experimental)

The **confirmed crash** (`EXC_BREAKPOINT / SIGTRAP`, signal 5, faulting frame `_libsecinit_appsandbox.cold.6`) occurred during system-library sandbox initialization, before Swift's entrypoint. The report does **not** identify `SYSCALL_SET_PROFILE` or prove whether Node's parent sandbox or missing bundle metadata is the primary cause. Apple's [entitlement inheritance guidance](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html) and [Apple Developer Technical Support notes](https://developer.apple.com/forums/thread/679940) explain why an inherited-versus-new-sandbox conflict can trap, but that is not a conclusive diagnosis for the standalone test.

The next low-risk differentiation is:

```sh
npm run mcp:mac-bundle-probe
```

This compiles **the same Swift logic** within a disposable `BlackBoxSandboxProbe.app/Contents/MacOS` structure, provides an explicit `Info.plist` application identifier, and ad-hoc signs **the bundle**, not just a loose executable. The Node harness still launches the bundled executable and verifies OS permissions; signing or a successful launch alone never counts as a PASS. This helps determine whether standard bundle packaging changes behavior, but it **is not an XPC service**, a registered LaunchServices test, or a reliable production macOS security boundary.

Results:
- If the three actual file/network/container checks pass, proceed to a separately sandboxed XPC worker and end-to-end MCP integration.
- If it still traps in `libsystem_secinit`, do **not** add `com.apple.security.inherit` to the unsandboxed Node process's child and claim success. Use the Xcode XPC Service template within a native host app for a supported `launchd`-managed separation, then repeat real isolation tests.

The test deletes the temporary `.app` bundle and synthetic host marker. macOS may retain its system-created sandbox container under `~/Library/Containers/dev.agentblackbox.sandbox-probe.bundle`; do not delete arbitrary containers by script.

### Phase 1c — macOS XPC service feasibility (awaiting on-device test)

The user's **app-bundled signed Swift probe passed all three OS-level checks**, in contrast with the identically entitled loose executable's `libsystem_secinit` SIGTRAP. This establishes that app-bundle packaging changes the result; it does not establish the exact low-level secinit root cause.

The next step embeds a **private XPC service in `Contents/XPCServices` of an ad-hoc signed host .app** and uses Apple's C-based XPC Services API. The service has its own `CFBundleIdentifier`, `XPC!` package type, a restrictive App Sandbox signature with **no network entitlement**, and a fixed single-method diagnostic interface. It is launched by macOS on demand through `xpc_connection_create`, not directly via Node's `spawn`. The parent host remains unsandboxed in this experiment so the boundary can be measured between host and service. Official documentation: [Apple Creating XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html) and [XPCService Info.plist keys](https://developer.apple.com/documentation/bundleresources/information-property-list/xpcservice).

To test on macOS (requires Xcode Clang):

```sh
npm run mcp:mac-xpc-probe
```

Apple's [Creating XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html) describes the C XPC Services API as **libSystem-level**. Xcode's macOS SDK does not expose the separate linker target `-lxpc`; Clang links libSystem by default. The first on-device attempt stopped before executing the service with `ld: library 'xpc' not found`. The build now omits the incorrect `-lxpc` flag. This is a build-system correction, **not** an App Sandbox or XPC runtime PASS.

The harness builds and signs a disposable host `.app` and nested `.xpc`, checks the nested signature/entitlement, starts a reachable loopback server, verifies an unrelated marker is host-readable, and requests one XPC diagnostic. Four outcomes must pass: separate process PID, permission-denied host file, permission-denied loopback TCP, and an allowed temporary-file write/cleanup in the service. Any failure (including XPC connection invalidation, timeout, or missing sandbox denial) fails closed and prints bounded diagnostics.

**On-device compilation correction (13 Oct 2026):** The first retry compiled the C XPC host, then reported a compile-time callback-type mismatch for the service's `xpc_main` call. Apple's [`xpc_main` declaration](https://developer.apple.com/documentation/xpc/xpc_main%28_%3A%29?language=objc) takes `xpc_connection_handler_t`, a **C function pointer**, while [`xpc_connection_set_event_handler`](https://developer.apple.com/documentation/xpc/xpc_connection_set_event_handler%28_%3A_%3A%29?language=objc) accepts a **block** for incoming message events. The service now supplies a named C function (`accept_peer`) to `xpc_main`, and keeps the message-event block in that function. This is a source-level build fix, not runtime isolation proof.

**Not yet the production worker:** the service currently accepts only a synthetic test operation, not `read_note` or `write_note`. The Node gateway still uses the bundled Node MCP notes executable, and `MCP_SANDBOX=required` on macOS remains unsupported/fail-closed. Only after native XPC acceptance do we design the bounded, authorization-checked Node→host→XPC request bridge, secure workspace provisioning, and real MCP read/write tests. Build-system and signing policy remain experimental; an Xcode project may be preferable to manual app packaging for shipping.

## Phase 2a — bounded native note operations (experimental)

**Previous gate on Mac PASSED:** The user ran `npm run mcp:mac-xpc-probe` and verified that the signed host app connected to a separately sandboxed native XPC service with a distinct process PID. A readable user-owned host marker and a reachable loopback TCP endpoint were both denied **with OS permission errors** from inside the worker; its temporary-file write/cleanup succeeded. This demonstrates real OS-enforced isolation of the diagnostic XPC service. It does not prove the complete MCP tool path.

**Next on-device gate:** `npm run mcp:mac-xpc-notes` compiles/signs an **additional independent native XPC notes worker**, which exposes fixed `write_note` and `read_note` operations to the experimental host and a test-only `cleanup_test_note`. The test exchanges a hard-coded non-secret note, verifies identical bytes returned through XPC, attempts a traversal read, and cleans the synthetic file. The worker is signed with `com.apple.security.app-sandbox` and no network entitlements. The C implementation restricts names to `bbx-test-*.txt`, content to at most 2,000 bytes, and uses `openat` with `O_NOFOLLOW` and `O_EXCL` for new-file-only writes.

**Strict limitation:** This deliberately operates only on synthetic files in the service's sandbox-accessible `TMPDIR`, **not** the project's demo workspace or durable notes. It has **no bridge to the Node MCP gateway**, no user approvals, no audit integration and no claim that the notes host is a complete MCP server. The earlier XPC OS isolation proof and existing Node policy/approval/audit checks remain separate. The test must pass on a real Mac before designing the Node-to-native IPC gateway or persistent workspace. No production credentials or existing audit records are needed. The native service is not yet hardened with client code-signature identity checks, and no other process should place sensitive content in this temporary test area.

### Engineering gates before enabling `MCP_SANDBOX=required` on macOS

1. Complete native note XPC test using synthetic data.
2. Design a durable, sandbox-contained workspace and explicit import/export workflow. Require the Node gateway's policy workspace to match the worker's actual data scope.
3. Build a bounded MCP stdio/native host IPC adapter with fixed `initialize`, `tools/list`, and `tools/call` schemas, enforce message size limits, and deny direct worker access to audit keys and controller approval tokens.
4. Exercise real MCP legacy/modern calls, read and operator-approved write, cancellations and worker crash / timeout; audit both successes and uncertain outcomes.
5. Rerun permission-denial tests on the **final native notes worker**, reverify signatures and entitlements at launch, and reject any unsupported configuration without unsandboxed fallback. Retain Linux 7/7 isolation acceptance.

## Phase 2 — native XPC worker architecture (not yet implemented)

- Build a dedicated sandboxed XPC service inside a minimal signed macOS host app, separated from the existing unsandboxed Node control plane. Model its IPC as a fixed set of `read_note`/`write_note` operations; never forward arbitrary tool names, paths, file descriptors or commands.
- Choose an app-owned workspace with explicit user-approved import/export. Keep the Node gateway's data directory and signing keys inaccessible to the XPC worker.
- Add supervisor and lifecycle integration (timeouts, cancellations, terminated XPC service, crashed worker) without treating partial or unknown execution outcomes as success.
- Prove the subprocess's actual sandbox (file access denied, loopback networking denied, allowed app-container writes) with native negative tests.
- Gate `MCP_SANDBOX=required` on successful entitlement/signature verification, worker handshake and runtime acceptance. Never fall back to the unsandboxed Node server.

## v0.8 release acceptance

Native macOS file and network denial **from the production worker**, not merely from this probe; safe positive workspace operation; Mac required-mode MCP legacy/modern protocol tests; approvals and audit chain remain intact; Linux Bubblewrap 7/7 acceptance preserved; CI and manual signature verification documented. No merge to `main` until user Mac results establish those claims.
