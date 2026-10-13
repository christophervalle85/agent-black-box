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

### Phase 2b — Experimental Node to native host to private XPC transport

The **Phase 2A Mac test passed**: the separately signed App Sandbox notes worker performed a synthetic new-file write, returned exact note content, denied traversal, and removed its test file. No Node MCP or approval/audit path was exercised.

`npm run mcp:mac-xpc-node-bridge` now tests a **separate bounded binary IPC** between a Node script and a signed native host executable. The host forwards only `READ`, `WRITE` and `REMOVE` synthetic note commands to the previously validated private notes XPC worker. It uses bounded, length-prefixed note bodies via **stdin**, not process command-line arguments or environment variables. The native host is unsandboxed but designed to access only its private XPC service; the OS-enforced file boundary remains in the signed XPC service. There is no shell execution or generic tool forwarding.

The native worker still accepts only `bbx-test-*.txt` filenames (≤64 characters) and up to 2,000 bytes, and rejects attempts at paths outside its synthetic test namespace. The bridge smoke also attempts duplicate new-file creation, rejects a test traversal, confirms the original content is unchanged, removes the synthetic note and verifies it cannot be read afterward. The test deletes its temporary signed app bundle.

**Important:** This is NOT a production MCP downstream, not durable notes storage, and not connected to `src/mcp-gateway.mjs`. This smoke deliberately bypasses human approvals and audit logs **because it can access only expendable synthetic test fixtures**; it must not be repurposed for real files. Before routing user-controlled operations, we need to align policy and XPC workspace identity, use a native durable container directory, constrain client identity/signature and executable trust, enforce operator approval and authenticated audit logging, handle XPC request cancellation and uncertain write outcomes, and replay both OS-denial tests on the final service. A synchronous XPC response can block indefinitely according to [Apple's API documentation](https://developer.apple.com/documentation/xpc/xpc_connection_send_message_with_reply_sync%28_%3A_%3A%29); the test's Node process supervisor imposes a timeout and treats a timed-out write as an **unknown outcome**, not a rollback. macOS `MCP_SANDBOX=required` must remain fail-closed.

### Phase 2C — Container-owned durable scratch storage (Mac acceptance pending)

The user ran the **Phase 2B transport acceptance on Apple Silicon** and verified every synthetic Node→native host→XPC operation: signed worker, exclusive new-file creation, exact readback, traversal and duplicate-write refusal, original note unchanged, deletion and post-deletion denial. This proves the *experimental transport only*, not MCP policy integration or real document storage.

The next isolated gate runs:

```sh
npm run mcp:mac-xpc-durable
```

It compiles a **separate** Objective-C/C native XPC service (`dev.agentblackbox.xpc-durable.worker`) without changing the previously accepted temporary-file service. Using Foundation's documented `NSFileManager URLForDirectory:NSDocumentDirectory ... create:YES`, the service requests its own sandbox-managed Documents directory. It refuses the operation unless this resolves into macOS's expected `/Library/Containers/.../Data/Documents` path shape. It creates a `0700` `AgentBlackBoxScratchNotes` subfolder, rejects symlinked/non-owner/world-accessible directories, and continues to use `openat`, `O_NOFOLLOW`, `O_EXCL`, `0600` and synthetic `bbx-test-*.txt` filenames. This path is never supplied by the MCP client or Node.

A first signed host process creates/reads a synthetic note and exits. A **separate native host invocation** then tries to read the same bytes, denies a duplicate write and a traversal, confirms no mutation, removes the note and rejects a post-delete read. Because `launchd` can reuse an XPC service process, this test proves continuity *across client invocations*, **not** that the worker itself restarted; an explicit worker restart acceptance must be added later. On completion the signed temporary `.app` is deleted, but macOS may retain the application sandbox's scratch directory after the test. The note is removed on the success path; a killed test can leave a harmless synthetic file in the sandbox. Never delete unrelated container data automatically.

This is a deliberate **workspace authority gate**, not a workaround using App Groups or wider disk access. Apple recommends standard Documents paths inside an app's container ([Protecting user data with App Sandbox](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox), [Files and directories](https://developer.apple.com/documentation/technologyoverviews/files-and-directories)). Sharing a container with an unsandboxed Node process via Apple App Groups requires separately supported signing/entitlement and potentially notarization/provisioning ([Accessing files from the macOS App Sandbox](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox)). This experiment **does not grant** that access.

**Remaining gaps:** the real `MCP_WORKSPACE_ROOT` and signed worker's storage scope are intentionally different; we must define their matching policy and explicit data import/export, user approvals, signed-binary identity checks, audit records, cancellation/uncertain-write semantics, and final-worker file/network OS-denial tests. The Node gateway is unchanged; macOS `MCP_SANDBOX=required` continues fail-closed.

### Phase 2D — Native XPC workspace identity and fail-closed policy root comparison

**Phase 2C on-device passed**: the user ran `npm run mcp:mac-xpc-durable` and confirmed sandbox Documents note persistence across **two separate host invocations**, exclusive creation, traversal and overwrite refusal, unchanged content after denials, deletion and post-deletion denial. It did **not** prove a native XPC service restart, MCP policy or audit controls.

Next diagnostic gate, **not a production MCP configuration**:

```sh
npm run mcp:mac-xpc-authority
```

This builds an **independent** `dev.agentblackbox.xpc-authority.worker` service with the same signed App Sandbox restrictions and Documents scratch storage. A fixed `workspace_info` XPC method obtains the opened notes directory with macOS `fcntl(F_GETPATH)`. Its native host supports a special bounded `ROOT - 0` protocol frame and never uses a client-supplied filesystem path to select the worker's root. Node receives the path **in memory**, then applies `validateMacWorkspaceBinding`:

- refuse a distinct or unspecified `MCP_WORKSPACE_ROOT`; do not silently map the gateway's `demo-workspace` into the worker's container
- require canonical absolute container-owned `Data/Documents/AgentBlackBoxScratchNotes` and a private same-owner directory
- reject symlinked or group/world-accessible directory roots

The acceptance script first proves that the existing demo workspace cannot bind to native storage, then proves that an explicitly equal **synthetic test policy root** passes. Finally it reruns the native two-host persistence and denial tests. This is a workspace **comparison**, not cryptographic attestation of the worker: the actual signed native app must be verified before trusting its reported root, and same-user attackers are outside this prototype's trust assumptions. A production integration must require an independent, explicitly configured root, not accept a path simply because a worker reports it.

**Gateway remains unchanged:** no real MCP tool routing, durable user document ingestion, operator approval or authenticated audit. `MCP_SANDBOX=required` continues to refuse execution on macOS. The private worker is test-only and named `bbx-test-*.txt`; the Node policy currently permits a broader set of paths, so those grammars also need harmonization before enabling actual MCP calls.

### Phase 3A — Real MCP policy/approval/audit path with synthetic XPC notes (Mac acceptance pending)

**Phase 2D Mac result PASSED:** The user executed `npm run mcp:mac-xpc-authority` and confirmed the private worker's canonical Documents identity matched an explicitly chosen test policy root, while the unrelated `demo-workspace` was refused. It also repeated signed XPC storage read/write, exclusive-create, path-traversal rejection and cleanup. No signer attestation, XPC service restart or real MCP authorization has been proven by that test alone.

Run the **opt-in** Phase 3A Mac acceptance only:

```sh
npm run mcp:mac-xpc-mcp-acceptance
```

The harness constructs a disposable signed XPC host/service bundle, verifies nested signatures and App Sandbox entitlement, queries the worker's Documents path, rejects the unrelated repo demo workspace, then creates a **fresh isolated audit store and localhost approval controller** in a temporary directory. Through an **in-process-only experimentalLaunch test hook**, it instantiates the *actual* `startGateway` code and the same `guardedToolCall` policy, approval and authenticated audit logic as the existing MCP gateway. The downstream is an experimental test-only MCP adapter that sends bounded stdin frames to a separately signed native host and the private XPC worker.

The acceptance scenario sends genuine **legacy MCP stdio JSON-RPC requests** to the gateway: `initialize`, `tools/list`, blocked traversal, a write **denied through the real dashboard approval endpoint**, a write **explicitly approved through that endpoint**, readback from XPC, a second approved but **native-rejected duplicate write**, and verification of HMAC audit chain validity and the absence of full note content in the audit records. Native files are restricted to synthetic `bbx-test-*.txt` notes; the test removes the approved synthetic note after use. A crash may leave a harmless test file in the sandbox Documents scratch folder. **No real user notes or the existing audit/key/checkpoint history are touched.**

**Security limits that remain critical:**
- The ordinary `src/mcp-gateway.mjs` CLI still uses its fixed bundled Node downstream. Only a direct in-process test harness can pass `experimentalLaunch`, and that hook **refuses `MCP_SANDBOX=required` or any non-macOS platform**. This new test deliberately uses `MCP_SANDBOX=off`; it does **not** prove or enable production required-mode isolation.
- The Node/native host process is **unsandboxed** in this experiment, while the private XPC worker is the enforced filesystem/network boundary; the host's native service still only supports the synthetic note filename grammar. A production implementation requires trusted code-signing identity checks beyond ad-hoc signature syntax, and authenticated/authorized binding of the bridge to the intended service.
- Policy path checks and native exclusive-create checks are not an atomic authorization transaction across processes. We must address TOCTOU, XPC service identity, cancellation, crash recovery, unknown write outcome, and mismatched native/Node filename grammars.
- The acceptance uses an isolated disposable audit history rather than the real user's authentic historical events. It tests **legacy** MCP only; modern protocol and SDK interoperability through the native path need their own Mac runtime acceptance.
- The native scratch Documents container persists across test invocations, but may retain synthetic orphan notes after abrupt termination. Never expose it as a real document workspace until lifecycle management, explicit import/export and cleanup are designed.

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
