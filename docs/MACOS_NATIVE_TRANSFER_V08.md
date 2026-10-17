# Phase 6 — Native Selected-File Snapshot (experimental)

## Scope
This feature tests a real, user-initiated macOS NSOpenPanel selection and bounded file-descriptor read of ONE generated synthetic fixture. It is not a document import, MCP tool, production signing, or production macOS sandbox permission. Only the byte count and SHA-256 digest are reported; the file path and contents are not returned.

## Security controls exercised
- Node creates exactly one bbx-test-snapshot.txt in a private temporary directory, with a disposable ad-hoc signed AppKit helper.
- A pre-panel O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK descriptor pins the generated fixture; only the exact selected fixture can be opened after the user acts.
- Both FDs must pass fstat: regular file, owner matches effective UID, exactly one hard link, 1–2000 bytes, identical device/inode/size. Path normalization between /var and /private/var is accepted only for the same inode.
- The selected leaf is opened with O_NOFOLLOW to exclude symlinks; unrelated file selections are rejected before any bytes are read.
- The helper reads only from the already opened selected FD, checking exact length, EOF and unchanged file metadata. A 2KiB buffer is wiped after computing CommonCrypto SHA-256.
- stdout includes only a fixed receipt carrying byte length and lowercase SHA-256. The trusted Node runner requires an exact process outcome and receipt, and uses constant-time digest comparison.
- All fixtures and binaries are deleted after the test. The entire experiment requires MCP_SANDBOX=off, never required mode.

## Real macOS acceptance — passed October 17, 2026
After switching to feature/v0.8-native-transfers and updating it, run each command individually:

    MCP_SANDBOX=off npm run mcp:mac-selected-snapshot -- select
    MCP_SANDBOX=off npm run mcp:mac-selected-snapshot -- altered

Choose ONLY bbx-test-snapshot.txt in the macOS native panel each time. The select mode must confirm the exact original fixture digest. The altered mode intentionally modifies one byte before the chooser opens; the native read must return the altered fixture's digest, and the controller-side verdict must reject it as different from the expected original. This is a CONTENT INTEGRITY negative test, NOT a concurrent filesystem race test. Never select personal documents.

An incorrect selection, cancellation, timeout, missing prompt, unavailable developer tools, or generic error cannot satisfy these acceptance gates.

## Production gates NOT met
Actual native import/export and XPC data transfer remain disabled. The ad-hoc helper is not Developer ID signed, the signed host/worker are not authenticated as same-Team-ID peers in production, a user-initiated picker has not yet been integrated with the review-specific Touch ID/HMAC authority, and durable file capabilities, atomic commit, race-safe transaction handling and worker-side checks remain outstanding. Production MCP_SANDBOX=required stays fail-closed.

Reference: https://developer.apple.com/documentation/Security/accessing-files-from-the-macos-app-sandbox

## October 17, 2026 — native compile failure and prevention

The first real Mac `select` and `altered` snapshot attempts **both failed during compilation**, before opening NSOpenPanel. Apple's Clang reported an undeclared `explicit_bzero` in SelectedFileSnapshot.m. The initial hypothesis was a missing function declaration header; the next macOS CI run demonstrated that adding `strings.h` was insufficient. Neither failed compilation run reached file-descriptor validation. The executable's local build now treats implicit function declarations as errors.

To prevent this Linux-only-CI blind spot, CI has a **macos-15 native compile** job for the snapshot fixture and three previously accepted native helpers using the real Apple SDK and `-Werror=implicit-function-declaration`. A successful macOS compile job confirms only native compilation, not OS prompt behavior, sandbox authorization, or successful file reads. At that stage, both Phase 6 GUI tests still required a real-Mac rerun.

## October 17, 2026 — follow-up CI result and SDK-compatible secure zeroing

The new **real macOS 15 native CI compile job failed** even after adding strings.h: `explicit_bzero` is not declared in the Xcode SDK tested. We therefore replaced `explicit_bzero` with Apple's documented `memset_s`, enabled by defining `__STDC_WANT_LIB_EXT1__ 1` before system headers. The secure_wipe helper treats any unexpected wipe error as fatal instead of continuing. Source contract tests cover the declaration and secure-wipe use.

The macOS compile job remains required and will be checked on this follow-up commit. Both native GUI tests were pending at the time of that fix; the successful results are documented below.

## October 17, 2026 — real Mac selected-file snapshots ACCEPTED

The operator reran both commands on the development Mac after the native-macos-compile CI fix (commit 92a2d796). The following results were observed directly:

- `MCP_SANDBOX=off npm run mcp:mac-selected-snapshot -- select`: **PASS**. The disposable AppKit/Objective-C helper compiled, its ad-hoc signature verified, and the OS picker returned the generated `bbx-test-snapshot.txt`. The already-opened, bounded file descriptor read yielded the expected SHA-256 digest and exact byte count. The helper printed neither the selected path nor its content.
- `MCP_SANDBOX=off npm run mcp:mac-selected-snapshot -- altered`: **PASS**. The same synthetic fixture was deliberately modified by one byte *before opening the panel*. The native helper successfully read and hashed that modified fixture, and the Node verdict rejected the altered digest against the expected original digest. This is controlled content-integrity testing, not a simultaneous modification or filesystem race.

**Acceptance scope complete for this slice:** native file-selection, bounded synthetic FD read, exact digest verification, and altered-content rejection all passed on a real Mac. The four-job CI run for the SDK-compatible source also passed (174/174 Node tests, native compilation, Linux sandbox, and MCP interoperability): https://github.com/christophervalle85/agent-black-box/actions/runs/39071303426

**What the evidence does NOT establish:** a user document was transferred, a native host passed data into XPC, code-signing identities were approved for production, prompt consent and file selection were tied to the same review, or kernel-mediated sandbox access was fully verified. The 2 KiB generated file is the only permitted read target in the present experiment. No release gate for `MCP_SANDBOX=required` was changed.

## Next independent gate: bounded reviewed bytes across authenticated native XPC

The next substantive security step should be a **separately tested, synthetic-only native transfer path**, not a generic request to 'open files'. Before any real document import, enforce these design constraints:

1. The trusted native host must own the NSOpenPanel interaction and read the selected file from a verified descriptor into a bounded, immutable snapshot. A path, copied URL, or digest-only receipt cannot be treated as an XPC authorization grant.
2. Issue one review for the exact operation, synthetic destination, data size, full SHA-256, unpredictable nonce and expiration. Present the review to the operator, run macOS authentication, and confirm pending state and unchanged bytes before authorizing one use.
3. Only a verified host-to-worker XPC channel can deliver the bounded bytes; the private sandboxed worker must independently verify the digest, destination constraints, nonce/authorization state, and single-use semantics. No remote model or ordinary HTTP request may set authority fields.
4. Reject cancel, wrong file, changed bytes, replay, forged or expired review, unauthorized XPC peers, worker crash, timeout, and partial commits with clear HMAC audit outcomes. An uncertain write must not be described as successful.
5. Preserve `MCP_SANDBOX=required` fail-closed until native positive **and** negative Developer ID / same-Team-ID code identity checks, App Sandbox confinement, and end-to-end on-device acceptance are complete.

Next-phase status: **not implemented**. The current Phase 6 commit is not a production document-transfer feature; do not merge or open a review PR until the next cohesive set of security gates is actually supported.

## Phase 6 next slice — bounded synthetic host-to-XPC data receipts (pending Mac acceptance)

An additional isolated test creates a disposable ad-hoc-signed app containing a sandbox-entitled XPC worker. The host transfers fixed 33-byte synthetic bytes inside an XPC DATA field. A separately compiled worker independently validates an exact five-key dictionary, the synthetic filename, 1–2000-byte payload size, 32-character random nonce and 64-character SHA-256 digest. It recomputes the digest over bytes received and refuses a mismatch. A process-local serial-queue nonce cache rejects a second use (up to 64 distinct nonces, then fail-closed). The worker returns only fixed status strings; no payload, file path, or file contents are written to disk or returned. The host checks responses and exposes one fixed outcome marker.

Run each mode separately on an interactive development Mac after updating feature/v0.8-native-transfers:

    MCP_SANDBOX=off npm run mcp:mac-xpc-transfer-receipt -- valid
    MCP_SANDBOX=off npm run mcp:mac-xpc-transfer-receipt -- tamper
    MCP_SANDBOX=off npm run mcp:mac-xpc-transfer-receipt -- replay

Valid must accept one bounded payload with matching digest. Tamper must deny one deliberately changed payload and then accept unmodified bytes with that same nonce, establishing that invalid bytes did not burn a nonce. Replay must accept once and then deny the identical nonce in the SAME XPC worker process. Each test must fail if the worker is unavailable, the process exits abnormally, or a receipt marker differs. The macOS CI job compiles both native files but cannot supply interactive XPC OS acceptance; the real Mac runs remain REQUIRED before marking this gate accepted.

SECURITY LIMITATIONS: This is an ad-hoc-signed transport and digest/replay experiment, not an OS-authenticated XPC peer. The receipt's nonce is generated by the test host and is NOT a Touch ID authorization grant, and its worker-side cache is not durable across crashes/restarts. No native picker-selected contents, controller-approved review bytes, operator-presence proof, MCP operations, document imports, or filesystem writes are connected to this worker. A malicious local client is not prevented from submitting its own well-formed synthetic receipt. Production must require same-Team-ID signing, a verified native consent chain, exact immutable review binding, durable replay protection when meaningful, and fail-closed transaction uncertainty handling. The worker's App Sandbox entitlement is checked, but its full production OS confinement acceptance is still pending. Required macOS sandbox mode remains fail-closed.
