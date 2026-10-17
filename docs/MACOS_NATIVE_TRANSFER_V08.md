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

## Real macOS acceptance — pending
After switching to feature/v0.8-native-transfers and updating it, run each command individually:

    MCP_SANDBOX=off npm run mcp:mac-selected-snapshot -- select
    MCP_SANDBOX=off npm run mcp:mac-selected-snapshot -- altered

Choose ONLY bbx-test-snapshot.txt in the macOS native panel each time. The select mode must confirm the exact original fixture digest. The altered mode intentionally modifies one byte before the chooser opens; the native read must return the altered fixture's digest, and the controller-side verdict must reject it as different from the expected original. This is a CONTENT INTEGRITY negative test, NOT a concurrent filesystem race test. Never select personal documents.

An incorrect selection, cancellation, timeout, missing prompt, unavailable developer tools, or generic error cannot satisfy these acceptance gates.

## Production gates NOT met
Actual native import/export and XPC data transfer remain disabled. The ad-hoc helper is not Developer ID signed, the signed host/worker are not authenticated as same-Team-ID peers in production, a user-initiated picker has not yet been integrated with the review-specific Touch ID/HMAC authority, and durable file capabilities, atomic commit, race-safe transaction handling and worker-side checks remain outstanding. Production MCP_SANDBOX=required stays fail-closed.

Reference: https://developer.apple.com/documentation/Security/accessing-files-from-the-macos-app-sandbox
