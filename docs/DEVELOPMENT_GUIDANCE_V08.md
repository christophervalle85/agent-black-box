# v0.8 Development Guidance — Agent Black Box

> **Track:** macOS native security research on `feature/v0.8-native-transfers`. Status updated from the October 17, 2026 real-Mac experiments and subsequent automated audit-reservation tests.
>
> **Release gate:** macOS `MCP_SANDBOX=required` remains **fail-closed**. None of these experiments permit real document import/export, arbitrary filesystem access, or MCP-triggered native transfers.

## Start here

Agent Black Box instruments local AI-agent tools with policy checks and an HMAC-protected audit trail. The v0.8 native work asks a harder security question: how can an **untrusted AI agent** request an operation without ever being able to *assert* the human's approval?

The intended system is:

~~~text
Untrusted agent request (no approval authority)
          |
          v
Trusted review controller + HMAC audit reservation
          |
          v
Verified, immutable transaction handoff
          |
          v
Signed native host + fresh Touch ID decision
          |
          v
Authenticated XPC connection + sandboxed worker
          |
          v
One bounded operation + authenticated/audited result
~~~

**Important:** This is the **target architecture**. The HMAC-audited synthetic dispatch and native Touch ID/XPC tests are currently **two independent experiments**, not one working end-to-end authorization system.

## Milestone tracker

| Boundary | Status | Evidence / limit |
| --- | --- | --- |
| Agent tool policy, guarded MCP and HMAC audit | Existing prototype and unit tests | Local educational system, not a universal OS sandbox |
| Generated fixture selected by NSOpenPanel; pinned-fd snapshot | **Real Mac PASS** | Select and changed-content digest checks, not a concurrent TOCTOU race |
| Bounded synthetic bytes received by XPC worker; process-local nonce denial | **Real Mac PASS** | Ad-hoc experiment, not authorization to open files |
| Apple Development signed host/worker mutual identity and wrong-worker rejection | **Real Mac PASS** | Same Team ID and exact signing identifiers; production signing not proved |
| Wrong-identifier signed incoming host rejected before handler delivery | **Real Mac PASS** | Worker stayed live; unauthorized request did not increase handler count |
| Native Touch ID gated XPC synthetic receipt | **Real Mac PASS** | Expired, approved, cancel, altered bytes and replay tested; not HMAC-controller-integrated |
| HMAC-audited one-time dispatch reservation with injected test callback | **Automated tests PASS** | Simulated callback only; no signed native handoff |
| **Unified audited review -> Touch ID -> signed worker** | **NEXT / NOT IMPLEMENTED** | Currently two different review-ID and nonce issuers |
| Durable recovery and unknown native outcome reconciliation | **NOT IMPLEMENTED** | Crashes/timeouts must never trigger an automatic retry |
| Real selected-file bytes and release-level sandbox | **BLOCKED** | Synthetic fixtures only; `MCP_SANDBOX=required` must refuse execution |

See [the native test log](MACOS_NATIVE_TRANSFER_V08.md) for individual observed acceptance results and [the macOS threat model](MACOS_SANDBOX_V08.md) for background.

## Next engineering milestone: one review, one outcome

**Goal:** The reviewed transaction in the audit controller must be *exactly the same* transaction reviewed by Touch ID and validated by the sandboxed worker. Avoid treating an agent-provided boolean, a copied manifest or a client-generated nonce as authorization.

### Step 1 — One canonical transaction schema

Agree on one authoritative issuer and strict representation for protocol version, operation, bounded target, byte count, SHA-256, nonce, review ID, issued/expiry timestamps and result identity. The Node controller currently creates UUIDv4 values; the native fixture currently generates its own 32-hex review ID and nonce. Simply translating those formats does **not** prove that the reviews are the same or that a human approved either one.

**Acceptance:** fail-closed tests for missing/extra keys, changed operation/target/length/digest, wrong ID/nonce, expired/future timestamps, duplicate attempts, and a second independently minted review. Document which trusted process owns issuance, checking and cancellation.

### Step 2 — Authenticated local handoff, synthetic bytes only

Prototype the handoff across explicit OS-verified signing boundaries without exposing it to the model or the ordinary MCP tool surface. Native Touch ID must apply to the **original frozen, trusted transaction**, not a separate native-generated replacement. The XPC worker must independently validate what it actually receives, including its peer identity and exact bytes.

**Acceptance:** correct signed peers pass on the real Mac, wrong callers fail before handler delivery, and cancelled or altered reviews cannot dispatch. No arbitrary executable paths, file paths, approval flags or hand-authored bearer tokens enter through model-controlled inputs.

### Step 3 — Durable reserve, irrevocable burn, unambiguous outcome

HMAC-verify and durably append the dispatch reservation **before** invoking a potentially effectful native operation. Consume the approval before inspecting a possibly altered dispatch attempt, so a failed attempt cannot be retried with the same approval. Bind every native acknowledgement to the reserved transaction.

**Acceptance:** incomplete audit writes, bad HMAC, changed bytes, forged reply, process crash, dropped XPC reply, deadline expiry, duplicate and concurrent execution all fail closed. A timeout may leave work in flight; classify it **UNCERTAIN**, preserve evidence and require reconciliation rather than automatic retry. Do not confuse the existing simulated callback's result with a signed native receipt.

### Step 4 — Restore selected-fd snapshot, still using generated fixtures

After the full synthetic handoff is accepted, feed the already-reviewed snapshot from the existing user-initiated native file selector into the trusted path. Check regular-file identity, bounded size, same digest and no path substitution. Continue selecting **only the test-generated `bbx-test-*.txt` fixture**, never personal documents.

**Acceptance:** one approved test file's exact bytes pass; wrong file, cancellation, altered content, symlink, changed digest or failed audit is denied without revealing paths or bytes to the AI agent.

### Step 5 — Production review remains separate

Before enabling any real transfer: review signing/distribution requirements, all macOS entitlements and OS-version behavior, host-to-worker peer checks, permission scope, durable replay prevention, restart reconciliation, real file isolation and a release threat model. Keep production macOS `MCP_SANDBOX=required` fail-closed until those tests are independently accepted.

## Day-to-day development commands

In the project directory:

~~~bash
git branch --show-current
# Expected: feature/v0.8-native-transfers

git pull --ff-only origin feature/v0.8-native-transfers
npm test
~~~

GitHub Actions also builds native sources against Apple's macOS SDK. A successful compile or mock regression is **not evidence** that a security check passed on the real Mac.

Re-run the **specific real-Mac acceptance command only when that boundary changes**:

~~~bash
# Apple Development signed peers; expected wrong-worker denial:
MCP_SANDBOX=off npm run mcp:mac-xpc-signed-peers -- both

# Unauthorized incoming host blocked by live worker:
MCP_SANDBOX=off npm run mcp:mac-xpc-inbound-signed

# Touch ID flows: expired (no prompt), approved (fingerprint), cancelled (click Cancel):
MCP_SANDBOX=off npm run mcp:mac-xpc-native-reviewed -- all

# Generated file fixture only; DO NOT select personal documents:
MCP_SANDBOX=off npm run mcp:mac-selected-snapshot -- select
MCP_SANDBOX=off npm run mcp:mac-selected-snapshot -- altered
~~~

### Keychain, Touch ID and failure handling

A Keychain prompt for **`codesign`** asks permission to use the Apple Development *signing key*. When it is the expected test prompt, choose **Allow** rather than **Deny**; `Always Allow` is not needed. A Touch ID prompt is a **different** test of the operator's approval; follow the command's explicit approve/cancel instructions. Never share a password, private key or certificate hash.

A native timeout, absent biometric prompt, generic XPC failure, rejected signing request or a failed command is **not** a passed security negative. Record the failure, debug it, rerun and update the acceptance log only once the exact expected evidence is observed.

## Working agreement and evidence policy

- **Branch:** always `feature/v0.8-native-transfers` for this work. Do not modify `main` or open/merge pull requests without explicit authorization.
- **Scope:** synthetic app-created files and fixed bounded text only, isolated throwaway native bundles, no personal documents, no MCP import/export, no new privileges.
- **Evidence labels:** distinguish *CI unit/compile*, *real-Mac positive*, *real-Mac negative*, *simulated-only*, *pending* and *blocked*. Do not promote a test fixture's passing result into a production claim.
- **Audit:** never write raw bytes, signing identities, secrets, private paths or reusable authorization tokens into records.
- **Iteration:** implement one narrow change, run CI, request only necessary on-device tests, review exact terminal output, update the documented acceptance and blockers, then continue.
- **Resume:** the next implementation should specify and negative-test the shared transaction contract **before** connecting the audited controller to the signed host.

## Recruiter-ready project description

> Built Agent Black Box, a local AI-agent tool-security prototype combining deterministic policy enforcement, MCP gateway controls, HMAC-chained audit evidence and experimental macOS native trust boundaries. Verified signed XPC peer identity, unauthorized-peer rejection, Touch ID-gated synthetic IPC, bounded payload integrity and replay denial on a real Mac. Currently developing a unified HMAC-audited and native-authenticated single-use transaction protocol.

Do **not** claim real Touch ID-authorized document imports, completed end-to-end HMAC/native approval, production Developer ID release acceptance, durable XPC replay recovery or a production-safe general AI sandbox.

[Return to README](../README.md) · [Native acceptance details](MACOS_NATIVE_TRANSFER_V08.md) · [Security considerations](SECURITY.md)
