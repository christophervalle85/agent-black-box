import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const file=p=>readFileSync(new URL(p,import.meta.url),'utf8');

test('Phase 3E keeps native cancellation fault isolated from ordinary service/host',()=>{
  const native=file('../native/macos/xpc/CancellationBridgeHost.c');
  const ordinary=file('../native/macos/xpc/AuthorityBridgeHost.c');
  const plist=file('../native/macos/xpc/CancellationService-Info.plist');
  const worker=file('../native/macos/xpc/CancellationNotesService.m');
  assert.match(native,/BBX_CANCEL_COMMITTED_PID/);
  assert.match(native,/for\(;;\)pause\(\)/);
  assert.match(native,/bbx-test-cancel-after-/);
  assert.ok(native.indexOf('xpc_connection_send_message_with_reply_sync')<
    native.indexOf('BBX_CANCEL_COMMITTED_PID'));
  assert.doesNotMatch(ordinary,/BBX_CANCEL_COMMITTED_PID/);
  assert.match(plist,/dev\.agentblackbox\.xpc-cancel\.worker/);
  assert.match(worker,/xpc_main\(accept_peer\)/);
  assert.doesNotMatch(worker,/BBX_CANCEL_COMMITTED_PID/);
});

test('synthetic adapter tracks native hosts and kills their own process groups on SIGTERM',()=>{
  const script=file('../examples/mcp-macos-xpc-mcp-downstream.mjs');
  assert.match(script,/const nativeHosts=new Set\(\)/);
  assert.match(script,/detached:true/);
  assert.match(script,/process\.kill\(-child\.pid,'SIGKILL'\)/);
  assert.match(script,/process\.once\('SIGTERM'/);
  assert.match(script,/process\.once\('exit',stopActiveNativeHosts\)/);
  assert.match(script,/nativeHosts\.add\(child\)/);
  assert.match(script,/nativeHosts\.delete\(child\)/);
  assert.match(script,/BBX_CANCEL_COMMITTED_PID/);
  assert.match(script,/writeFileSync\(readyFile/);
  assert.match(script,/flag:'wx'/);
});

test('end-to-end cancellation gate checks post-commit note, process exit, HMAC and no fallback',()=>{
 const script=file('../examples/mcp-macos-xpc-cancellation.mjs');
 const gateway=file('../src/mcp-gateway.mjs');
 const wire=file('../src/mcp-wire.mjs');
 const monitor=file('../src/monitor.mjs');
 assert.match(script,/CancellationBridgeHost\.c/);
 assert.match(script,/CancellationNotesService\.m/);
 assert.match(script,/BLACKBOX_XPC_CANCEL_READY_FILE:cancellationReady/);
 assert.match(script,/client\.notify\('notifications\/cancelled',\{requestId:issued\.requestId/);
 assert.match(script,/Cancelled MCP request left a running native host process/);
 assert.match(script,/frameBridgeRequest\('READ',name\)/);
 assert.match(script,/uncertainEvents\.length!==1/);
 assert.match(script,/controller\.store\.verify\(\)/);
 assert.match(script,/Gateway used unexpected downstream after cancellation/);
 assert.match(script,/MCP_SANDBOX:'off'/);
 assert.match(gateway,/active\.get\(msg\.params\?\.requestId\)\?\.abort\(\)/);
 assert.match(wire,/this\.close\(new Error\('Downstream cancelled/);
 assert.match(monitor,/MCP_OUTCOME_UNKNOWN/);
});
