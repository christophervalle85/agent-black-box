import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessInboundPeerRejection} from '../examples/mcp-macos-xpc-inbound-peer-negative.mjs';
const file=p=>readFileSync(new URL(p,import.meta.url),'utf8');
const valid=()=>({
  armedPid:1234,workerAlive:true,workerMarkerFresh:true,
  hostRunning:true,hostAnswered:false,deliverySeen:false
});
test('worker-side peer-identity acceptance requires armed live worker and no incoming messages',()=>{
  assert.equal(assessInboundPeerRejection(valid()),true);
  for(const bad of [
    {armedPid:0},{armedPid:-1},{armedPid:'1234'},
    {workerAlive:false},{workerMarkerFresh:false},
    {hostRunning:false},{hostAnswered:true},{deliverySeen:true}
  ])assert.throws(()=>assessInboundPeerRejection({...valid(),...bad}));
  assert.throws(()=>assessInboundPeerRejection());
});
test('only test worker builds install the OS incoming code-signing requirement before resume',()=>{
  const worker=file('../native/macos/xpc/AuthorityNotesService.m');
  const host=file('../native/macos/xpc/AuthorityBridgeHost.c');
  const script=file('../examples/mcp-macos-xpc-inbound-peer-negative.mjs');
  const ordinary=file('../examples/mcp-macos-xpc-authority.mjs');
  assert.match(worker,/#ifdef BBX_TEST_INBOUND_PEER_REQUIREMENT/);
  assert.match(worker,/"dev\.agentblackbox\.xpc-inbound\.host"/);
  assert.match(worker,/peerGate=bbx_install_same_team_peer_requirement/);
  assert.match(worker,/if\(peerGate!=0/);
  assert.match(worker,/bbx-test-inbound-armed\.txt/);
  assert.match(worker,/bbx-test-inbound-delivered\.txt/);
  assert.ok(worker.indexOf('peerGate=bbx_install_same_team_peer_requirement')<
    worker.indexOf('xpc_connection_resume(peer)'));
  assert.match(worker,/O_EXCL\|O_NOFOLLOW\|O_CLOEXEC/);
  assert.match(host,/#ifdef BBX_TEST_INBOUND_CLIENT/);
  assert.match(host,/"dev\.agentblackbox\.xpc-inbound\.worker"/);
  assert.match(script,/workerBuild\(false\)/);
  assert.match(script,/workerBuild\(true\)/);
  assert.match(script,/inspectMinimalWorkerEntitlements/);
  assert.match(script,/validateMacWorkspaceBinding/);
  assert.match(script,/liveWorker\(armedPid\)/);
  assert.match(script,/MCP_SANDBOX!=='off'/);
  assert.doesNotMatch(ordinary,/BBX_TEST_INBOUND_PEER_REQUIREMENT/);
});
