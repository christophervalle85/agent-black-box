import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  assessSignedPeerExperiment,parseSignedIdentity,
  selectLocalDevelopmentIdentity
} from '../examples/mcp-macos-xpc-signed-peers.mjs';

const SHA='A'.repeat(40);
const keychain='  1) '+SHA+' "Apple Development: Test User (ABCD123456)"\n     1 valid identities found\n';
const valid=(stdout)=>({
  status:0,signal:null,error:null,stdout,stderr:''
});
const markers=Object.freeze({
  'signed-valid':'BBX_XPC_SIGNED_MUTUAL_ACCEPTED\n',
  'wrong-worker':'BBX_XPC_SIGNED_OUTBOUND_OS_REJECTED\n'
});
test('developer identity selection refuses ad-hoc, absent and ambiguous certificates',()=>{
  assert.equal(selectLocalDevelopmentIdentity(keychain),SHA);
  for(const invalid of [
    '',
    '  0 valid identities found\n',
    '  1) '+SHA+' "Developer ID Application: Test Corp (ABCD123456)"\n     1 valid identities found\n',
    '  1) '+SHA+' "Apple Development: Tester (ABCD123456)"\n  2) '+SHA+' "Apple Development: Other (ABCD123456)"\n     2 valid identities found\n',
    '  1) '+SHA+' "Apple Development: Tester (ABCD123456)"\n     0 valid identities found\n',
    '  1) '+SHA+' "Apple Development: Tester (ABCD123456)"\n     2 valid identities found\n',
    null
  ])assert.throws(()=>selectLocalDevelopmentIdentity(invalid));
});
test('code signature assertions require exact identifier and explicit matching Team ID',()=>{
  const host='Identifier=dev.agentblackbox.xpc-snapshot-receipt.host\nTeamIdentifier=ABCD123456\n';
  const worker='Identifier=dev.agentblackbox.xpc-snapshot-receipt.worker\nTeamIdentifier=ABCD123456\n';
  assert.equal(parseSignedIdentity(host,'dev.agentblackbox.xpc-snapshot-receipt.host'),'ABCD123456');
  assert.equal(parseSignedIdentity(worker,'dev.agentblackbox.xpc-snapshot-receipt.worker'),'ABCD123456');
  for(const invalid of [
    'Identifier=wrong.app\nTeamIdentifier=ABCD123456\n',
    'Identifier=dev.agentblackbox.xpc-snapshot-receipt.host\nTeamIdentifier=not set\n',
    'Identifier=dev.agentblackbox.xpc-snapshot-receipt.host\n',
    'Identifier=dev.agentblackbox.xpc-snapshot-receipt.host\nTeamIdentifier=ABCD123456\nTeamIdentifier=ABCD123456\n',
    null
  ])assert.throws(()=>parseSignedIdentity(invalid,'dev.agentblackbox.xpc-snapshot-receipt.host'));
});
test('native signed positive and wrong-worker OS negative must produce exact evidence',()=>{
  for(const mode of Object.keys(markers)){
    const accepted=valid(markers[mode]);
    assert.equal(assessSignedPeerExperiment(mode,accepted),true);
    for(const bad of [
      {...accepted,status:85},
      {...accepted,stdout:'BBX_XPC_SIGNED_PEER_GATE_UNAVAILABLE\n'},
      {...accepted,stdout:'BBX_XPC_SIGNED_PEER_NOT_ACCEPTED\n'},
      {...accepted,stdout:markers[mode]+'extra\n'},
      {...accepted,stdout:markers[mode]+'path=/Users/private\n'},
      {...accepted,stderr:'XPC error\n'},
      {...accepted,signal:'SIGKILL'},
      {...accepted,error:new Error('native crashed')},
      {...accepted,status:null},
      valid(markers[mode==='signed-valid'?'wrong-worker':'signed-valid'])
    ])assert.throws(()=>assessSignedPeerExperiment(mode,bad));
  }
  assert.throws(()=>assessSignedPeerExperiment('valid',valid(markers['signed-valid'])));
});
test('OS peer requirements are opt-in for developer-signed diagnostic only',()=>{
  const worker=readFileSync(new URL(
    '../native/macos/xpc/TransferReceiptService.m',import.meta.url),'utf8');
  const host=readFileSync(new URL(
    '../native/macos/xpc/TransferReceiptHost.c',import.meta.url),'utf8');
  const harness=readFileSync(new URL(
    '../examples/mcp-macos-xpc-signed-peers.mjs',import.meta.url),'utf8');
  assert.match(worker,/#ifdef BBX_TEST_SIGNED_PEER_REQUIREMENT/);
  assert.match(host,/#ifdef BBX_TEST_SIGNED_PEER_REQUIREMENT/);
  assert.match(worker,/#include "PeerRequirementGate.h"/);
  assert.match(host,/#include "PeerRequirementGate.h"/);
  assert.match(worker,/bbx_install_same_team_peer_requirement\(\s*peer,"dev\.agentblackbox\.xpc-snapshot-receipt\.host"\)/);
  assert.match(host,/bbx_install_same_team_peer_requirement\(\s*peer,requiredIdentifier\)/);
  assert.match(host,/XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT/);
  assert.match(host,/dev\.agentblackbox\.xpc-snapshot-receipt\.wrong-worker/);
  assert.match(worker,/xpc_connection_resume\(peer\)/);
  assert.match(host,/xpc_connection_resume\(peer\)/);
  assert.match(harness,/BBX_TEST_SIGNED_PEER_REQUIREMENT=1/);
  assert.match(harness,/--force','--sign',signingIdentity/);
  assert.match(harness,/if\(hostTeam!==workerTeam\)/);
  assert.match(harness,/--verify','--strict','--deep'/);
  assert.match(harness,/com\\\.apple\\\.security\\\.app-sandbox/);
  assert.match(harness,/MCP_SANDBOX!=='off'/);
  assert.doesNotMatch(harness,/createBlackBoxServer|createAuditedMacTransferController/);
});
