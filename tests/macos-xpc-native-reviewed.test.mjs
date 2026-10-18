import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessNativeReviewedXpc} from '../examples/mcp-macos-xpc-native-reviewed.mjs';

const marker={
  approved:'BBX_REVIEWED_XPC_TOUCHID_APPROVED_TAMPER_REPLAY_BLOCKED\n',
  cancel:'BBX_REVIEWED_XPC_CANCELLED_NO_DISPATCH\n',
  expired:'BBX_REVIEWED_XPC_EXPIRED_NO_DISPATCH\n',
  'handoff-invalid':'BBX_REVIEWED_XPC_INVALID_HANDOFF_NO_AUTH_NO_XPC\n',
  'handoff-approved':'BBX_REVIEWED_XPC_PREISSUED_TOUCHID_ACCEPTED\n'
};
const good=mode=>({stdout:marker[mode],stderr:'',status:0,
  signal:null,error:null});
test('native reviewed XPC mode-specific evidence is exact and fail-closed',()=>{
  for(const mode of Object.keys(marker)){
    assert.equal(assessNativeReviewedXpc(mode,good(mode)),true);
    for(const invalid of [
      {...good(mode),status:87},
      {...good(mode),status:null},
      {...good(mode),signal:'SIGKILL'},
      {...good(mode),error:new Error('spawn failed')},
      {...good(mode),stdout:marker[mode]+'extra'},
      {...good(mode),stderr:'sensitive debug'},
      ...Object.keys(marker).filter(x=>x!==mode).map(good)
    ])assert.throws(()=>assessNativeReviewedXpc(mode,invalid));
  }
  assert.throws(()=>assessNativeReviewedXpc('approve',good('approved')));
  assert.throws(()=>assessNativeReviewedXpc('approved',null));
});
test('native host owns authentication and worker validates exact reviewed receipt',()=>{
  const host=readFileSync(new URL(
    '../native/macos/xpc/ReviewedTransferHost.m',import.meta.url),'utf8');
  const worker=readFileSync(new URL(
    '../native/macos/xpc/TransferReceiptService.m',import.meta.url),'utf8');
  const runner=readFileSync(new URL(
    '../examples/mcp-macos-xpc-native-reviewed.mjs',import.meta.url),'utf8');
  for(const requirement of [
    'LAPolicyDeviceOwnerAuthenticationWithBiometrics',
    'touchIDAuthenticationAllowableReuseDuration=0',
    '[context evaluatePolicy:policy',
    'LAErrorUserCancel',
    'reviewIsExact(&review)',
    'BBX_REVIEWED_XPC_CANCELLED_NO_DISPATCH',
    'BBX_REVIEWED_XPC_EXPIRED_NO_DISPATCH',
    'BBX_REVIEWED_XPC_TOUCHID_APPROVED_TAMPER_REPLAY_BLOCKED',
    'bbx_install_same_team_peer_requirement(peer,serviceID)',
    'statusIs(peer,&review,changed,sizeof(changed)',
    '"BAD_REQUEST","bad-transaction-id"',
    '"BAD_REQUEST","bad-version"',
    '"BAD_REQUEST","bad-note"',
    '"BAD_REQUEST","bad-nonce"',
    '"ACCEPTED",NULL)',
    '"REPLAY",NULL)',
    'xpc_dictionary_set_uint64(request,"version",BBX_REVIEWED_VERSION)',
    'xpc_dictionary_set_string(request,"transactionId",review->transactionId)',
    'randomUuid4(review->nonce)',
    'randomUuid4(review->reviewId)',
    'memset_s(changed'
  ])assert.ok(host.includes(requirement),requirement);
  assert.ok(host.includes('const NativeReview committed=review;'));
  assert.ok(host.includes('memcmp(&review,&committed,sizeof(review))!=0'));
  const auth=host.indexOf('const int auth=authenticateReview(&review);');
  const connect=host.indexOf('xpc_connection_t peer=openWorker();',auth);
  assert.ok(auth>0 && connect>auth);
  assert.ok(host.includes('if(auth!=0)'));
  for(const prohibited of ['open(', 'openat(', 'fopen(', 'unlink(', 'system(', 'popen('])
    assert.equal(host.includes(prohibited),false,prohibited);
  for(const requirement of [
    '#ifdef BBX_TEST_NATIVE_REVIEWED_RECEIPT',
    'return valid && count==12',
    'strcmp(method,"reviewed_snapshot_receipt")',
    'statedSize!=count',
    'bbx_reviewed_transaction_id(',
    'bbx_reviewed_equal_hash(expectedId,transactionId)',
    'now<issued || now>=expires',
    'xpc_dictionary_get_uint64(message,"version")',
    'xpc_dictionary_get_string(message,"transactionId")',
    'DIGEST_MISMATCH','REPLAY'
  ])assert.ok(worker.includes(requirement),requirement);
  for(const requirement of [
    "'--identifier',WORKER_ID","'--identifier',HOST_ID",
    'if(signingTeam(app,HOST_ID)!==signingTeam(service,WORKER_ID))',
    'verifyWorkerSandbox(service)',
    "MCP_SANDBOX!=='off'",
    'rmSync(temp,{recursive:true,force:true})'
  ])assert.ok(runner.includes(requirement),requirement);
  assert.ok(runner.includes("mode==='all'?['expired','approved','cancel']:[mode]"));
  assert.ok(runner.includes('for(const check of checks)'));
  assert.ok(runner.includes('assessNativeReviewedXpc(check,outcome)'));
  assert.ok(runner.includes("INSTRUCTION: At the native Touch ID prompt, choose Cancel"));
  assert.ok(!runner.includes('createBlackBoxServer'));
  assert.ok(runner.includes('createAuditedMacTransferController'));
  assert.ok(runner.includes('MAC_TRANSFER_DISPATCH_RESERVED'));
  assert.ok(runner.includes('SYNTHETIC_ACCEPTED'));
  assert.ok(runner.includes("['handoff-approved']"));
  assert.ok(runner.includes("['handoff-invalid']"));
  assert.ok(runner.includes('await auditedHandoff(host,temp)'));
  assert.ok(runner.includes("'BBX_REVIEWED_XPC_PREISSUED_TOUCHID_ACCEPTED"));
  assert.ok(host.includes('#ifdef BBX_TEST_EXTERNAL_REVIEW_HANDOFF'));
  assert.ok(host.includes('bbx_read_preissued_review(stdin,&preissued)'));
  assert.ok(host.indexOf('const bool valid=importPreissuedReview(&review);') <
    host.indexOf('const int auth=authenticateReview(&review);'));
  assert.ok(host.includes('BBX_REVIEWED_XPC_INVALID_HANDOFF_NO_AUTH_NO_XPC'));
});
