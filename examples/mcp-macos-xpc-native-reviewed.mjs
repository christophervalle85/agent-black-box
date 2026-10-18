/**
 * Opt-in real Mac signed native Touch ID -> XPC test. The signed Objective-C
 * host, not Node, creates the immutable synthetic review, obtains biometric
 * success and sends bounded bytes. This is NOT the MCP import controller,
 * audited grant, native picker nor production entitlement.
 */
import {spawnSync} from 'node:child_process';
import {copyFileSync,mkdirSync,mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {AuditStore} from '../src/audit.mjs';
import {createMacTransferIntent} from '../src/macos-transfer-intent.mjs';
import {createAuditedMacTransferController} from '../src/macos-transfer-controller.mjs';
import {
  createCanonicalMacReviewedTransaction,encodeCanonicalMacReviewedHandoff
} from '../src/macos-reviewed-transaction.mjs';
import {
  selectLocalDevelopmentIdentity,parseSignedIdentity,describeCodesignFailure
 } from './mcp-macos-xpc-signed-peers.mjs';
import {
  createEphemeralMacControllerSigner,encodeMacReviewedRsaHandoff,
  formatPinnedMacRsaPublicHeader
} from '../src/macos-reviewed-signed-authority.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const native=join(root,'native','macos','xpc');
const HOST_ID='dev.agentblackbox.xpc-snapshot-receipt.host';
const WORKER_ID='dev.agentblackbox.xpc-snapshot-receipt.worker';
const marker=Object.freeze({
  approved:'BBX_REVIEWED_XPC_TOUCHID_APPROVED_TAMPER_REPLAY_BLOCKED\n',
  cancel:'BBX_REVIEWED_XPC_CANCELLED_NO_DISPATCH\n',
  expired:'BBX_REVIEWED_XPC_EXPIRED_NO_DISPATCH\n',
  'handoff-invalid':'BBX_REVIEWED_XPC_INVALID_HANDOFF_NO_AUTH_NO_XPC\n',
  'handoff-approved':'BBX_REVIEWED_XPC_PREISSUED_TOUCHID_ACCEPTED\n',
  'handoff-rsa-invalid':'BBX_REVIEWED_XPC_INVALID_RSA_HANDOFF_NO_AUTH_NO_XPC\n',
  'handoff-rsa-approved':'BBX_REVIEWED_XPC_RSA_PREISSUED_TOUCHID_ACCEPTED\n',
  'handoff-rsa-durable-invalid':'BBX_REVIEWED_XPC_INVALID_RSA_HANDOFF_NO_AUTH_NO_XPC\n',
  'handoff-rsa-durable-approved':'BBX_REVIEWED_XPC_RSA_DURABLE_TOUCHID_ACCEPTED\n',
  'handoff-rsa-durable-replay':'BBX_REVIEWED_XPC_DURABLE_REPLAY_REJECTED\n'
});
export function assessNativeReviewedXpc(mode,outcome){
  if(!Object.hasOwn(marker,mode))
    throw Error('Unsupported signed native reviewed XPC mode.');
  if(!outcome || outcome.error || outcome.signal || outcome.status!==0 ||
     outcome.stdout!==marker[mode] || outcome.stderr!=='')
    throw Error('Signed native Touch ID to XPC acceptance not proven.');
  return true;
}
function command(tool,args,label,{timeout=30000,maxBuffer=16000}={}){
  const res=spawnSync(tool,args,{encoding:'utf8',timeout,maxBuffer,
    env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C'}});
  if(res.error || res.signal || res.status!==0){
    if(tool==='/usr/bin/codesign' && args.includes('--sign'))
      throw Error(label+' failed ('+describeCodesignFailure(res)+
        '); native transfer authority NOT accepted.');
    throw Error(label+' failed; native transfer authority NOT accepted.');
  }
  return res;
}
function signingTeam(path,id){
  const code=command('/usr/bin/codesign',[
    '--display','--verbose=4',path],'Signed code verification');
  return parseSignedIdentity(code.stdout+'\n'+code.stderr,id);
}
function verifyWorkerSandbox(worker){
  const info=command('/usr/bin/codesign',[
    '--display','--entitlements','-','--xml',worker],
    'Worker sandbox entitlements');
  const text=info.stdout+'\n'+info.stderr;
  if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(text) ||
     /<key>com\.apple\.security\.network\.(?:client|server)<\/key>\s*<true\s*\/>/.test(text))
    throw Error('Sandboxed XPC worker with no network entitlement required.');
}

/**
 * Diagnostic boundary: one HMAC-verified, trusted in-process review is
 * RESERVED and burned before a real signed host receives its DATA envelope.
 * The scripted controller facet is not a verified human UI; native Touch ID
 * is the independent actual user authentication in this experiment.
 * The host does NOT authenticate the HMAC reservation: this is not a
 * production-ready authorization channel or a bearer-ticket design.
 */
async function auditedHandoff(host,dir,{privateKey=null,durable=false}={}){
  const rsa=privateKey!==null;
  if(durable&&!rsa)throw Error('Durable native replay requires signed controller data.');
  const approveMode=durable?'handoff-rsa-durable-approved':
    rsa?'handoff-rsa-approved':'handoff-approved';
  const invalidMode=durable?'handoff-rsa-durable-invalid':
    rsa?'handoff-rsa-invalid':'handoff-invalid';
  const bytes=Buffer.from('BBX synthetic Touch ID reviewed bytes.\n');
  const now=Date.now();
  const store=new AuditStore(join(dir,'handoff-audit.jsonl'),{
    externalReceiptFile:null
  });
  let callbackCount=0;
  let signedCommittedWire=null;
  const controller=createAuditedMacTransferController({
    store,clock:Date.now,syntheticTimeoutMs:30000,
    syntheticTransport:context=>{
      callbackCount++;
      // Sign only after the independently HMAC-verified reservation event.
      const last=store.list({limit:1})[0];
      if(last?.ruleId!=='MAC_TRANSFER_DISPATCH_RESERVED' ||
         last.approvalId!==context.reviewId)return undefined;
      const wire=rsa?encodeMacReviewedRsaHandoff(context.transaction,{
        privateKey,reservationMac:store.verify().head
      }):encodeCanonicalMacReviewedHandoff(context.transaction);
      if(durable)signedCommittedWire=Buffer.from(wire);
      const observed=spawnSync(host,[approveMode],{
        input:wire,encoding:'utf8',timeout:28000,maxBuffer:1024,
        env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}
      });
      try {
        assessNativeReviewedXpc(approveMode,observed);
      }catch{
        // Unknown native outcome is never success or permission to retry.
        return undefined;
      }
      return 'SYNTHETIC_ACCEPTED';
    }
  });
  const intent=createMacTransferIntent({
    operation:'import',noteName:'bbx-test-reviewed.txt',bytes,now
  });
  const review=controller.host.request(intent);
  const transaction=createCanonicalMacReviewedTransaction(review,{now});
  const valid=rsa?encodeMacReviewedRsaHandoff(transaction,{
    privateKey,reservationMac:store.verify().head,now
  }):encodeCanonicalMacReviewedHandoff(transaction,{now});

  // Negative cases originate from the local harness, NOT the agent.
  // Reject before HMAC approval, Touch ID or signed XPC dispatch.
  const invalid=[
    ['transactionId=',64],
    ['reviewId=',36],
    ['nonce=',36],
    ['sha256=',64],
    ['version=',1],
    ['noteName=',21]
  ];
  for(const [field,length] of invalid){
    const mutated=Buffer.from(valid);
    const pos=mutated.indexOf(field);
    if(pos<0 || pos+field.length+length>mutated.length)
      throw Error('Missing synthetic preflight test vector.');
    const offset=pos+field.length;
    const old=mutated[offset];
    mutated[offset]=old===0x66?0x65:0x66;
    const observed=spawnSync(host,[invalidMode],{
      input:mutated,encoding:'utf8',timeout:2500,maxBuffer:1024,
      env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}
    });
    assessNativeReviewedXpc(invalidMode,observed);
  }
  if(rsa){
    const reject=input=>assessNativeReviewedXpc(invalidMode,spawnSync(host,
      [invalidMode],{
        input,encoding:'utf8',timeout:2500,maxBuffer:1024,
        env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}
      }));
    const changed=Buffer.from(valid);
    const at=changed.indexOf('controllerSig=')+'controllerSig='.length;
    if(at<'controllerSig='.length)throw Error('Missing controller signature.');
    changed[at]=changed[at]===0x66?0x65:0x66;
    reject(changed);
    const changedRes=Buffer.from(valid);
    const atRes=changedRes.indexOf('reservationMac=')+
      'reservationMac='.length;
    if(atRes<'reservationMac='.length)throw Error('Missing audit reservation.');
    changedRes[atRes]=changedRes[atRes]===0x66?0x65:0x66;
    reject(changedRes);
    const foreign=createEphemeralMacControllerSigner();
    reject(encodeMacReviewedRsaHandoff(transaction,{
      privateKey:foreign.privateKey,reservationMac:store.verify().head,now
    }));
    const {reviewId,transactionId,...originalIntent}=transaction;
    const forged=createCanonicalMacReviewedTransaction({
      reviewId:'123e4567-e89b-42d3-a456-426614174001',
      intent:originalIntent
    },{now});
    reject(Buffer.from(valid.toString('ascii')
      .replace('reviewId='+reviewId,'reviewId='+forged.reviewId)
      .replace('transactionId='+transactionId,
        'transactionId='+forged.transactionId),'ascii'));
    reject(valid.subarray(0,-1));
    reject(Buffer.concat([valid,Buffer.from('approved=true\n')]));
    console.log('PASS: Native pinned RSA verifier denied forged controller signature, audit checkpoint and coherent review before Touch ID/XPC.');
  }
  console.log('PASS: Mutated preissued review fields were rejected before Touch ID or XPC.');
  if(!controller.controller.decide(review.reviewId,'approve'))
    throw Error('Trusted local synthetic controller did not stage review.');
  console.log('ACTION: Authenticated test-harness handoff to signed host. Approve ONLY the Touch ID prompt for the fixed synthetic bytes.');
  const result=await controller.host.dispatchSynthetic({
    reviewId:review.reviewId,intent,bytes
  });
  if(result!==true || callbackCount!==1 || store.verify().ok!==true)
    throw Error('Audited synthetic handoff acceptance not established.');
  const end=store.list({limit:20});
  const rules=end.map(e=>e.ruleId);
  if(!rules.includes('MAC_TRANSFER_DISPATCH_RESERVED') ||
     rules[0]!=='MAC_TRANSFER_DISPATCH_SIMULATED' ||
     end.some(e=>e.approvalId!==review.reviewId))
    throw Error('HMAC synthetic dispatch lifecycle did not reconcile.');
  try{
    await controller.host.dispatchSynthetic({
      reviewId:review.reviewId,intent,bytes
    });
    throw Error('Consumed review unexpectedly replayed.');
  }catch(error){
    if(!/No unconsumed/.test(error.message))throw error;
  }
  if(callbackCount!==1)throw Error('One-use native launch check failed.');
  if(durable){
    if(!signedCommittedWire)
      throw Error('Missing durably reserved original signed handoff.');
    // A new native HOST process submits the previously signed transaction.
    // This proves worker filesystem continuity, but does not itself prove
    // launchd restarted the XPC worker between these two host invocations.
    const replay=spawnSync(host,['handoff-rsa-durable-replay'],{
      input:signedCommittedWire,encoding:'utf8',
      timeout:10000,maxBuffer:1024,
      env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}
    });
    assessNativeReviewedXpc('handoff-rsa-durable-replay',replay);
    console.log('PASS: Separate signed native host process received durable worker nonce REPLAY for the identical RSA-reviewed transaction.');
  }
  console.log('PASS: Single HMAC-audited synthetic reservation launched one signed native Touch ID/XPC transaction; consumed review could not be replayed.');
  console.log(durable?
    'NOTE: Test-only worker App Sandbox nonce marker persists; XPC worker restart is not proven. No independently provisioned controller identity, real file transfer or production authority.':
    rsa?
    'NOTE: Public key pinned from an ephemeral local test issuer, not an independently provisioned controller identity. No trusted UI or durable replay; audit is disposable.':
    'NOTE: Local test controller decision and plain stdin record are not a production-authenticated handoff. Audit fixture is disposable.');
}

async function main(){
  if(process.platform!=='darwin')throw Error('Real macOS required.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Opt-in synthetic test must use MCP_SANDBOX=off.');
  const mode=process.argv[2];
  if(process.argv.length!==3 ||
     (!['all','handoff','handoff-rsa','handoff-rsa-durable','approved','cancel','expired'].includes(mode)))
    throw Error('Expected one mode: all, handoff, handoff-rsa, handoff-rsa-durable, approved, cancel or expired.');
  const identity=selectLocalDevelopmentIdentity(command(
    '/usr/bin/security',['find-identity','-v','-p','codesigning'],
    'Apple Development certificate discovery').stdout);
  const temp=mkdtempSync(join(tmpdir(),'bbx-native-reviewed-xpc-'));
  try{
    const durable=mode==='handoff-rsa-durable';
    const rsa=mode==='handoff-rsa'||durable;
    const signer=rsa?createEphemeralMacControllerSigner():null;
    if(signer)writeFileSync(join(temp,'BBXTestPinnedControllerKey.h'),
      formatPinnedMacRsaPublicHeader(signer.publicKey),{mode:0o600,flag:'wx'});
    const app=join(temp,'BlackBoxTransferReceiptHost.app');
    const host=join(app,'Contents','MacOS','BlackBoxTransferReceiptHost');
    const service=join(app,'Contents','XPCServices',
      'BlackBoxTransferReceiptWorker.xpc');
    const worker=join(service,'Contents','MacOS','BlackBoxTransferReceiptWorker');
    mkdirSync(dirname(host),{recursive:true});
    mkdirSync(dirname(worker),{recursive:true});
    copyFileSync(join(native,'TransferReceiptHost-Info.plist'),
      join(app,'Contents','Info.plist'));
    copyFileSync(join(native,'TransferReceiptService-Info.plist'),
      join(service,'Contents','Info.plist'));
    const flags=['-std=c11','-fblocks','-fno-objc-arc','-O2','-Wall',
      '-Wextra','-Werror=implicit-function-declaration',
      '-DBBX_TEST_SIGNED_PEER_REQUIREMENT=1',
      '-DBBX_TEST_NATIVE_REVIEWED_RECEIPT=1',
      '-DBBX_TEST_EXTERNAL_REVIEW_HANDOFF=1',
      ...(rsa?['-DBBX_TEST_RSA_CONTROLLER_HANDOFF=1','-I',temp]:[]),
      ...(durable?['-DBBX_TEST_DURABLE_REPLAY=1']:[])];
    command('/usr/bin/xcrun',['clang',...flags,'-o',host,
      join(native,'ReviewedTransferHost.m'),
      '-framework','Foundation','-framework','LocalAuthentication',
      '-framework','Security'],
      'Native reviewed host compilation');
    command('/usr/bin/xcrun',['clang',...flags,'-o',worker,
      join(native,'TransferReceiptService.m'),'-framework','Foundation'],
      'Native reviewed XPC worker compilation');
    command('/usr/bin/codesign',[
      '--force','--sign',identity,'--options','runtime',
      '--identifier',WORKER_ID,
      '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),
      service],'Reviewed sandbox worker development signing');
    command('/usr/bin/codesign',[
      '--force','--sign',identity,'--options','runtime',
      '--identifier',HOST_ID,app],'Reviewed native host development signing');
    command('/usr/bin/codesign',['--verify','--strict','--deep',app],
      'Native reviewed host nested code integrity');
    command('/usr/bin/codesign',['--verify','--strict',service],
      'Native reviewed XPC worker integrity');
    if(signingTeam(app,HOST_ID)!==signingTeam(service,WORKER_ID))
      throw Error('Signing Team ID mismatch; native review denied.');
    verifyWorkerSandbox(service);
    console.log('PASS: Apple Development-signed native Touch ID host and sandboxed XPC worker verified with matching Team IDs.');
    if(mode==='handoff'||mode==='handoff-rsa'||durable){
      await auditedHandoff(host,temp,{
        privateKey:signer?.privateKey??null,durable
      });
      return;
    }
    // The combined test uses ONE signed app for all three independent
    // transactions, avoiding redundant Keychain private-key prompts.
    const checks=mode==='all'?['expired','approved','cancel']:[mode];
    for(const check of checks){
      console.log('ACTION: Native synthetic '+check+' review. No user files or MCP tools.');
      if(check==='approved')
        console.log('INSTRUCTION: At the native Touch ID prompt, approve with your enrolled fingerprint.');
      else if(check==='cancel')
        console.log('INSTRUCTION: At the native Touch ID prompt, choose Cancel. Do NOT approve this test.');
      else
        console.log('INSTRUCTION: Expired mode requires no Touch ID prompt.');
      const outcome=spawnSync(host,[check],{
        encoding:'utf8',timeout:35000,maxBuffer:1024,
        env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C'}
      });
      assessNativeReviewedXpc(check,outcome);
      if(check==='approved')
        console.log('PASS: Native biometric approval permitted exact bytes once; modified transaction ID, version, target and nonce, altered bytes and replay were denied by the signed XPC worker.');
      else if(check==='cancel')
        console.log('PASS: Explicit user cancellation blocked XPC dispatch within the signed native host.');
      else
        console.log('PASS: Expired synthetic native review denied before biometric prompt or XPC dispatch.');
    }
    console.log('NOTE: No HMAC audit-controller binding, native file selection, real documents, or production sandbox authorization.');
  }finally{
    rmSync(temp,{recursive:true,force:true});
  }
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(error=>{
    console.error('NATIVE REVIEWED XPC NOT ACCEPTED: '+error.message);
    process.exitCode=1;
  });
