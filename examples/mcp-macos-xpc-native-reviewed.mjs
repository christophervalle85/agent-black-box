/**
 * Opt-in real Mac signed native Touch ID -> XPC test. The signed Objective-C
 * host, not Node, creates the immutable synthetic review, obtains biometric
 * success and sends bounded bytes. This is NOT the MCP import controller,
 * audited grant, native picker nor production entitlement.
 */
import {spawnSync} from 'node:child_process';
import {copyFileSync,mkdirSync,mkdtempSync,rmSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  selectLocalDevelopmentIdentity,parseSignedIdentity,describeCodesignFailure
} from './mcp-macos-xpc-signed-peers.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const native=join(root,'native','macos','xpc');
const HOST_ID='dev.agentblackbox.xpc-snapshot-receipt.host';
const WORKER_ID='dev.agentblackbox.xpc-snapshot-receipt.worker';
const marker=Object.freeze({
  approved:'BBX_REVIEWED_XPC_TOUCHID_APPROVED_TAMPER_REPLAY_BLOCKED\n',
  cancel:'BBX_REVIEWED_XPC_CANCELLED_NO_DISPATCH\n',
  expired:'BBX_REVIEWED_XPC_EXPIRED_NO_DISPATCH\n'
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
async function main(){
  if(process.platform!=='darwin')throw Error('Real macOS required.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Opt-in synthetic test must use MCP_SANDBOX=off.');
  const mode=process.argv[2];
  if(process.argv.length!==3 || (!Object.hasOwn(marker,mode) && mode!=='all'))
    throw Error('Expected exactly one mode: all, approved, cancel or expired.');
  const identity=selectLocalDevelopmentIdentity(command(
    '/usr/bin/security',['find-identity','-v','-p','codesigning'],
    'Apple Development certificate discovery').stdout);
  const temp=mkdtempSync(join(tmpdir(),'bbx-native-reviewed-xpc-'));
  try{
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
      '-DBBX_TEST_NATIVE_REVIEWED_RECEIPT=1'];
    command('/usr/bin/xcrun',['clang',...flags,'-o',host,
      join(native,'ReviewedTransferHost.m'),
      '-framework','Foundation','-framework','LocalAuthentication'],
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
