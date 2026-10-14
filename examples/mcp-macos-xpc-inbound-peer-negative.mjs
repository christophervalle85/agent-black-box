/**
 * Real-macOS negative acceptance: an ad-hoc-signed host cannot call an XPC
 * notes worker that enforces Apple's same-team and host signing identifier
 * requirement on the *incoming* peer connection.
 *
 * Build and sign only a throwaway synthetic app + nested private worker.
 * Uses real native worker code; no Developer ID, required mode, or MCP
 * operations are enabled. Timeouts alone NEVER establish authentication.
 */
import {spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {
  copyFileSync,existsSync,mkdtempSync,mkdirSync,readFileSync,rmSync,writeFileSync
} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseBridgeReply} from '../src/macos-xpc-bridge-wire.mjs';
import {validateMacWorkspaceBinding} from '../src/macos-workspace-binding.mjs';
import {inspectMinimalWorkerEntitlements} from '../src/macos-signer-trust.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sources=join(root,'native','macos','xpc');
const workerIdentifier='dev.agentblackbox.xpc-inbound.worker';
const hostIdentifier='dev.agentblackbox.xpc-inbound.host';
const armedName='bbx-test-inbound-armed.txt';
const deliveredName='bbx-test-inbound-delivered.txt';
function command(exe,args,label,{input,timeout=30000}={}){
  const result=spawnSync(exe,args,{
    encoding:'utf8',timeout,input,maxBuffer:128*1024,
    env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C.UTF-8'}
  });
  if(result.error||result.signal||result.status!==0)
    throw Error(label+' failed (status '+result.status+'): '+
      (result.error?.message??result.stderr?.slice(0,500)??'no details'));
  return result;
}
function nativeHost(host){
  return command(host,[],'Unrestricted native ROOT baseline',
    {input:'ROOT - 0\n',timeout:12000});
}
function readNativeRoot(host){
  const text=nativeHost(host).stdout;
  const identity=parseBridgeReply(Buffer.from(text,'utf8'));
  if(!identity.ok)throw Error('Unrestricted baseline returned no native workspace.');
  validateMacWorkspaceBinding({
    configuredRoot:identity.content,reportedRoot:identity.content
  });
  return identity.content;
}
function liveWorker(pid) {
  if(!Number.isSafeInteger(pid)||pid<=0)return false;
  const r=spawnSync('/bin/ps',['-o','stat=','-p',String(pid)],{
    encoding:'utf8',timeout:1500,maxBuffer:1000
  });
  const state=r.stdout?.trim()??'';
  return r.status===0 && state!=='' && !state.startsWith('Z');
}
export function assessInboundPeerRejection({armedPid,workerAlive,deliverySeen,
  hostAnswered,hostRunning,workerMarkerFresh}={}) {
  if(!workerMarkerFresh || !Number.isSafeInteger(armedPid)||armedPid<=0 ||
     workerAlive!==true)
    throw Error('Worker-side signing requirement was not proven installed on a live worker.');
  if(hostRunning!==true || hostAnswered!==false)
    throw Error('Unauthorized native host was not demonstrably blocked while worker lived.');
  if(deliverySeen!==false)
    throw Error('Unauthorized request reached the restricted native worker handler.');
  return true;
}
function dispatch(host){
  const child=spawn(host,[],{
    shell:false,stdio:['pipe','pipe','pipe'],
    env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C.UTF-8'}
  });
  let stdout='',stderr='',error=null,exited=false,overflow=false;
  const completion=new Promise(resolve=>{
    child.on('close',(code,signal)=>{exited=true;resolve({code,signal});});
  });
  child.on('error',e=>{error=e.message;});
  child.stdout.on('data',chunk=>{
    stdout+=chunk.toString('utf8');
    if(stdout.length>3000){overflow=true;child.kill('SIGKILL');}
  });
  child.stderr.on('data',chunk=>{
    stderr+=chunk.toString('utf8');
    if(stderr.length>3000){overflow=true;child.kill('SIGKILL');}
  });
  child.stdin.on('error',()=>{});
  child.stdin.end('ROOT - 0\n');
  return {child,completion,observe:()=>({
    stdout,stderr,error,exited,overflow
  })};
}
async function sleep(ms){await new Promise(resolve=>setTimeout(resolve,ms));}
async function main(){
  if(process.platform!=='darwin')throw Error('Real macOS required.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Synthetic XPC inbound-peer test requires explicit MCP_SANDBOX=off.');
  if(process.argv.slice(2).length!==0)
    throw Error('Unexpected fixture arguments.');
  command('/usr/bin/xcrun',['--find','clang'],'Native compiler');
  const dir=mkdtempSync(join(tmpdir(),'bb-inbound-peer-'));
  let trial,workspace,armedPath,deliveredPath;
  try {
    const app=join(dir,'BlackBoxInboundHost.app');
    const host=join(app,'Contents','MacOS','BlackBoxAuthorityHost');
    const bundle=join(app,'Contents','XPCServices','BlackBoxAuthorityWorker.xpc');
    const worker=join(bundle,'Contents','MacOS','BlackBoxAuthorityWorker');
    mkdirSync(dirname(host),{recursive:true});
    mkdirSync(dirname(worker),{recursive:true});
    const hostPlist=readFileSync(join(sources,'AuthorityHost-Info.plist'),'utf8')
      .replace('dev.agentblackbox.xpc-authority.host',hostIdentifier);
    const workerPlist=readFileSync(join(sources,'AuthorityService-Info.plist'),'utf8')
      .replace('dev.agentblackbox.xpc-authority.worker',workerIdentifier);
    if(!hostPlist.includes(hostIdentifier)||!workerPlist.includes(workerIdentifier))
      throw Error('Synthetic XPC bundle identity fixture incorrect.');
    writeFileSync(join(app,'Contents','Info.plist'),hostPlist);
    writeFileSync(join(bundle,'Contents','Info.plist'),workerPlist);
    command('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2',
      '-Wall','-Wextra','-DBBX_TEST_INBOUND_CLIENT=1',
      '-o',host,join(sources,'AuthorityBridgeHost.c')],
    'Native inbound test host build');
    const workerBuild=(restricted)=>command('/usr/bin/xcrun',
      ['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
       ...(restricted?['-DBBX_TEST_INBOUND_PEER_REQUIREMENT=1']:[]),
       '-o',worker,join(sources,'AuthorityNotesService.m'),
       '-framework','Foundation'],
      restricted?'Restricted XPC worker build':'Baseline XPC worker build');
    const signWorker=()=>command('/usr/bin/codesign',
      ['--force','--sign','-','--options','runtime',
       '--identifier',workerIdentifier,
       '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),
       bundle],'Ad-hoc App Sandbox worker signature');
    const signHost=()=>command('/usr/bin/codesign',
      ['--force','--sign','-','--options','runtime',
       '--identifier',hostIdentifier,app],
      'Ad-hoc host signature');
    const verify=()=>{
      command('/usr/bin/codesign',['--verify','--strict','--deep',app],
        'Nested app signature');
      command('/usr/bin/codesign',['--verify','--strict',bundle],
        'Worker signature');
      const ent=command('/usr/bin/codesign',
        ['--display','--entitlements','-','--xml',bundle],
        'Worker entitlements');
      inspectMinimalWorkerEntitlements(ent.stdout+'\n'+ent.stderr);
    };
    workerBuild(false);
    signWorker();
    signHost();
    verify();
    workspace=readNativeRoot(host);
    console.log('PASS: Baseline ad-hoc native host reached the separate private notes worker.');
    armedPath=join(workspace,armedName);
    deliveredPath=join(workspace,deliveredName);
    // Only remove named markers inside the independently validated disposable
    // service container; no directories, arbitrary user files or source data.
    rmSync(armedPath,{force:true});
    rmSync(deliveredPath,{force:true});
    workerBuild(true);
    signWorker();
    signHost();
    verify();
    console.log('PASS: Test worker re-signed with inbound peer requirement fixture.');
    trial=dispatch(host);
    let armedPid=0;
    const began=Date.now();
    while(Date.now()-began<7000){
      const current=trial.observe();
      if(current.error||current.exited||current.overflow)
        throw Error('Restricted native host terminated before worker identity was armed.');
      if(existsSync(deliveredPath))
        throw Error('Untrusted host request reached native message handler.');
      if(existsSync(armedPath)){
        const match=/^([1-9][0-9]{0,9})\n$/.exec(readFileSync(armedPath,'utf8'));
        if(!match)throw Error('Malformed worker-owned signing requirement marker.');
        armedPid=Number(match[1]);
        break;
      }
      await sleep(40);
    }
    if(!armedPid)throw Error('Worker did not prove OS peer-requirement installation.');
    if(!liveWorker(armedPid))
      throw Error('Worker died after arming its incoming XPC signing requirement.');
    console.log('PASS: Real sandboxed worker installed inbound signing requirement and remained alive.');
    // Incoming peer rejection is *silent* by Apple design. Therefore require
    // BOTH a worker-owned armed marker and a LIVE worker while its request
    // remains blocked. Never count a generic timeout as authentication.
    await sleep(1100);
    const current=trial.observe();
    assessInboundPeerRejection({
      armedPid,workerMarkerFresh:existsSync(armedPath),
      workerAlive:liveWorker(armedPid),deliverySeen:existsSync(deliveredPath),
      hostRunning:!current.exited && !current.error && !current.overflow,
      hostAnswered:current.stdout.length>0
    });
    console.log('PASS: Live worker never delivered the ad-hoc host request to its handler.');
    console.log('PASS: No worker data was returned to the unauthorized host.');
    console.log('PASS: OS-enforced inbound peer-identity rejection accepted (synthetic-only).');
    console.log('NOTE: Positive Developer ID trust and production reciprocal identity remain pending.');
  } finally {
    if(trial){
      try{trial.child.kill('SIGKILL');}catch{}
      await trial.completion;
    }
    if(armedPath)rmSync(armedPath,{force:true});
    if(deliveredPath)rmSync(deliveredPath,{force:true});
    rmSync(dir,{recursive:true,force:true});
  }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(e=>{console.error('INBOUND XPC PEER IDENTITY NOT ACCEPTED: '+e.message);
    process.exitCode=1;});
