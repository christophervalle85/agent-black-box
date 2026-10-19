/**
 * v0.8 opt-in native operator import/export acceptance, NOT an MCP tool or
 * released macOS required-mode implementation.
 *
 * Never accept a host filesystem path from the CLI, model, or IPC.
 * AppKit alone selects real source/destination. The sandboxed XPC worker
 * receives only narrow test note names and bounded UTF-8 note contents.
 *
 * Apple Development-signed host/worker; worker checks incoming host OS
 * identity. An HMAC audit records only redacted event metadata. Signing
 * and audit keys are still same-user local, not independent trust anchors.
 */
import {spawnSync} from 'node:child_process';
import {copyFileSync,mkdirSync,mkdtempSync,rmSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {AuditStore} from '../src/audit.mjs';
import {
  selectLocalDevelopmentIdentity,parseSignedIdentity,
  describeCodesignFailure
} from './mcp-macos-xpc-signed-peers.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const native=join(root,'native','macos','xpc');
const hostId='dev.agentblackbox.xpc-authority.host';
const workerId='dev.agentblackbox.xpc-authority.worker';
const note=/^bbx-test-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\.txt$/;
const resultPattern=/^BBX_OPERATOR_(IMPORT|EXPORT)_COMMITTED (bbx-test-[a-f0-9-]+\.txt) ([1-9][0-9]{0,3}) ([a-f0-9]{64})\n$/;

export function assessOperatorTransfer(mode,observed,{requestedName=null}={}){
  if(!['import','export'].includes(mode))
    throw Error('Unsupported native transfer mode.');
  if(!observed||observed.error||observed.signal||
     observed.status!==0||observed.stderr!==''||
     typeof observed.stdout!=='string')
    throw Error('Native operator transfer produced no accepted receipt.');
  const matched=resultPattern.exec(observed.stdout);
  if(!matched||matched[1]!==(mode==='import'?'IMPORT':'EXPORT')||
     !note.test(matched[2])||
     (requestedName!==null&&requestedName!==matched[2])||
     Number(matched[3])>2000)
    throw Error('Native operator transfer receipt invalid.');
  return Object.freeze({noteName:matched[2],byteLength:Number(matched[3]),
    sha256:matched[4]});
}
/**
 * Render compiler failures without printing local home directories, selected
 * file paths, signing identities, or raw (potentially sensitive) diagnostics.
 */
export function summarizeNativeBuildFailure(stderr=''){
  if(typeof stderr!=='string')return 'No compiler diagnostic available.';
  const cleaned=stderr.split(/\r?\n/).flatMap(line=>{
    const source=/(?:^|\/)([A-Za-z][\w.-]*\.(?:m|c|h)):(\d+):(\d+):\s*(fatal\s+)?error:\s*(.*)/.exec(line);
    if(source)return [source[1]+':'+source[2]+':'+source[3]+
      ': '+(source[4]??'')+'error: '+source[5].slice(0,220)];
    const linker=/^(?:ld: |clang: error: )(.*)/.exec(line);
    if(linker)return ['linker/compiler: '+linker[1].replace(/\/[^\s"'():]+/g,'<path>').slice(0,220)];
    return [];
  });
  return cleaned.length?cleaned.slice(0,4).join(' | '):
    'No recognized compiler error line (use xcrun clang locally for diagnostics).';
}
function command(binary,args,label,{timeout=90000}={}){
  const result=spawnSync(binary,args,{
    encoding:'utf8',timeout,maxBuffer:16384,
    env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}
  });
  if(result.error||result.signal||result.status!==0){
    const extra=binary==='/usr/bin/codesign'&&args.includes('--sign')?
      ' ('+describeCodesignFailure(result)+')':'';
    const diagnostic=binary==='/usr/bin/xcrun'&&args[0]==='clang'?
      ' — '+summarizeNativeBuildFailure(result.stderr):'';
    throw Error(label+' denied'+extra+diagnostic);
  }
  return result;
}
function signedTeam(path,id){
  const output=command('/usr/bin/codesign',['--display','--verbose=4',path],
                       'Native signed identity inspection');
  return parseSignedIdentity(output.stdout+'\n'+output.stderr,id);
}
function requireSandbox(worker){
  const report=command('/usr/bin/codesign',[
    '--display','--entitlements','-','--xml',worker
  ],'Native worker entitlements');
  const output=report.stdout+'\n'+report.stderr;
  if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(output)||
     /<key>com\.apple\.security\.network\.(client|server)<\/key>\s*<true\s*\/>/.test(output))
    throw Error('Signed XPC worker must be sandboxed with no network entitlement.');
}
function build(temp,identity){
  const app=join(temp,'BlackBoxOperatorTransferHost.app');
  const host=join(app,'Contents','MacOS','BlackBoxOperatorTransferHost');
  const service=join(app,'Contents','XPCServices','BlackBoxAuthorityWorker.xpc');
  const worker=join(service,'Contents','MacOS','BlackBoxAuthorityWorker');
  mkdirSync(dirname(host),{recursive:true});
  mkdirSync(dirname(worker),{recursive:true});
  copyFileSync(join(native,'OperatorTransferHost-Info.plist'),
               join(app,'Contents','Info.plist'));
  copyFileSync(join(native,'AuthorityService-Info.plist'),
               join(service,'Contents','Info.plist'));
  const flags=['-std=c11','-fblocks','-O2','-Wall','-Wextra',
    '-Werror=implicit-function-declaration'];
  // xpc_object_t requires explicit xpc_release() in this C/ObjC host.
  // ARC and manual XPC lifetime management must not be mixed.
  command('/usr/bin/xcrun',['clang',...flags,'-o',host,
    join(native,'OperatorTransferHost.m'),'-framework','AppKit',
    '-framework','Foundation','-framework','LocalAuthentication'],
    'Operator transfer native host build');
  command('/usr/bin/xcrun',['clang',...flags,'-DBBX_NATIVE_OPERATOR_TRANSFER=1',
    '-o',worker,join(native,'AuthorityNotesService.m'),
    '-framework','Foundation'],'Operator transfer XPC worker build');
  command('/usr/bin/codesign',['--force','--sign',identity,'--options','runtime',
    '--identifier',workerId,
    '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),
    service],'Native worker signing');
  command('/usr/bin/codesign',['--force','--sign',identity,'--options','runtime',
    '--identifier',hostId,app],'Native operator host signing');
  command('/usr/bin/codesign',['--verify','--strict','--deep',app],
    'Native host and nested worker seal');
  command('/usr/bin/codesign',['--verify','--strict',service],
    'Native operator worker signature');
  if(signedTeam(app,hostId)!==signedTeam(service,workerId))
    throw Error('Operator transfer host and worker signing Team IDs differ.');
  requireSandbox(service);
  return host;
}
function auditEvent(store,ruleId,decision,outcome,summary,metadata=null){
  store.verify();
  store.add({
    id:randomUUID(),timestamp:new Date().toISOString(),
    runId:'mac-operator-transfer-v0.8',
    agentId:'trusted-local-operator',source:'native-macos-operator-transfer',
    tool:'native.operator.transfer',
    input:'Opt-in interactive native file picker; host paths omitted',
    decision,outcome,risk:'high',riskScore:85,ruleId,
    summary,reason:summary,durationMs:0,
    ...(metadata===null?{}:{approvalId:metadata.noteName,
      transferBytes:metadata.byteLength,
      transferSHA256:metadata.sha256})
  });
  store.verify();
}
async function main(){
  if(process.platform!=='darwin')
    throw Error('Interactive macOS required.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Explicit MCP_SANDBOX=off required; normal MCP gateway is unchanged.');
  const mode=process.argv[2],name=process.argv[3]??null;
  const buildOnly=mode==='build-check'&&process.argv.length===3;
  if(!buildOnly&&(!(['import','export'].includes(mode))||
     (mode==='import'&&process.argv.length!==3)||
     (mode==='export'&&(process.argv.length!==4||!note.test(name)))))
    throw Error('Use build-check, import, or export followed by the EXACT bbx-test-UUID.txt printed after a successful import.');
  const identity=selectLocalDevelopmentIdentity(command('/usr/bin/security',[
    'find-identity','-v','-p','codesigning'
  ],'Apple Development identity lookup').stdout);
  const temp=mkdtempSync(join(tmpdir(),'bbx-native-operator-transfer-'));
  try {
    const host=build(temp,identity);
    if(buildOnly){
      console.log('PASS: Operator native host compiled; Apple Development host/XPC signatures, Team IDs and App Sandbox entitlements verified. No picker, Touch ID, transfer or HMAC audit was launched.');
      return;
    }
    const folder=join(homedir(),'Library','Application Support',
                      'AgentBlackBox','OperatorTransfer');
    mkdirSync(folder,{recursive:true,mode:0o700});
    const store=new AuditStore(join(folder,'operator-transfers.jsonl'),{
      externalReceiptFile:null
    });
    auditEvent(store,'MAC_OPERATOR_TRANSFER_OPENED','review','pending',
      'Separate signed native operator transfer initiated; no operation claimed.');
    console.log('PASS: Native operator host and sandboxed XPC worker verified with matching Apple Team ID; worker requires OS-verified incoming host.');
    console.log(mode==='import'?
      'ACTION: Select one small, NON-SENSITIVE text file in the native Open Panel and approve fresh Touch ID.':
      'ACTION: Choose a NEW export destination in the Save Panel and approve fresh Touch ID. Existing files are never overwritten.');
    const observed=spawnSync(host,mode==='import'?[mode]:[mode,name],{
      encoding:'utf8',timeout:130000,maxBuffer:4096,
      env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}
    });
    if(observed.status===83&&!observed.error&&!observed.signal&&
       observed.stdout===''&&observed.stderr===''){
      auditEvent(store,'MAC_OPERATOR_TRANSFER_CANCELLED','block','blocked',
        'Native picker or native biometric consent explicitly cancelled.');
      console.log('PASS: Operator cancellation denied the transfer; no receipt accepted.');
      return;
    }
    if(observed.status===87&&!observed.error&&!observed.signal&&
       observed.stdout===''&&observed.stderr===''){
      auditEvent(store,'MAC_OPERATOR_TRANSFER_DENIED','block','blocked',
        'Native validation or safe filesystem precondition rejected transfer.');
      throw Error('Native transfer rejected without an accepted receipt.');
    }
    let evidence;
    try{evidence=assessOperatorTransfer(mode,observed,{requestedName:name});}
    catch{
      auditEvent(store,'MAC_OPERATOR_TRANSFER_UNCERTAIN','block','error',
        'No authenticated end-to-end native receipt; possible write must not be automatically retried.');
      throw Error('Unknown native transfer outcome; manually reconcile, NEVER retry automatically.');
    }
    auditEvent(store,'MAC_OPERATOR_TRANSFER_NATIVE_RECEIPT','allow','native-test-committed',
      'Native host reported completed bounded transfer; not a production MCP approval.',evidence);
    console.log('PASS: Native Touch ID and user-selected '+mode+
      ' produced an accepted bounded XPC receipt; HMAC metadata audit verified.');
    console.log('NOTE: '+evidence.noteName+
      ' ('+evidence.byteLength+' bytes, SHA256 '+evidence.sha256+').');
    console.log('NOTE: Operator-only test, not a production transfer grant. MCP required mode stays disabled.');
  }finally{rmSync(temp,{recursive:true,force:true});}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(error=>{
    console.error('MAC OPERATOR TRANSFER NOT ACCEPTED: '+error.message);
    process.exitCode=1;
  });
