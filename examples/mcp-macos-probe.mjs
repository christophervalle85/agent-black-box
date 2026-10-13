/**
 * macOS-only, opt-in native sandbox feasibility test. No sandbox-exec profiles.
 * Signs a throwaway Swift executable with Apple's App Sandbox entitlement,
 * checks its signature/entitlements, then tests actual OS-denied operations.
 * Does not change the MCP gateway or its OS-isolation guarantees.
 */
import { spawnSync } from 'node:child_process';
import { connect, createServer } from 'node:net';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assessMacProbe } from '../src/macos-probe-verdict.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const native=join(root,'native','macos');
const exeName='blackbox-sandbox-probe';
const run=(command,args,opts={})=>spawnSync(command,args,{encoding:'utf8',timeout:60000,maxBuffer:256*1024,...opts});
function success(command,args,{title,timeout=60000}={}) {
  const r=run(command,args,{timeout});
  if(r.error||r.status!==0)throw Error((title??command)+' failed: '+(r.error?.message??r.stderr?.trim()??'')+' (exit '+r.status+')');
  return r;
}
function ensureEntitlements(executable) {
  success('/usr/bin/codesign',['--verify','--strict',executable],{title:'codesign verification'});
  const info=success('/usr/bin/codesign',['--display','--entitlements','-','--xml',executable],{title:'codesign entitlement inspection'});
  const xml=info.stdout+'\n'+info.stderr;
  if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(xml))
    throw Error('The native executable lacks an enabled com.apple.security.app-sandbox entitlement.');
  if(/<key>com\.apple\.security\.(?:network\.(?:client|server)|files\.all)<\/key>\s*<true\s*\/>/.test(xml))
    throw Error('Probe has a prohibited network or unrestricted-files entitlement.');
  console.log('PASS: Signed executable has App Sandbox entitlement and no network permissions.');
}
async function endpoint() {
  const server=createServer(socket=>socket.end());
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const port=server.address().port;
  try {
    await new Promise((resolve,reject)=>{
      const client=connect({host:'127.0.0.1',port});
      client.once('connect',()=>{client.destroy();resolve();});
      client.once('error',reject);
      client.setTimeout(2000,()=>{client.destroy();reject(Error('Baseline loopback connection timed out.'));});
    });
  }catch(error){server.close();throw Error('Cannot establish an unsandboxed loopback baseline: '+error.message);}
  return {server,port};
}
async function main() {
  if(process.platform!=='darwin')throw Error('The native App Sandbox feasibility test requires macOS. Linux/Windows are not equivalent.');
  const swift=success('/usr/bin/xcrun',['--find','swiftc'],{title:'Apple Swift compiler lookup'}).stdout.trim();
  console.log('Swift compiler available: '+swift);
  const temporary=mkdtempSync(join(tmpdir(),'agent-black-box-macos-probe-'));
  const privateDir=mkdtempSync(join(homedir(),'.agent-black-box-host-only-'));
  const privateFile=join(privateDir,'user-owned-marker.txt');
  let server;
  try {
    const executable=join(temporary,exeName);
    writeFileSync(privateFile,'test marker: NOT a real credential\n',{mode:0o600});
    if(readFileSync(privateFile,'utf8').length<1)throw Error('Cannot read baseline host test file.');
    success('/usr/bin/xcrun',['swiftc','-O','-o',executable,join(native,'SandboxProbe.swift')],{title:'Swift compilation',timeout:120000});
    success('/usr/bin/codesign',['--force','--sign','-','--options','runtime','--identifier','dev.agentblackbox.sandbox-probe',
      '--entitlements',join(native,'SandboxProbe.entitlements'),executable],{title:'Local ad-hoc signing'});
    ensureEntitlements(executable);
    const listener=await endpoint();server=listener.server;
    const proof=run(executable,['--probe',realpathSync(privateFile),String(listener.port)],{timeout:12000});
    if(proof.error||proof.status!==0)throw Error('Signed helper failed to run: '+(proof.error?.message??proof.stderr?.trim()??'')+' (exit '+proof.status+')');
    let diagnostics;
    try{diagnostics=JSON.parse(proof.stdout);}catch{throw Error('Native probe produced invalid JSON: '+proof.stdout.slice(0,300));}
    const verdict=assessMacProbe(diagnostics);
    for(const check of verdict.checks)console.log((check.passed?'PASS: ':'FAIL: ')+check.name);
    if(!verdict.ok) {
      console.error('Diagnostic (no real credentials):',JSON.stringify({
        hostFileError:diagnostics.hostFileError,networkErrorNumber:diagnostics.networkErrorNumber,
        sandboxHomeError:diagnostics.sandboxHomeError
      }));
      throw Error('macOS isolation is NOT proven. Do not enable required sandbox mode.');
    }
    console.log('PASS: Native macOS sandbox FEASIBILITY proven for the signed test executable only.');
    console.log('NOTE: The Node MCP downstream has NOT been isolated; production XPC implementation remains future work.');
  }finally {
    await new Promise(resolve=>server?server.close(resolve):resolve());
    rmSync(temporary,{recursive:true,force:true});
    rmSync(privateDir,{recursive:true,force:true});
  }
}
main().catch(e=>{console.error('MAC SANDBOX PROBE FAILED: '+e.message);process.exitCode=1;});
