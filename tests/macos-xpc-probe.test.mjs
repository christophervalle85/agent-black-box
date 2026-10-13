import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessXpc} from '../examples/mcp-macos-xpc-probe.mjs';

const valid=()=>({hostPID:100,workerPID:101,hostFileDenied:true,hostFileErrno:1,
 networkDenied:true,networkErrorNumber:13,temporaryWriteAllowed:true,temporaryWriteErrno:0});
test('XPC acceptance requires different PID and genuine permission-denied results',()=>{
 const result=assessXpc(valid());
 assert.equal(result.ok,true);assert.equal(result.checks.length,4);
 for(const changes of [{workerPID:100},{hostFileErrno:2},{networkErrorNumber:61},
   {hostFileDenied:false},{networkDenied:false},{temporaryWriteAllowed:false},
   {temporaryWriteErrno:13}])assert.equal(assessXpc({...valid(),...changes}).ok,false);
});
test('XPC probe rejects missing, malformed or untrusted results',()=>{
 for(const candidate of [null,[],{},undefined,{...valid(),workerPID:'101'},
   {...valid(),networkDenied:1}, {...valid(),temporaryWriteErrno:null}])
   assert.throws(()=>assessXpc(candidate));
});
test('XPC private service bundle has correct package type and distinct ID',()=>{
 const h=readFileSync(new URL('../native/macos/xpc/Host-Info.plist',import.meta.url),'utf8');
 const x=readFileSync(new URL('../native/macos/xpc/Service-Info.plist',import.meta.url),'utf8');
 assert.match(h,/<string>APPL<\/string>/);
 assert.match(x,/<string>XPC!<\/string>/);
 assert.match(x,/dev\.agentblackbox\.xpc-probe\.worker/);
 assert.match(x,/<key>XPCService<\/key>/);
 assert.match(h,/dev\.agentblackbox\.xpc-probe\.host/);
});
