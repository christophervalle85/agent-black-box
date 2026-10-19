import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessOperatorTransfer,summarizeNativeBuildFailure}
  from '../examples/mcp-macos-operator-transfer.mjs';

const source=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const id='bbx-test-123e4567-e89b-42d3-a456-426614174000.txt';
const digest='a'.repeat(64);
const ok=(mode,name=id)=>({
  status:0,signal:null,stderr:'',stdout:
    'BBX_OPERATOR_'+mode.toUpperCase()+'_COMMITTED '+name+' 25 '+digest+'\n'
});
test('operator transfer receipts require exact direction, canonical test note, bounded byte count and full digest',()=>{
  assert.deepEqual(assessOperatorTransfer('import',ok('import')),{
    noteName:id,byteLength:25,sha256:digest
  });
  assert.deepEqual(assessOperatorTransfer('export',ok('export'),{
    requestedName:id
  }),{noteName:id,byteLength:25,sha256:digest});
  for(const invalid of [
    {...ok('import'),stdout:ok('import').stdout+'extra\n'},
    {...ok('import'),stdout:ok('import').stdout.replace(' 25 ',' 2001 ')},
    {...ok('import'),stdout:ok('import').stdout.replace(digest,'A'.repeat(64))},
    {...ok('import'),stdout:ok('import').stdout.replace('bbx-test-','../')},
    {...ok('import'),status:83},
    {...ok('import'),status:89},
    {...ok('import'),signal:'SIGTERM'},
    {...ok('import'),stderr:'native diagnostic\n'},
    {...ok('import'),stdout:'BBX_OPERATOR_EXPORT_COMMITTED '+id+' 25 '+digest+'\n'}
  ])assert.throws(()=>assessOperatorTransfer('import',invalid));
  assert.throws(()=>assessOperatorTransfer('export',ok('export'),{
    requestedName:'bbx-test-123e4567-e89b-42d3-a456-426614174001.txt'
  }));
});
test('operator-only native file capability is not exposed in normal macOS required mode or MCP tools',()=>{
  const script=source('examples/mcp-macos-operator-transfer.mjs');
  const gateway=source('src/mcp-gateway.mjs');
  const packageFile=JSON.parse(source('package.json'));
  const build=source('native/macos/xpc/OperatorTransferHost.m');
  const worker=source('native/macos/xpc/AuthorityNotesService.m');
  assert.equal(packageFile.scripts['mcp:mac-operator-transfer'],
    'node examples/mcp-macos-operator-transfer.mjs');
  assert.match(script,/process\.env\.MCP_SANDBOX!=='off'/);
  assert.match(script,/process\.platform!=='darwin'/);
  assert.match(script,/selectLocalDevelopmentIdentity/);
  assert.match(script,/parseSignedIdentity/);
  assert.match(script,/requireSandbox\(service\)/);
  assert.match(script,/BBX_NATIVE_OPERATOR_TRANSFER=1/);
  assert.match(script,/MAC_OPERATOR_TRANSFER_UNCERTAIN/);
  assert.match(script,/MAC_OPERATOR_TRANSFER_NATIVE_RECEIPT/);
  assert.match(script,/new AuditStore/);
  assert.doesNotMatch(gateway,/operator[_-]transfer|native\.operator\.transfer/);
  assert.match(worker,/#ifdef BBX_NATIVE_OPERATOR_TRANSFER/);
  assert.match(worker,/bbx_install_same_team_peer_requirement\(peer,/);
  assert.match(worker,/dev\.agentblackbox\.xpc-authority\.host/);
  assert.match(build,/NSOpenPanel \*panel=\[NSOpenPanel openPanel\]/);
  assert.match(build,/NSSavePanel \*panel=\[NSSavePanel savePanel\]/);
  assert.match(build,/LAPolicyDeviceOwnerAuthenticationWithBiometrics/);
  assert.match(build,/O_RDONLY\|O_NOFOLLOW\|O_CLOEXEC/);
  assert.match(build,/O_WRONLY\|O_CREAT\|O_EXCL\|O_NOFOLLOW\|O_CLOEXEC/);
  assert.match(build,/fsync\(fd\)/);
  assert.match(build,/bbx-test-/);
  assert.match(build,/xpc_connection_send_message_with_reply_sync/);
  assert.match(build,/memchr\(bytes,0,used\)==NULL/);
  assert.match(build,/before\.st_ino==after\.st_ino/);
  assert.match(build,/readNote\(peer,note\)/);
  assert.doesNotMatch(build,/system\s*\(|popen\s*\(/);
});
test('unsigned, ad-hoc or automatic feature branch CI cannot silently enable transfer',()=>{
  const script=source('examples/mcp-macos-operator-transfer.mjs');
  const ci=source('.github/workflows/ci.yml');
  const req=source('src/sandbox.mjs');
  assert.ok(script.includes("'--sign',identity"));
  assert.ok(script.includes("'--entitlements'"));
  assert.ok(script.includes("'--verify','--strict','--deep'"));
  assert.ok(ci.includes('branches: [main]'));
  assert.ok(!ci.includes("'feature/v0.8-*'"));
  assert.ok(!req.includes('mcp-macos-operator-transfer.mjs'));
});

test('macOS native operator host uses manual XPC lifetime and exposes redacted Clang build errors',()=>{
  const runner=source('examples/mcp-macos-operator-transfer.mjs');
  assert.match(runner,/const buildOnly=mode==='build-check'/);
  assert.match(runner,/if\(buildOnly\)\{/);
  assert.ok(runner.includes('No picker, Touch ID, transfer or HMAC audit was launched.'));
  const hostBuild=runner.slice(
    runner.indexOf("command('/usr/bin/xcrun',['clang',...flags"),
    runner.indexOf("command('/usr/bin/xcrun',['clang',...flags")+290
  );
  assert.ok(hostBuild.includes("OperatorTransferHost.m"));
  assert.ok(!hostBuild.includes("'-fobjc-arc'"));
  const path='/Users/hidden/work/agent-black-box/native/macos/xpc/OperatorTransferHost.m';
  const issue=summarizeNativeBuildFailure(path+':174:8: error: ARC forbids explicit message send of release\n');
  assert.equal(issue,'OperatorTransferHost.m:174:8: error: ARC forbids explicit message send of release');
  assert.ok(!issue.includes('/Users/hidden/'));
  assert.equal(summarizeNativeBuildFailure('ld: library not found for -lxyz\n'),
    'linker/compiler: library not found for -lxyz');
  assert.match(summarizeNativeBuildFailure('nonspecific error'),/No recognized compiler/);
});
