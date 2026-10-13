import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { planMcpSandbox, downstreamLaunch } from '../src/sandbox.mjs';

function fixture(fn) {
  const root=mkdtempSync(join(tmpdir(),'blackbox-sandbox-'));
  const workspaceRoot=join(root,'workspace');mkdirSync(workspaceRoot);
  const src=join(root,'src');mkdirSync(src);
  const examples=join(root,'examples');mkdirSync(examples);
  const scriptPath=join(examples,'mcp-notes-server.mjs');
  for(const file of [scriptPath,join(src,'policy.mjs'),join(src,'mcp-wire.mjs')])writeFileSync(file,'// test\n');
  try {return fn({root,workspaceRoot,scriptPath});} finally {rmSync(root,{recursive:true,force:true});}
}

test('off mode is explicitly labeled and never forwards untrusted Node environment',()=>fixture(args=>{
  const result=planMcpSandbox({...args,mode:'off'});
  assert.equal(result.enabled,false);
  assert.equal(result.env.BLACKBOX_WORKSPACE_ROOT,args.workspaceRoot);
  assert.equal(result.env.NODE_OPTIONS,undefined);
  assert.equal(result.env.HOME,'/tmp');
}));

test('required mode refuses unsupported macOS rather than launching unsandboxed',()=>fixture(args=>{
  assert.throws(()=>planMcpSandbox({...args,platform:'darwin',mode:'required'}),/signed App Sandbox helper/);
}));

test('Linux plan confines file mounts and denies network via namespace',()=>fixture(args=>{
  // Use /bin/true as placeholder for testing argv; we are testing the *plan*,
  // not claiming a namespace launched successfully in the CI container.
  const p=planMcpSandbox({...args,platform:'linux',mode:'required',bwrap:'/bin/true'});
  assert.equal(p.enabled,true);
  const flat=p.args.join(' ');
  for(const required of ['--unshare-user','--unshare-pid','--unshare-net','--new-session','--die-with-parent','--ro-bind','--bind','--tmpfs'])assert.ok(p.args.includes(required),required);
  assert.ok(flat.includes(args.workspaceRoot));
  assert.ok(!flat.includes(join(args.root,'data')));
  assert.ok(!flat.includes('--ro-bind '+args.root+' '+args.root));
  assert.equal(p.env.NODE_OPTIONS,undefined);
}));

test('required mode validates sandbox binary, never falls back to native spawn',()=>fixture(args=>{
  assert.throws(()=>downstreamLaunch({...args,env:{MCP_SANDBOX:'required',MCP_BWRAP_PATH:'/nonexistent/bwrap'},platform:'linux'}),/Bubblewrap unavailable/);
  assert.throws(()=>downstreamLaunch({...args,env:{MCP_SANDBOX:'required',MCP_BWRAP_PATH:'/nonexistent/bwrap'},platform:'darwin'}),/signed App Sandbox helper/);
  assert.throws(()=>planMcpSandbox({...args,mode:'auto'}),/MCP_SANDBOX must/);
}));
