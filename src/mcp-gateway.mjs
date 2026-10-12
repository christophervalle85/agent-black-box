/**
 * Agent Black Box v0.4: a deliberately narrow legacy MCP stdio gateway.
 * Supported: initialize, initialized, ping, tools/list, tools/call,
 * cancellation. Everything else is rejected (not transparently forwarded).
 *
 * IMPORTANT: only the bundled downstream MCP demo is launched. No shell,
 * network MCP servers, arbitrary commands, or model-supplied executables.
 */
import { spawn } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { AuditStore } from './audit.mjs';
import { guardedToolCall } from './monitor.mjs';
import { McpPeer, readJsonLines, sendJsonLine } from './mcp-wire.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ALLOWED = Object.freeze({read_note:'file.read',write_note:'file.write'});
const schema = {type:'object',additionalProperties:false};
const EXPOSED_TOOLS = Object.freeze([
  {name:'read_note',description:'Read a regular UTF-8 file from the demo workspace. Sensitive files and path escapes are denied.',inputSchema:{...schema,properties:{path:{type:'string'}},required:['path']}},
  {name:'write_note',description:'Create one new top-level .txt note in the demo workspace. Requires a one-time human approval in the Black Box dashboard.',inputSchema:{...schema,properties:{path:{type:'string'},content:{type:'string'}},required:['path','content']}}
]);
const fail = (id,code,message) => ({jsonrpc:'2.0',id,error:{code,message}});
const toolFailure = message => ({content:[{type:'text',text:message}],isError:true});

function validArgs(name, args) {
  if (!args || typeof args !== 'object' || Array.isArray(args) ||
      Object.keys(args).some(key => !['path','content'].includes(key))) return false;
  if (typeof args.path !== 'string') return false;
  if (name === 'read_note') return Object.keys(args).length === 1;
  return name === 'write_note' && Object.keys(args).length === 2 && typeof args.content === 'string';
}

export async function startGateway({ input = process.stdin, output = process.stdout, env = process.env, onReady } = {}) {
  const workspaceRoot = realpathSync(resolve(env.MCP_WORKSPACE_ROOT ?? join(root,'demo-workspace')));
  const auditFile = resolve(env.MCP_AUDIT_FILE ?? join(root,'data','audit.jsonl'));
  const tokenFile = resolve(env.MCP_TOKEN_FILE ?? join(dirname(auditFile),'mcp-controller-token'));
  const port = Number(env.MCP_CONTROLLER_PORT ?? 4317);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw Error('MCP_CONTROLLER_PORT must be valid.');
  const store = new AuditStore(auditFile);
  const downstream = spawn(process.execPath,[fileURLToPath(new URL('../examples/mcp-notes-server.mjs',import.meta.url))],{
    cwd:root, shell:false, stdio:['pipe','pipe','inherit'],
    env:{BLACKBOX_WORKSPACE_ROOT:workspaceRoot, LANG:'C.UTF-8',PATH:process.env.PATH??'/usr/bin:/bin'}
  });
  const peer = new McpPeer(downstream,{timeoutMs:12000});
  let initialized = false, connected = false, closed = false;
  const active = new Map();
  const gatewayRunId = randomUUID();
  const write = msg => { if (!closed) sendJsonLine(output,msg); };
  async function requestApproval(request,{signal}) {
    if (signal.aborted) return {approved:false};
    // The bearer token never goes to the AI client or the downstream server.
    const token = readFileSync(tokenFile,'utf8').trim();
    const body = JSON.stringify({ id:request.id,runId:request.runId,agentId:request.agentId,tool:request.tool,args:request.args });
    const response = await fetch(`http://127.0.0.1:${port}/api/mcp/approval`,{
      method:'POST',headers:{authorization:`Bearer ${token}`,'content-type':'application/json','host':`127.0.0.1:${port}`},body,signal:AbortSignal.any([signal,AbortSignal.timeout(95000)])
    });
    if (!response.ok) return {approved:false};
    const result = await response.json();
    return {approved:result.approved === true && !signal.aborted};
  }
  async function dispatch(message) {
    const id=message.id;
    const method=message.method;
    if (method === 'initialize') {
      if (connected || !message.params || typeof message.params.protocolVersion !== 'string') return write(fail(id,-32600,'Invalid initialization.'));
      // The gateway supports ONLY the 2025-11-25 protocol. Older clients may
      // disconnect if they cannot negotiate this version, as specified by MCP.
      try {
        const result=await peer.request('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'agent-black-box-gateway',version:'0.4.0'}});
        if (result.protocolVersion !== '2025-11-25' || !result.capabilities?.tools) throw Error('Downstream incompatible.');
        const discovered = await peer.request('tools/list', {});
        const names = discovered?.tools?.map(tool => tool.name);
        if (!Array.isArray(names) || !['read_note','write_note'].every(name => names.filter(n => n === name).length === 1))
          throw Error('Required downstream MCP tools missing or ambiguous.');
      } catch { return write(fail(id,-32000,'MCP downstream initialization failed.')); }
      connected=true;
      return write({jsonrpc:'2.0',id,result:{protocolVersion:'2025-11-25',capabilities:{tools:{}},serverInfo:{name:'agent-black-box-gateway',version:'0.4.0'}}});
    }
    if (!connected || !initialized) return write(fail(id,-32002,'MCP session not initialized.'));
    if (method === 'ping') return write({jsonrpc:'2.0',id,result:{}});
    if (method === 'tools/list') {
      if (message.params?.cursor) return write(fail(id,-32602,'No tool pagination supported.'));
      return write({jsonrpc:'2.0',id,result:{tools:EXPOSED_TOOLS}});
    }
    if (method !== 'tools/call') return write(fail(id,-32601,'Method not permitted by MCP gateway.'));
    if (active.has(id)) return write(fail(id,-32600,'Duplicate active request ID.'));
    if (active.size >= 8) return write(fail(id,-32000,'Gateway concurrency limit exceeded.'));
    const name=message.params?.name;
    const args=message.params?.arguments;
    if (typeof name !== 'string' || name.length > 128 || typeof args !== 'object' || !args || Array.isArray(args)) return write(fail(id,-32602,'Invalid tool parameters.'));
    if (JSON.stringify(args).length > 3500) return write(fail(id,-32602,'Tool arguments too large.'));
    if (typeof id !== 'string' && typeof id !== 'number') return;
    const abort=new AbortController(); active.set(id,abort);
    try {
      const allowedName=Object.hasOwn(ALLOWED,name);
      // Unregistered tools are audited and denied, not forwarded.
      const tool=allowedName?ALLOWED[name]:`mcp.unknown.${name.slice(0,40)}`;
      const safeArgs=validArgs(name,args) ? structuredClone(args) : {};
      const checked=await guardedToolCall({
        agentId:'mcp-client',runId:gatewayRunId,tool,args:safeArgs,store,workspaceRoot,
        source:'mcp-stdio',recordStart:true,signal:abort.signal,
        requestApproval:req=>requestApproval(req,{signal:abort.signal}),
        execute:async fixedArgs=>{
          if (abort.signal.aborted) throw Error('MCP call cancelled.');
          const answer=await peer.request('tools/call',{name,arguments:fixedArgs},{signal:abort.signal});
          if (!Array.isArray(answer.content) || answer.isError) throw Error('Downstream tool execution failed.');
          return {value:answer,summary:`MCP tool ${name} executed; result contents not logged.`};
        }
      });
      if (abort.signal.aborted) return;
      if (checked.event.decision==='block') return write({jsonrpc:'2.0',id,result:toolFailure(`Denied: ${checked.event.ruleId}`)});
      if (checked.event.outcome==='error') return write({jsonrpc:'2.0',id,result:toolFailure('Downstream MCP tool failed; see local audit.')});
      return write({jsonrpc:'2.0',id,result:checked.result});
    } catch { if (!abort.signal.aborted) write({jsonrpc:'2.0',id,result:toolFailure('Gateway unavailable; action not authorized.')}); }
    finally { active.delete(id); }
  }
  const unlisten=readJsonLines(input,{
    maxBytes:16384,
    onMessage:message=>{
      if (closed) return;
      if (message.method==='notifications/initialized' && connected && !Object.hasOwn(message,'id')) {initialized=true;peer.notify('notifications/initialized');return;}
      if (message.method==='notifications/cancelled' && !Object.hasOwn(message,'id')) {active.get(message.params?.requestId)?.abort();return;}
      if (!Object.hasOwn(message,'id')) return;
      if (typeof message.id!=='string' && typeof message.id!=='number') return;
      if (typeof message.method!=='string') return write(fail(message.id,-32600,'Invalid MCP request.'));
      dispatch(message).catch(()=>{try{write(fail(message.id,-32603,'Gateway internal failure.'));}catch{}});
    },
    onError:()=>close()
  });
  function close(){if(closed)return;closed=true;unlisten();for(const abort of active.values())abort.abort();peer.close();}
  input.on('end',close);
  process.once('SIGTERM',close);
  onReady?.({close,downstream,peer});
  return {close,downstream,peer};
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startGateway().catch(error=>{console.error('MCP gateway failed to start:',error.message);process.exitCode=1;});
}
