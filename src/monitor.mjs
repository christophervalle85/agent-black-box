import { randomUUID } from 'node:crypto';
import { evaluatePolicy } from './policy.mjs';

const riskScore = { low: 10, medium: 45, high: 75, critical: 95 };

export function redact(text) {
  return String(text)
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED_AWS_KEY]')
    .replace(/\bgh[pousr]_[a-zA-Z0-9_]{20,}\b/g, '[REDACTED_GITHUB_TOKEN]')
    .replace(/\bsk-[a-zA-Z0-9_-]{12,}\b/g, '[REDACTED_TOKEN]')
    .replace(/((?:api[_-]?key|authorization|password|token|secret)\s*[=:]\s*)([^\s&;,"']+)/gi, '$1[REDACTED]')
    .slice(0, 180);
}

export function describeInput(tool, args) {
  // Intentionally avoid logging full arguments, file contents or URL query strings.
  if (!args || typeof args !== 'object') return 'Invalid input';
  if (tool === 'file.write') return `new note: ${redact(args.path ?? '<missing>')} (content not logged)`;
  if (tool === 'file.read') return `path: ${redact(args.path ?? '<missing>')}`;
  if (tool === 'network.fetch') {
    let host = 'invalid URL';
    try { host = new URL(args.url).host; } catch { /* ignore malformed input */ }
    return `${redact(args.method ?? '?')} ${redact(host)}`;
  }
  if (tool === 'shell.exec') return 'Shell command requested (arguments not retained)';
  return 'Tool arguments not retained';
}

/**
 * Pre-execution guard for in-process tools. A callback is invoked only on ALLOW.
 * This cannot intercept calls that bypass the wrapper.
 */
export async function guardedToolCall({ agentId, runId, tool, args, execute, store, workspaceRoot, source = 'integration', requestApproval }) {
  if (typeof execute !== 'function') throw new TypeError('An execution callback is required.');
  const policy = evaluatePolicy(tool, args, workspaceRoot);
  // A human approves these exact primitive values, not mutable model objects.
  const reviewedArgs = policy.decision === 'review' ? Object.freeze({ path: args.path, content: args.content }) : null;
  const start = performance.now();
  const event = {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    runId: String(runId), agentId: String(agentId), source,
    tool, input: describeInput(tool, args),
    decision: policy.decision, risk: policy.risk,
    riskScore: riskScore[policy.risk], ruleId: policy.ruleId,
    reason: policy.reason,
    outcome: policy.decision === 'block' ? 'blocked' : 'success',
    summary: policy.decision === 'block' ? 'Execution prevented by policy.' : '',
    durationMs: 0
  };

  if (policy.decision === 'review') {
    // A review record is persisted before the operator can authorize execution.
    event.approvalId = event.id;
    event.outcome = 'pending';
    event.summary = 'Awaiting one-time human approval. No execution yet.';
    store.add({ ...event });
    let response = { approved: false, reason: 'No approval service available; failed closed.' };
    if (typeof requestApproval === 'function') {
      try { response = await requestApproval({ id: event.approvalId, agentId, runId, tool, args: reviewedArgs, input: event.input }); }
      catch { response = { approved: false, reason: 'Approval service failed; denied.' }; }
    }
    event.id = randomUUID();
    event.timestamp = new Date().toISOString();
    event.decision = response?.approved === true ? 'allow' : 'block';
    event.ruleId = response?.approved === true ? 'APPROVAL_GRANTED' : 'APPROVAL_DENIED';
    event.reason = response?.approved === true ? 'The local operator approved this exact note creation.' : 'Human approval was not granted.';
    event.outcome = response?.approved === true ? 'success' : 'blocked';
    event.summary = response?.approved === true ? 'Human approval granted; executing controlled adapter.' : 'Note creation prevented: approval denied, unavailable, or expired.';
    if (event.decision === 'block') {
      event.durationMs = Math.round((performance.now() - start) * 10) / 10;
      store.add({ ...event });
      return { event, result: null };
    }
  }
  if (policy.decision === 'block') {
    event.durationMs = Math.round((performance.now() - start) * 10) / 10;
    store.add(event);
    return { event, result: null };
  }

  try {
    const result = await execute(reviewedArgs ?? args);
    event.outcome = result?.simulated ? 'simulated' : 'success';
    event.summary = redact(result?.summary ?? 'Tool completed (output not recorded).');
    event.durationMs = Math.round((performance.now() - start) * 10) / 10;
    store.add(event);
    return { event, result: result?.value };
  } catch (error) {
    event.outcome = 'error';
    event.summary = 'Execution failed; raw error details withheld from audit storage.';
    event.durationMs = Math.round((performance.now() - start) * 10) / 10;
    store.add(event);
    return { event, result: null, error };
  }
}
