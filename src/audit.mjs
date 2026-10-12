import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { EventEmitter } from 'node:events';

export class AuditStore extends EventEmitter {
  constructor(filename) {
    super();
    this.filename = filename;
    mkdirSync(dirname(filename), { recursive: true });
    if (!existsSync(filename)) appendFileSync(filename, '');
  }

  add(event) {
    // Persist the audit record before notifying subscribers.
    appendFileSync(this.filename, JSON.stringify(event) + '\n', { mode: 0o600 });
    this.emit('event', event);
    return event;
  }

  list({ limit = 300, decision, runId } = {}) {
    const safeLimit = Math.max(1, Math.min(Number(limit) || 300, 1000));
    const lines = readFileSync(this.filename, 'utf8').split('\n').filter(Boolean);
    const events = [];
    for (let i = lines.length - 1; i >= 0 && events.length < safeLimit; i--) {
      let event;
      try { event = JSON.parse(lines[i]); } catch { continue; }
      if (decision && event.decision !== decision) continue;
      if (runId && event.runId !== runId) continue;
      events.push(event);
    }
    return events;
  }

  stats() {
    const events = this.list({ limit: 1000 });
    const count = key => events.filter(e => e.decision === key).length;
    return {
      total: events.length,
      allowed: count('allow'),
      blocked: count('block'),
      errors: events.filter(e => e.outcome === 'error').length,
      highRisk: events.filter(e => e.risk === 'high' || e.risk === 'critical').length,
      runs: new Set(events.map(e => e.runId)).size,
      window: 'Latest 1,000 audit events'
    };
  }
}
