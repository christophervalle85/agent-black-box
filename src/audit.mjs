import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { EventEmitter } from 'node:events';
import { groupAuditEvents, filterActivity } from './activity.mjs';

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

  activity({ limit = 300, decision, runId } = {}) {
    // Group BEFORE limiting or filtering so the final decision isn't detached
    // from the pending event. Raw events remain available at /api/events.
    const safeLimit = Math.max(1, Math.min(Number(limit) || 300, 1000));
    const groups = groupAuditEvents(this.list({ limit: 1000, runId }));
    return filterActivity(groups, decision).slice(0, safeLimit);
  }

  stats() {
    // The window is explicitly bounded; totals are for requests represented by
    // the latest 1,000 audit events, not lifetime totals.
    const events = this.list({ limit: 1000 });
    const activity = groupAuditEvents(events);
    const count = decision => activity.filter(item => item.decision === decision).length;
    return {
      total: activity.length,
      auditEvents: events.length,
      allowed: count('allow'),
      blocked: count('block'),
      pending: count('review'),
      errors: activity.filter(item => item.outcome === 'error').length,
      highRisk: activity.filter(item => item.risk === 'high' || item.risk === 'critical').length,
      runs: new Set(activity.map(item => item.runId)).size,
      window: 'Tool requests represented in latest 1,000 audit events'
    };
  }
}
