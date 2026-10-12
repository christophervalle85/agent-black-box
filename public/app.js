const state = { events: [], policies: [], filter: 'all', view: 'overview', selected: null };
const $ = id => document.getElementById(id);
const text = (node, value) => { node.textContent = String(value); };
const ago = timestamp => {
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(timestamp)) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return new Date(timestamp).toLocaleDateString();
};
const make = (tag, className = '', label = '') => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (label) node.textContent = label;
  return node;
};
const empty = (label = 'No activity to display') => {
  const box = make('div', 'empty-state');
  box.append(make('div', 'empty-icon', '◇'), make('strong', '', label), make('p', '', 'Run the demo agent to generate real policy decisions and explore its audit trail.'));
  return box;
};
const statusLabel = event => event.decision === 'block' ? 'Blocked' : event.outcome === 'error' ? 'Failed' : event.outcome === 'simulated' ? 'Simulated' : 'Allowed';

async function fetchJson(path, options) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
async function refresh() {
  const [ev, stats, pol] = await Promise.all([
    fetchJson('/api/events?limit=300'), fetchJson('/api/stats'), fetchJson('/api/policies')
  ]);
  state.events = ev.events;
  state.policies = pol.policies;
  text($('total-value'), stats.total);
  text($('allowed-value'), stats.allowed);
  text($('blocked-value'), stats.blocked);
  text($('risk-value'), stats.highRisk);
  text($('nav-count'), stats.total);
  text($('policy-count'), `${pol.policies.length} active`);
  render();
}
function renderRecent() {
  const parent = $('recent-activity');
  parent.replaceChildren();
  if (!state.events.length) { parent.append(empty()); return; }
  for (const event of state.events.slice(0, 6)) {
    const item = make('button', 'recent-event');
    item.type = 'button';
    const icon = make('div', `event-icon ${event.decision}`, event.decision === 'allow' ? '✓' : '×');
    const main = make('div', 'event-main');
    main.append(make('strong', '', event.tool), make('small', '', `${event.agentId}  ·  ${event.ruleId}`));
    const side = make('div', 'event-side');
    side.append(make('span', `status ${event.decision}`, statusLabel(event)), make('small', '', ago(event.timestamp)));
    item.append(icon, main, side);
    item.addEventListener('click', () => showEvent(event));
    parent.append(item);
  }
}
function renderTable() {
  const body = $('event-table');
  body.replaceChildren();
  const filtered = state.events.filter(e => state.filter === 'all' || e.decision === state.filter);
  if (!filtered.length) {
    const cell = make('td'); cell.colSpan = 7; cell.append(empty('No matching events'));
    const row = make('tr'); row.append(cell); body.append(row);
  }
  for (const event of filtered) {
    const row = make('tr');
    row.tabIndex = 0;
    row.setAttribute('aria-label', `Inspect ${event.tool} ${statusLabel(event)}`);
    const time = make('td', '', new Date(event.timestamp).toLocaleTimeString());
    const toolCell = make('td');
    toolCell.append(make('span', 'tool-name', event.tool), make('span', 'tool-agent', event.agentId));
    const decision = make('td'); decision.append(make('span', `status ${event.decision}`, event.decision === 'block' ? 'Blocked' : 'Allowed'));
    const risk = make('td'); risk.append(make('span', `risk-pill ${event.risk}`, `${event.risk} · ${event.riskScore}`));
    const rule = make('td', 'mono', event.ruleId);
    const outcome = make('td', '', event.outcome);
    row.append(time, toolCell, decision, risk, rule, outcome, make('td', '', '↗'));
    row.addEventListener('click', () => showEvent(event));
    row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); showEvent(event); } });
    body.append(row);
  }
  text($('table-foot'), `Showing ${filtered.length} recent events · audit history stored locally`);
}
function renderPolicies() {
  const parent = $('policy-list'); parent.replaceChildren();
  for (const policy of state.policies) {
    const item = make('div', 'policy-item');
    item.append(make('div', 'policy-item-icon', policy.id.startsWith('DENY') ? '⊘' : '✓'));
    const content = make('div');
    content.append(make('h3', '', policy.id), make('p', '', policy.description));
    item.append(content, make('span', 'policy-category', policy.category));
    parent.append(item);
  }
}
function render() { renderRecent(); renderTable(); renderPolicies(); }
function showEvent(event) {
  const content = $('dialog-content'); content.replaceChildren();
  text($('dialog-title'), event.tool);
  const body = make('div', 'dialog-body');
  const fields = [
    ['Decision', event.decision === 'block' ? 'BLOCKED — execution was prevented' : 'ALLOWED — passed pre-execution policy', event.decision === 'block' ? 'red-text' : 'green-text'],
    ['Policy rule', event.ruleId, 'mono'],
    ['Reason', event.reason],
    ['Risk assessment', `${event.risk.toUpperCase()} (${event.riskScore}/100)`],
    ['Input summary', event.input, 'mono'],
    ['Execution outcome', event.outcome],
    ['Result summary', event.summary],
    ['Agent / source', `${event.agentId} / ${event.source}`],
    ['Run ID', event.runId, 'mono'],
    ['Timestamp', new Date(event.timestamp).toLocaleString()],
    ['Elapsed', `${event.durationMs} ms`],
    ['Event ID', event.id, 'mono']
  ];
  for (const [title, value, color = ''] of fields) {
    const row = make('div', 'dialog-field');
    row.append(make('span', 'dialog-label', title), make('div', `dialog-value ${color}`, value));
    body.append(row);
  }
  content.append(body); $('event-dialog').showModal();
}
function navigate(view) {
  state.view = view;
  const labels = { overview: ['Security overview', 'Monitor every agent action. Understand every security decision.', 'Overview'], agent: ['Local AI agent', 'Give a real model a task and observe guarded tool calls in real time.', 'AI agent'], activity: ['Activity log', 'Explore decisions, risk classifications and execution outcomes.', 'Activity log'], policies: ['Security policies', 'Review the rules protecting instrumented tools.', 'Security policies'] };
  const [title, subtitle, crumb] = labels[view];
  text($('page-title'), title); text($('page-subtitle'), subtitle); text($('page-crumb'), crumb);
  for (const section of ['overview', 'agent', 'activity', 'policies']) $(section + '-view').classList.toggle('hidden', section !== view);
  for (const button of document.querySelectorAll('.nav-item')) button.classList.toggle('active', button.dataset.view === view);
}
let toastTimeout;
function toast(message) {
  text($('toast'), message); $('toast').classList.add('visible');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => $('toast').classList.remove('visible'), 4500);
}
async function runDemo() {
  const button = $('run-demo'); button.disabled = true;
  const initial = button.innerHTML;
  button.textContent = 'Running demo…';
  try {
    const data = await fetchJson('/api/demo/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    await refresh();
    toast(`Run completed: ${data.allowed} allowed · ${data.blocked} blocked · ${data.errors} failed`);
    navigate('activity');
  } catch (error) { toast(`Demo failed: ${error.message}`); }
  finally { button.disabled = false; button.innerHTML = initial; }
}
async function checkAgentModel() {
  try {
    const state = await fetchJson('/api/agent/status');
    text($('model-name'), state.model);
    $('model-led').classList.toggle('ready', state.ready);
    text($('model-status'), state.ready ? 'Connected · model installed and ready' : state.reachable ? 'Ollama connected · run ollama pull ' + state.model : 'Offline · start Ollama on localhost:11434');
  } catch { text($('model-status'), 'Unable to check Ollama status'); }
}
async function runRealAgent() {
  const prompt = $('agent-prompt').value.trim();
  if (!prompt) { toast('Enter a task first.'); return; }
  const button = $('run-agent'); button.disabled = true;
  text(button, 'Running… (model may take a while)');
  text($('agent-result-status'), 'RUNNING');
  text($('agent-answer'), 'Waiting for Ollama. Any tool calls will be audited as they occur…');
  $('agent-run-meta').replaceChildren(); $('agent-run-events').replaceChildren();
  try {
    const result = await fetchJson('/api/agent/run', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ prompt })
    });
    text($('agent-answer'), result.answer);
    text($('agent-result-status'), result.status === 'finished' ? 'COMPLETE' : 'LIMIT REACHED');
    text($('agent-run-meta'), `${result.model} · ${result.toolCalls} audited tool calls · Run ${result.runId}`);
    const parent = $('agent-run-events');
    for (const ev of result.events) {
      const row = make('button', 'agent-run-event'); row.type = 'button';
      row.append(make('span', `status ${ev.decision}`, statusLabel(ev)), make('span', 'mono', ev.tool), make('span', '', ev.ruleId));
      row.addEventListener('click', () => showEvent(ev)); parent.append(row);
    }
    await refresh();
    toast(`Agent finished · ${result.toolCalls} tool calls recorded`);
  } catch (error) {
    text($('agent-result-status'), 'ERROR');
    text($('agent-answer'), `Agent could not run: ${error.message}`);
    toast(error.message);
    checkAgentModel();
  } finally { button.disabled = false; text(button, '✧ Run with local LLM ↗'); }
}
$('run-agent').addEventListener('click', runRealAgent);
$('check-model').addEventListener('click', checkAgentModel);
for (const preset of document.querySelectorAll('.preset-button')) preset.addEventListener('click', () => {
  $('agent-prompt').value = preset.dataset.prompt;
  $('agent-prompt').focus();
});
checkAgentModel();
for (const button of document.querySelectorAll('.nav-item')) button.addEventListener('click', () => navigate(button.dataset.view));
$('view-all').addEventListener('click', () => navigate('activity'));
$('run-demo').addEventListener('click', runDemo);
$('decision-filter').addEventListener('change', e => { state.filter = e.target.value; renderTable(); });
$('dialog-close').addEventListener('click', () => $('event-dialog').close());
$('event-dialog').addEventListener('click', e => { if (e.target === $('event-dialog')) $('event-dialog').close(); });

refresh().catch(error => toast(`Could not load audit data: ${error.message}`));
try {
  const stream = new EventSource('/api/stream');
  stream.addEventListener('open', () => { text($('connection-label'), 'Live monitoring'); });
  stream.addEventListener('audit', () => refresh().catch(() => {}));
  stream.addEventListener('error', () => { text($('connection-label'), 'Reconnecting'); });
} catch { text($('connection-label'), 'Offline'); }
// Safe fallback when SSE is unavailable.
setInterval(() => refresh().catch(() => {}), 30000);
