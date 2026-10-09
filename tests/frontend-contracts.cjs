const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
const app = { innerHTML: '', querySelector(selector) { if(selector==='.page') return {classList:{add(){},remove(){}},querySelectorAll(){return []}}; if(selector==='.page-head h1' && this.innerHTML.includes('page-head')) return {tabIndex:-1,focus(){}}; return null; } }, modalRoot = { innerHTML: '' };
const store = new Map();
const document = {
  querySelector(selector) {
    if (selector === '#app') return app;
    if (selector === '#modal-root') return modalRoot;
    return null;
  },
  querySelectorAll() { return []; },
  addEventListener() {},
  createElement() { return { className: '', textContent: '', append() {} }; }
};
const context = vm.createContext({
  document,
  location: { pathname: '/demo-login', search: '?session=demo-session&api=local' },
  URLSearchParams,
  sessionStorage: { getItem: k => store.get(k) ?? null, setItem: (k,v) => store.set(k,v), removeItem: k => store.delete(k) },
  localStorage: { getItem: () => 'seen', setItem() {}, removeItem() {} },
  fetch: async () => { throw new Error('Unexpected API call in static render check'); },
  console,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  window: {},
  crypto: { randomUUID: () => '00000000-0000-4000-8000-000000000001' }
});
vm.runInContext(source, context, { filename: 'app.js' });
assert.match(app.innerHTML, /Request Access/);
assert.match(app.innerHTML, /Do not enter a password/);
assert.match(source, /Secure Access/);
assert.match(source, /Enter your access passphrase to continue/);
assert.match(source, /function verifyWorkspacePassphrase/);
vm.runInContext(`state.accessConfig={enabled:true};renderAccessPortal();`, context);
assert.match(app.innerHTML, /<h1>Secure Access<\/h1>/);
assert.match(app.innerHTML, /Enter your access passphrase to continue\./);
assert.equal((app.innerHTML.match(/<input\b/g)||[]).length, 1, 'the Secure Access form has one input');
assert.match(app.innerHTML, />Continue<\/button>/);
assert.ok(!app.innerHTML.includes('Request Access'), 'the entry screen stays a single passphrase step');
assert.match(source, /security-events/);
assert.ok(!source.includes('CyberAI'), 'the passphrase must not appear in frontend source');
vm.runInContext(`
  state.data={assets:[],findings:[],events:[],correlations:[],investigations:[],remediations:[],audit:[],settings:[{name:'Northstar Dental Clinic'}]};
  state.loaded=true; state.loading=false; state.error='';
  const sections=['Overview','Assets','Findings','Events','Correlations','Investigations','Remediation','Audit Trail','Settings','About'];
  globalThis.renderedSections=[];
  for(const section of sections){navigate(section); renderedSections.push([section,document.querySelector('#app').innerHTML.includes('aria-current="page"')]);}
  globalThis.guidedDemoStepCount=guidedSteps.length;
`, context);
const rendered = vm.runInContext('renderedSections', context);
for (const [section, active] of rendered) assert.equal(active, true, `${section} should render with active nav`);
assert.equal(vm.runInContext('guidedDemoStepCount', context), 10, 'the ten-step guided demo remains');
for (const marker of ['function approvalForm(', 'function executeRemediation(', 'function verifyForm(', 'Acknowledge the impact and simulation scope', 'Approver name', 'Skip Intro', 'Enter CyberRakshak', 'Connect the Signals.', 'Verify the Evidence.', 'Prioritize the Risk.', 'function replayIntro()', 'prefers-reduced-motion', '10800']) {
  assert.ok(source.toLowerCase().includes(marker.toLowerCase()), `existing safeguard marker: ${marker}`);
}
console.log('Frontend render checks passed: phone page, 10 sections, 10-step guided tour, remediation safeguards and cinematic intro controls.');



