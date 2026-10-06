// Exercise the real form handler with controlled API timing. No DOM package or
// live server is needed to check that a single submit creates at most one client.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const appSource = fs.readFileSync(path.join(__dirname, '../public/assets/app.js'), 'utf8');
const start = appSource.indexOf('const supportsKeepaliveRange =');
const end = appSource.indexOf('async function showContainer(', start);
assert.ok(start >= 0 && end > start, 'load the actual create-client form and validators');
const formScript = new vm.Script(appSource.slice(start, end) + '\ncreateClient();', {
  filename: 'create-client.test.js',
});

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const flush = () => new Promise(resolve => setImmediate(resolve));
const executablePlan = id => ({ plan_id: id, executable: true, read_only: false });
const tunnel = { container: 'amnezia-awg', interface: 'awg0', config_path: '/opt/amnezia/awg/awg0.conf', listen_port: 51820, protocol: 'AmneziaWG', protocol_version: '3.1' };

class Element {
  constructor(id, value = '') {
    this.id = id;
    this.value = value;
    this.disabled = false;
    this.open = false;
    this.dataset = {};
    this.innerHTML = '';
    this.textContent = '';
    this.validityMessage = '';
    this.reported = 0;
    this.listeners = new Map();
  }
  addEventListener(type, callback) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(callback);
    this.listeners.set(type, listeners);
  }
  async dispatch(type, target = this) {
    const event = { target, prevented: false, preventDefault() { this.prevented = true; } };
    await Promise.all((this.listeners.get(type) || []).map(callback => callback(event)));
    return event;
  }
  setCustomValidity(message) { this.validityMessage = message; }
  reportValidity() { this.reported++; return !this.validityMessage; }
  closest(selector) {
    return selector === '#client-options' && ['client-dns', 'client-routes', 'client-keepalive'].includes(this.id) ? this.options : null;
  }
}

function harness({ apiHandler = () => { throw new Error('Unexpected API request'); }, readOnly = false, mode = 'live', tunnels = [tunnel] } = {}) {
  const state = { snapshot: { tunnels }, mode, server: 'server-a', generation: 2, modalGeneration: 0 };
  const elements = new Map();
  const dialog = new Element('modal');
  const closeButtons = [new Element('header-close'), new Element('cancel')];
  elements.set('modal', dialog);
  const calls = [], results = [], modals = [], refreshes = [], audits = [];
  const context = {
    state,
    selectedServer: () => ({ read_only: readOnly }),
    escape: value => String(value ?? ''),
    icon: name => `<icon name="${name}"></icon>`,
    $: selector => {
      const element = elements.get(selector.replace(/^#/, ''));
      assert.ok(element, `expected fake DOM selector ${selector}`);
      return element;
    },
    $$: (selector, root) => {
      assert.equal(selector, '[data-close]');
      assert.equal(root, dialog);
      return closeButtons;
    },
    modal: (title, description, body) => {
      state.modalGeneration++;
      dialog.open = true;
      modals.push({ title, description, body });
      // Only the controls used by this form need DOM behavior. Initial values
      // and disabled state come from the production HTML, not a duplicate form.
      for (const tag of body.matchAll(/<(?:input|select|button|details|p|small|form)\b[^>]*\bid="([^"]+)"[^>]*>/g)) {
        const value = /\bvalue="([^"]*)"/.exec(tag[0])?.[1] || '';
        const element = new Element(tag[1], value);
        element.disabled = /\sdisabled(?:\s|>)/.test(tag[0]);
        elements.set(tag[1], element);
      }
      elements.get('client-tunnel').value = tunnels.length ? '0' : '';
      const controls = ['client-name', 'client-tunnel', 'client-dns', 'client-routes', 'client-keepalive', 'client-create-submit'].map(id => elements.get(id));
      elements.get('client-form').querySelectorAll = selector => {
        assert.equal(selector, 'input,select,button[type="submit"]');
        return controls;
      };
      for (const id of ['client-dns', 'client-routes', 'client-keepalive']) elements.get(id).options = elements.get('client-options');
      elements.get('client-name').value = '  Work laptop  ';
    },
    api: (endpoint, options) => {
      const call = { endpoint, options: JSON.parse(JSON.stringify(options)) };
      calls.push(call);
      return apiHandler(endpoint, options, calls.length);
    },
    showOperationResult: (result, executionMode, clientName) => {
      results.push({ result, executionMode, clientName });
      state.modalGeneration++; // The result replaces the form in the real modal.
    },
    refresh: force => refreshes.push(force),
    loadAudit: force => audits.push(force),
  };
  formScript.runInNewContext(context);
  const get = id => elements.get(id);
  return { state, dialog, get, calls, results, modals, refreshes, audits, closeButtons, openForm: () => context.createClient(), submit: () => get('client-form').dispatch('submit') };
}

test('one submit prepares and executes the captured client, then preserves its connection exports', async () => {
  const result = { config: '[Interface]\nPrivateKey = test\n', filename: 'laptop.conf', amnezia: { key: 'vpn://test', filename: 'laptop.vpn', qr_payloads: ['B8ABAQAAAAR0ZXN0'] } };
  const h = harness({ apiHandler: endpoint => endpoint === 'actions/plan' ? executablePlan('plan-one') : result });
  h.get('client-dns').value = ' 1.1.1.1, 1.0.0.1 ';
  h.get('client-routes').value = ' 0.0.0.0/0, ::/0 ';
  const event = await h.submit();
  assert.equal(event.prevented, true);
  assert.deepEqual(h.calls, [
    { endpoint: 'actions/plan', options: { method: 'POST', body: { server_id: 'server-a', mode: 'live', action: 'client.create', target: 'Work laptop', params: { name: 'Work laptop', dns: '1.1.1.1, 1.0.0.1', allowed_ips: '0.0.0.0/0, ::/0', keepalive: '25-35', container: tunnel.container, interface: tunnel.interface, config_path: tunnel.config_path } } } },
    { endpoint: 'actions/execute', options: { method: 'POST', body: { plan_id: 'plan-one', confirmation: 'Work laptop' } } },
  ]);
  assert.deepEqual(h.results, [{ result, executionMode: 'live', clientName: 'Work laptop' }]);
  assert.deepEqual(h.refreshes, [true]);
  assert.deepEqual(h.audits, [false]);
  assert.equal(h.modals.length, 1, 'there is no intermediate plan or confirmation modal');
  assert.match(h.modals[0].body, /button-primary[^>]*id="client-create-submit"/);
  assert.doesNotMatch(h.modals[0].body, /button-danger|name="power"|Просмотреть план/);
  assert.equal(h.dialog.dataset.busy, undefined);
});

test('repeated submits during preparation and execution cannot create duplicate clients', async () => {
  const preparing = deferred(), executing = deferred();
  const h = harness({ apiHandler: endpoint => endpoint === 'actions/plan' ? preparing.promise : executing.promise });
  const pending = h.submit();
  assert.equal(h.get('client-create-submit').disabled, true);
  await h.submit();
  assert.equal(h.calls.length, 1);
  preparing.resolve(executablePlan('only-plan'));
  await flush();
  assert.deepEqual(h.calls.map(call => call.endpoint), ['actions/plan', 'actions/execute']);
  assert.ok(h.dialog.dataset.busy);
  assert.ok(h.closeButtons.every(button => button.disabled), 'closing is locked once execution begins');
  await h.submit();
  assert.equal(h.calls.length, 2);
  executing.resolve({ config: 'export' });
  await pending;
  assert.equal(h.results.length, 1);
  assert.equal(h.dialog.dataset.busy, undefined);
});

test('preparation failure restores the form and a retry prepares a fresh plan', async () => {
  let attempts = 0;
  const h = harness({ apiHandler: endpoint => {
    if (endpoint === 'actions/plan') {
      if (++attempts === 1) throw new Error('SSH unavailable');
      return executablePlan('fresh-plan');
    }
    return { config: 'export' };
  } });
  await h.submit();
  assert.equal(h.calls.length, 1, 'failed preparation never executes');
  assert.equal(h.get('client-create-status').textContent, 'SSH unavailable');
  assert.equal(h.get('client-create-submit').disabled, false);
  assert.equal(h.get('client-name').value, '  Work laptop  ');
  await h.submit();
  assert.deepEqual(h.calls.map(call => call.endpoint), ['actions/plan', 'actions/plan', 'actions/execute']);
  assert.equal(h.calls[2].options.body.plan_id, 'fresh-plan');
});

test('non-executable and read-only preparation responses never execute', async () => {
  for (const response of [{ executable: false, read_only: false }, { executable: true, read_only: true }, { executable: true }]) {
    const h = harness({ apiHandler: () => response });
    await h.submit();
    assert.equal(h.calls.length, 1);
    assert.match(h.get('client-create-status').textContent, /Создание недоступно/);
    assert.equal(h.get('client-create-submit').disabled, false);
    assert.equal(h.dialog.dataset.busy, undefined);
  }
});

test('demo, read-only and missing-tunnel forms cannot make API requests', async () => {
  for (const options of [{ mode: 'demo' }, { readOnly: true }, { tunnels: [] }]) {
    const h = harness(options);
    assert.equal(h.get('client-create-submit').disabled, true);
    await h.submit(); // Also protect against programmatically dispatched submits.
    assert.deepEqual(h.calls, []);
  }
});

test('closing or changing the server during preparation aborts before execution', async () => {
  for (const change of [h => { h.dialog.open = false; h.state.modalGeneration++; }, h => { h.state.server = 'server-b'; h.state.generation++; }]) {
    const preparing = deferred();
    const h = harness({ apiHandler: () => preparing.promise });
    const pending = h.submit();
    change(h);
    preparing.resolve(executablePlan('stale-plan'));
    await pending;
    assert.deepEqual(h.calls.map(call => call.endpoint), ['actions/plan']);
    assert.deepEqual(h.results, []);
    assert.equal(h.dialog.dataset.busy, undefined);
  }
});

test('execution failure releases the lock, warns about existing clients, and retries with a new plan', async () => {
  let plans = 0, executions = 0;
  const h = harness({ apiHandler: endpoint => {
    if (endpoint === 'actions/plan') return executablePlan(`plan-${++plans}`);
    if (++executions === 1) throw new Error('Connection lost');
    return { config: 'new export' };
  } });
  await h.submit();
  assert.match(h.get('client-create-status').textContent, /Connection lost.*Проверьте список клиентов/);
  assert.equal(h.dialog.dataset.busy, undefined);
  assert.ok(h.closeButtons.every(button => !button.disabled));
  assert.equal(h.get('client-create-submit').disabled, false);
  assert.equal(h.calls.length, 2, 'errors never automatically retry');
  await h.submit();
  assert.deepEqual(h.calls.filter(call => call.endpoint === 'actions/execute').map(call => call.options.body.plan_id), ['plan-1', 'plan-2']);
  assert.equal(h.results.length, 1);
});

test('invalid keepalive opens the advanced options without requesting a plan', async () => {
  const h = harness();
  h.get('client-keepalive').value = '35-25';
  await h.submit();
  assert.deepEqual(h.calls, []);
  assert.equal(h.get('client-options').open, true);
  assert.match(h.get('client-keepalive').validityMessage, /Начало диапазона/);
  assert.equal(h.get('client-keepalive').reported, 1);
  assert.equal(h.get('client-create-submit').disabled, false);
});

test('a started execution still delivers its exports after the current server changes', async () => {
  const executing = deferred();
  const result = { config: 'original client export', amnezia: { key: 'vpn://original' } };
  const h = harness({ apiHandler: endpoint => endpoint === 'actions/plan' ? executablePlan('original-plan') : executing.promise });
  const pending = h.submit();
  await flush();
  assert.ok(h.dialog.dataset.busy);
  h.state.server = 'server-b';
  h.state.mode = 'demo';
  h.state.generation++;
  executing.resolve(result);
  await pending;
  assert.deepEqual(h.results, [{ result, executionMode: 'live', clientName: 'Work laptop' }], 'credentials remain available for the operation that actually ran');
  assert.equal(h.dialog.dataset.busy, undefined);
  assert.equal(h.calls[0].options.body.server_id, 'server-a');
});

test('an old preparation cannot unlock the execution started in a newer modal', async () => {
  const oldPreparation = deferred(), newExecution = deferred();
  let preparations = 0;
  const h = harness({ apiHandler: endpoint => {
    if (endpoint === 'actions/plan') return ++preparations === 1 ? oldPreparation.promise : executablePlan('new-plan');
    return newExecution.promise;
  } });
  const oldPending = h.submit();
  h.dialog.open = false;
  h.state.modalGeneration++;
  h.openForm();
  const newPending = h.submit();
  await flush();
  const newLock = h.dialog.dataset.busy;
  assert.ok(newLock);
  oldPreparation.resolve(executablePlan('old-plan'));
  await oldPending;
  assert.equal(h.dialog.dataset.busy, newLock, 'stale preparation must not release another execution’s close lock');
  assert.ok(h.closeButtons.every(button => button.disabled));
  assert.deepEqual(h.calls.map(call => call.endpoint), ['actions/plan', 'actions/plan', 'actions/execute']);
  assert.equal(h.calls[2].options.body.plan_id, 'new-plan');
  newExecution.resolve({ config: 'new client export' });
  await newPending;
  assert.equal(h.dialog.dataset.busy, undefined);
  assert.equal(h.results.length, 1);
});
