const $ = (id) => document.getElementById(id);
const dictionaries = window.VPNPROXI_I18N || {};
const supportedLanguages = ['ru', 'en'];
const dynamicTextIds = new Set(['stateBadge', 'protocolBadge', 'statusBox', 'logBox', 'pendingMessage', 'routeProbeStatus', 'autoProxyDomains', 'autoProxyIps']);
const trackedFieldIds = ['shareLink', 'vpnDomain', 'vpnSubnet', 'tproxyPort', 'tproxyMark', 'tproxyTable', 'certFile', 'keyFile', 'proxyDomains', 'directDomains', 'proxyIps', 'directIps', 'proxyPorts'];

let serverState = null;
let language = initialLanguage();
let statusLoaded = false;
let logsLoaded = false;
let logLines = [];
let lastClientRows = [];
let docsLoadedLanguage = '';
let autoRefreshBusy = false;
let authenticated = false;
let routeProbe = emptyRouteProbe();

function emptyRouteProbe() {
  return { rawLink: '', ok: false, outbound: null, probe: null };
}

function initialLanguage() {
  const saved = localStorage.getItem('vpnproxiLanguage');
  if (supportedLanguages.includes(saved)) return saved;
  const browser = (navigator.language || '').toLowerCase();
  return browser.startsWith('ru') ? 'ru' : 'en';
}

function t(key, params = {}) {
  const phrase = dictionaries[language]?.[key] || dictionaries.en?.[key] || key;
  return phrase.replace(/\{(\w+)\}/g, (_, name) => params[name] ?? '');
}

function formatDate(value) {
  const locale = language === 'ru' ? 'ru-RU' : 'en-US';
  return new Date(value).toLocaleString(locale);
}

function applyLanguage() {
  document.documentElement.lang = language;
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    if (!dynamicTextIds.has(el.id)) el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  });
  document.querySelectorAll('[data-tip-key]').forEach((el) => {
    el.dataset.tip = t(el.dataset.tipKey);
  });
  document.querySelectorAll('[data-language]').forEach((el) => {
    const active = el.dataset.language === language;
    el.classList.toggle('is-active', active);
    el.setAttribute('aria-pressed', String(active));
  });
  updateDynamicText();
  updateEndpoint();
  if ($('docsPanel')?.open) {
    loadDocs(true).catch(() => {
      $('docsBody').textContent = t('docsLoadError');
    });
  }
  renderLogs(logLines);
}

function setLanguage(next) {
  if (!supportedLanguages.includes(next) || next === language) return;
  const draftUsers = serverState ? currentSnapshot().users : [];
  language = next;
  localStorage.setItem('vpnproxiLanguage', next);
  applyLanguage();
  if (serverState) {
    renderUsers(draftUsers);
    updateUserTraffic(lastClientRows);
    syncDraftUI();
  }
}

function lines(v) {
  return (v || '').split('\n').map((x) => x.trim()).filter(Boolean);
}

function setLines(id, values) {
  $(id).value = (values || []).join('\n');
  resizeTextarea($(id));
}

function csvNumbers(v) {
  return (v || '').split(/[,\n]/).map((x) => Number(x.trim())).filter((n) => Number.isInteger(n) && n > 0);
}

function normalizeDomainRules(value) {
  return lines(value).map((item) => {
    if (/^(domain|full|regexp|geosite):/i.test(item)) return item;
    return `domain:${item}`;
  });
}

function resizeTextarea(el) {
  if (!el || el.tagName !== 'TEXTAREA') return;
  el.style.height = 'auto';
  el.style.height = `${el.scrollHeight}px`;
}

function resizeTextareas() {
  document.querySelectorAll('textarea').forEach(resizeTextarea);
}

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  const res = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  if (res.status === 401) showLogin();
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function publicApi(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  const res = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function showLogin(message = '') {
  authenticated = false;
  $('loginOverlay').hidden = false;
  $('appShell').hidden = true;
  $('pendingBar').hidden = true;
  $('logoutBtn').hidden = true;
  $('sessionUser').hidden = true;
  $('loginError').textContent = message;
  setTimeout(() => $('loginUsername').focus(), 0);
}

function hideLogin(username = '') {
  authenticated = true;
  $('loginOverlay').hidden = true;
  $('appShell').hidden = false;
  $('logoutBtn').hidden = false;
  $('sessionUser').hidden = !username;
  $('sessionUser').textContent = username;
  $('loginPassword').value = '';
  $('loginError').textContent = '';
}

async function checkSession() {
  const session = await publicApi('/api/session');
  if (!session.authenticated) {
    showLogin();
    return false;
  }
  hideLogin(session.username || '');
  return true;
}

async function login() {
  $('loginError').textContent = '';
  const username = $('loginUsername').value.trim();
  const password = $('loginPassword').value;
  try {
    const result = await publicApi('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) });
    hideLogin(result.username || username);
    await load();
  } catch (_) {
    showLogin(t('loginFailed'));
  }
}

async function logout() {
  await publicApi('/api/logout', { method: 'POST', body: '{}' }).catch(() => {});
  serverState = null;
  statusLoaded = false;
  logsLoaded = false;
  logLines = [];
  routeProbe = emptyRouteProbe();
  updateDynamicText();
  showLogin();
}

function cloneJSON(value) {
  return JSON.parse(JSON.stringify(value));
}

function baselineSnapshot() {
  if (!serverState) return emptySnapshot();
  return snapshotFromState(serverState);
}

function emptySnapshot() {
  return {
    shareLink: '',
    vpnDomain: '',
    vpnSubnet: '',
    mobikeEnabled: false,
    tproxyPort: 10000,
    tproxyMark: '0x2333',
    tproxyTable: 100,
    certFile: '',
    keyFile: '',
    routingMode: 'direct',
    useRunet: false,
    proxyDomains: [],
    directDomains: [],
    proxyIps: [],
    directIps: [],
    proxyPorts: [],
    users: [],
  };
}

function snapshotFromState(source) {
  return {
    shareLink: source.outbound?.rawLink || '',
    vpnDomain: source.server.vpnDomain || '',
    vpnSubnet: source.server.vpnSubnet || '',
    mobikeEnabled: Boolean(source.server.mobikeEnabled),
    tproxyPort: Number(source.server.tproxyPort) || 10000,
    tproxyMark: source.server.tproxyMark || '0x2333',
    tproxyTable: Number(source.server.tproxyTable) || 100,
    certFile: source.server.certFile || '',
    keyFile: source.server.keyFile || '',
    routingMode: source.routes.mode || 'direct',
    useRunet: Boolean(source.routes.useRunetGeodata),
    proxyDomains: [...(source.routes.proxyDomains || [])],
    directDomains: [...(source.routes.directDomains || [])],
    proxyIps: [...(source.routes.proxyIps || [])],
    directIps: [...(source.routes.directIps || [])],
    proxyPorts: [...(source.routes.proxyPorts || [])],
    users: (source.server.users || []).map((user) => ({ login: user.login || '', password: user.password || '' })),
  };
}

function currentSnapshot() {
  return {
    shareLink: $('shareLink').value.trim(),
    vpnDomain: $('vpnDomain').value.trim(),
    vpnSubnet: $('vpnSubnet').value.trim(),
    mobikeEnabled: $('mobikeEnabled').checked,
    tproxyPort: Number($('tproxyPort').value),
    tproxyMark: $('tproxyMark').value.trim(),
    tproxyTable: Number($('tproxyTable').value),
    certFile: $('certFile').value.trim(),
    keyFile: $('keyFile').value.trim(),
    routingMode: $('routingMode').value,
    useRunet: $('useRunet').checked,
    proxyDomains: normalizeDomainRules($('proxyDomains').value),
    directDomains: normalizeDomainRules($('directDomains').value),
    proxyIps: lines($('proxyIps').value),
    directIps: lines($('directIps').value),
    proxyPorts: csvNumbers($('proxyPorts').value),
    users: [...document.querySelectorAll('.user-card')].map((row) => ({
      login: row.querySelector('[data-field="login"]').value.trim(),
      password: row.querySelector('[data-field="password"]').value,
    })).filter((user) => user.login),
  };
}

function snapshotsEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function hasPendingChanges() {
  return serverState ? !snapshotsEqual(baselineSnapshot(), currentSnapshot()) : false;
}

function outboundChanged(snapshot = currentSnapshot()) {
  return snapshot.shareLink !== baselineSnapshot().shareLink;
}

function hasProxyRoutingRules() {
  return Boolean(
    $('useRunet').checked ||
    lines($('proxyDomains').value).length ||
    lines($('proxyIps').value).length ||
    csvNumbers($('proxyPorts').value).length
  );
}

function buildStateForApply(outbound) {
  const next = cloneJSON(serverState);
  const snapshot = currentSnapshot();
  next.server.vpnDomain = snapshot.vpnDomain;
  next.server.vpnSubnet = snapshot.vpnSubnet;
  next.server.mobikeEnabled = snapshot.mobikeEnabled;
  next.server.tproxyPort = snapshot.tproxyPort;
  next.server.tproxyMark = snapshot.tproxyMark;
  next.server.tproxyTable = snapshot.tproxyTable;
  next.server.certFile = snapshot.certFile;
  next.server.keyFile = snapshot.keyFile;
  next.server.users = snapshot.users;
  next.routes.mode = snapshot.routingMode;
  next.routes.useRunetGeodata = snapshot.useRunet;
  next.routes.proxyDomains = snapshot.proxyDomains;
  next.routes.directDomains = snapshot.directDomains;
  next.routes.proxyIps = snapshot.proxyIps;
  next.routes.directIps = snapshot.directIps;
  next.routes.proxyPorts = snapshot.proxyPorts;
  next.outbound = snapshot.shareLink ? cloneJSON(outbound) : null;
  return next;
}

function currentOutboundPreview(snapshot = currentSnapshot()) {
  if (!snapshot.shareLink) return null;
  if (routeProbe.rawLink === snapshot.shareLink && routeProbe.outbound) return routeProbe.outbound;
  if (serverState?.outbound?.rawLink === snapshot.shareLink) return serverState.outbound;
  return null;
}

function fill() {
  routeProbe = emptyRouteProbe();
  const snapshot = baselineSnapshot();
  $('shareLink').value = snapshot.shareLink;
  resizeTextarea($('shareLink'));
  $('vpnDomain').value = snapshot.vpnDomain;
  $('vpnSubnet').value = snapshot.vpnSubnet;
  $('mobikeEnabled').checked = snapshot.mobikeEnabled;
  $('tproxyPort').value = snapshot.tproxyPort;
  $('tproxyMark').value = snapshot.tproxyMark;
  $('tproxyTable').value = snapshot.tproxyTable;
  $('certFile').value = snapshot.certFile;
  $('keyFile').value = snapshot.keyFile;
  $('routingMode').value = snapshot.routingMode;
  $('useRunet').checked = snapshot.useRunet;
  setLines('proxyDomains', snapshot.proxyDomains);
  setLines('directDomains', snapshot.directDomains);
  setLines('proxyIps', snapshot.proxyIps);
  setLines('directIps', snapshot.directIps);
  $('proxyPorts').value = snapshot.proxyPorts.join(', ');
  renderUsers(snapshot.users);
  syncDraftUI();
}

async function load() {
  serverState = await api('/api/state');
  fill();
  await refreshStatus();
  if ($('activityPanel')?.open) await refreshLogs();
  if ($('docsPanel')?.open) await loadDocs(true);
}

function setDirtyClass(el, dirty) {
  if (!el) return;
  el.classList.toggle('is-dirty', Boolean(dirty));
}

function updateDirtyHighlights(base, draft) {
  const fieldMap = {
    shareLink: () => base.shareLink !== draft.shareLink,
    vpnDomain: () => base.vpnDomain !== draft.vpnDomain,
    vpnSubnet: () => base.vpnSubnet !== draft.vpnSubnet,
    mobikeEnabled: () => base.mobikeEnabled !== draft.mobikeEnabled,
    tproxyPort: () => base.tproxyPort !== draft.tproxyPort,
    tproxyMark: () => base.tproxyMark !== draft.tproxyMark,
    tproxyTable: () => base.tproxyTable !== draft.tproxyTable,
    certFile: () => base.certFile !== draft.certFile,
    keyFile: () => base.keyFile !== draft.keyFile,
    proxyDomains: () => JSON.stringify(base.proxyDomains) !== JSON.stringify(draft.proxyDomains),
    directDomains: () => JSON.stringify(base.directDomains) !== JSON.stringify(draft.directDomains),
    proxyIps: () => JSON.stringify(base.proxyIps) !== JSON.stringify(draft.proxyIps),
    directIps: () => JSON.stringify(base.directIps) !== JSON.stringify(draft.directIps),
    proxyPorts: () => JSON.stringify(base.proxyPorts) !== JSON.stringify(draft.proxyPorts),
  };
  for (const id of trackedFieldIds) {
    setDirtyClass($(id), fieldMap[id]());
  }
  setDirtyClass($('routingModeCards'), base.routingMode !== draft.routingMode);
  setDirtyClass($('useRunetWrap'), base.useRunet !== draft.useRunet);
  setDirtyClass($('mobikeWrap'), fieldMap.mobikeEnabled());

  const rows = [...document.querySelectorAll('.user-card')];
  rows.forEach((row, index) => {
    const baseUser = base.users[index] || { login: '', password: '' };
    const loginInput = row.querySelector('[data-field="login"]');
    const passwordInput = row.querySelector('[data-field="password"]');
    const loginDirty = loginInput.value.trim() !== baseUser.login;
    const passwordDirty = passwordInput.value !== baseUser.password;
    setDirtyClass(loginInput, loginDirty);
    setDirtyClass(passwordInput, passwordDirty);
    row.classList.toggle('is-dirty', loginDirty || passwordDirty || index >= base.users.length);
  });
}

function routeCheckPassed(snapshot = currentSnapshot()) {
  return routeProbe.ok && routeProbe.rawLink === snapshot.shareLink;
}

function routeCheckNeeded(snapshot = currentSnapshot()) {
  return Boolean(snapshot.shareLink) && outboundChanged(snapshot) && !routeCheckPassed(snapshot);
}

function routeCheckStatus(snapshot = currentSnapshot()) {
  if (!snapshot.shareLink) {
    return { level: 'idle', text: t('routeCheckIdle') };
  }
  if (!outboundChanged(snapshot)) {
    return { level: 'ok', text: t('routeCheckSaved') };
  }
  if (routeProbe.rawLink !== snapshot.shareLink) {
    return { level: 'pending', text: t('routeCheckRequired') };
  }
  if (routeProbe.ok) {
    const target = `${routeProbe.probe.host}:${routeProbe.probe.port}`;
    const latency = routeProbe.probe.latencyMs > 0 ? `${routeProbe.probe.latencyMs} ms` : t('routeCheckReachable');
    return { level: 'ok', text: t('routeCheckPassed', { target, latency }) };
  }
  return { level: 'error', text: t('routeCheckFailed', { error: routeProbe.probe?.error || '-' }) };
}

function renderProtocolBadge(snapshot = currentSnapshot()) {
  const outbound = currentOutboundPreview(snapshot);
  if (outbound) return `${outbound.protocol} · ${outbound.tag}`;
  if (!snapshot.shareLink) return t('protocolNotConfigured');
  return t('routeCheckPendingShort');
}

function renderStateBadge() {
  if (!serverState) return t('stateLoading');
  if (hasPendingChanges()) return t('statePending');
  return t('stateAppliedAt', { date: formatDate(serverState.updatedAt) });
}

function updateRoutingModeCards() {
  document.querySelectorAll('[data-route-mode]').forEach((button) => {
    const active = button.dataset.routeMode === $('routingMode').value;
    button.classList.toggle('is-active', active);
    button.setAttribute('aria-pressed', String(active));
  });
}

function updateRoutingModeNotice() {
  const notice = $('routingModeNotice');
  if ($('routingMode').value === 'direct' && hasProxyRoutingRules()) {
    notice.hidden = false;
    notice.textContent = t('directModeNotice');
    return;
  }
  notice.hidden = true;
  notice.textContent = '';
}

function updateRunetAutoRules() {
  const enabled = $('useRunet').checked;
  const domainWrap = $('autoProxyDomainsWrap');
  const ipWrap = $('autoProxyIpsWrap');
  if (!domainWrap || !ipWrap) return;
  domainWrap.hidden = !enabled;
  ipWrap.hidden = !enabled;
  if (!enabled) return;
  if ($('routingMode').value === 'force_proxy') {
    $('autoProxyDomains').textContent = 'geosite:ru-blocked-all';
    $('autoProxyIps').textContent = [
      'geoip:ru-blocked',
      'geoip:ru-blocked-community',
      'geoip:telegram',
    ].join('\n');
    return;
  }
  $('autoProxyDomains').textContent = 'ru-blocked-all.txt';
  $('autoProxyIps').textContent = [
    'ru-blocked.txt',
    'ru-blocked-community.txt',
    'telegram.txt',
  ].join('\n');
}

function updateEndpoint() {
  const uiHost = window.location.hostname || '-';
  const configuredDomain = $('vpnDomain')?.value.trim() || serverState?.server?.vpnDomain || '';
  $('uiHostValue').textContent = uiHost;
  $('ipsecEndpointValue').textContent = configuredDomain || uiHost;
}

function updatePendingBar() {
  if (!serverState) {
    $('pendingBar').hidden = true;
    return;
  }
  const snapshot = currentSnapshot();
  const dirty = hasPendingChanges();
  const needsCheck = routeCheckNeeded(snapshot);
  const pendingMessage = dirty
    ? (needsCheck ? t('pendingChangesRouteCheck') : t('pendingChangesMessage'))
    : '';
  $('pendingBar').hidden = !dirty;
  $('pendingMessage').textContent = pendingMessage;
  $('pendingApplyBtn').disabled = !dirty || needsCheck;
  $('stateBadge').textContent = renderStateBadge();
}

function updateRouteProbeView() {
  const status = routeCheckStatus();
  const box = $('routeProbeStatus');
  box.textContent = status.text;
  box.classList.remove('is-idle', 'is-pending', 'is-ok', 'is-error');
  box.classList.add(`is-${status.level}`);
  $('protocolBadge').textContent = renderProtocolBadge();
}

function updateDynamicText() {
  $('stateBadge').textContent = renderStateBadge();
  $('protocolBadge').textContent = renderProtocolBadge();
  if (!statusLoaded) $('statusBox').textContent = t('noStatus');
  if (!logsLoaded) $('logBox').textContent = t('noLogs');
  updateRouteProbeView();
  updatePendingBar();
  updateRunetAutoRules();
}

function syncDraftUI() {
  if (!serverState) return;
  updateRoutingModeCards();
  updateRoutingModeNotice();
  updateEndpoint();
  updateDirtyHighlights(baselineSnapshot(), currentSnapshot());
  updateDynamicText();
  resizeTextareas();
}

function eyeIcon(open) {
  return open
    ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 10.7a2 2 0 0 0 2.7 2.7"/><path d="M9.9 5.2A10.9 10.9 0 0 1 12 5c5.5 0 9.5 5.1 10 7-.2.7-1 2.2-2.5 3.7"/><path d="M6.7 6.7C4.5 8.2 3.2 10.3 2 12c.4 1.3 3.5 7 10 7 1.9 0 3.6-.5 5-1.2"/></svg>'
    : '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';
}

function copyIcon() {
  return '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="10" height="10" rx="2"/><path d="M7 15H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h7a2 2 0 0 1 2 2v1"/></svg>';
}

function removeIcon() {
  return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>';
}

function setCopyFeedback(button) {
  button.dataset.copied = 'true';
  button.title = t('copied');
  setTimeout(() => {
    button.dataset.copied = 'false';
    button.title = button.dataset.copyField === 'login' ? t('copyLogin') : t('copyPassword');
  }, 1200);
}

function userTrafficMarkup() {
  return `
    <dl class="user-stats">
      <div><dt>${escapeHTML(t('clientInDownload'))}</dt><dd data-traffic="inDownload">0 B</dd></div>
      <div><dt>${escapeHTML(t('clientInUpload'))}</dt><dd data-traffic="inUpload">0 B</dd></div>
      <div><dt>${escapeHTML(t('clientOutDownload'))}</dt><dd data-traffic="outDownload">0 B</dd></div>
      <div><dt>${escapeHTML(t('clientOutUpload'))}</dt><dd data-traffic="outUpload">0 B</dd></div>
    </dl>
  `;
}

function addUserRow(user = { login: '', password: '' }) {
  const row = document.createElement('section');
  row.className = 'user-card';
  row.innerHTML = `
    <div class="user-card-header">
      <div class="user-card-meta">
        <div class="user-card-meta-top">
          <strong class="user-card-title" data-user-title>${escapeHTML(user.login || t('userCardNew'))}</strong>
          <span class="status-chip is-offline" data-user-status>${escapeHTML(t('clientOffline'))}</span>
        </div>
        <span class="user-card-subtitle" data-user-ip>${escapeHTML(t('userInternalIp', { ip: '-' }))}</span>
      </div>
      <div class="user-card-actions">
        <button type="button" class="ghost icon-button" data-remove-user title="${escapeHTML(t('removeUser'))}" aria-label="${escapeHTML(t('removeUser'))}">${removeIcon()}<span class="visually-hidden-inline">${escapeHTML(t('removeUser'))}</span></button>
      </div>
    </div>
    <div class="user-card-grid">
      <div class="credential-stack">
        <div class="credential-field">
          <label data-i18n="adminUsername">${escapeHTML(t('adminUsername'))}</label>
          <div class="credential-input-wrap">
            <input data-field="login" placeholder="${escapeHTML(t('loginPlaceholder'))}" value="${escapeHTML(user.login || '')}">
            <button type="button" class="ghost icon-button" data-copy-field="login" data-copied="false" title="${escapeHTML(t('copyLogin'))}" aria-label="${escapeHTML(t('copyLogin'))}">${copyIcon()}<span class="visually-hidden-inline">${escapeHTML(t('copyLogin'))}</span></button>
          </div>
        </div>
        <div class="credential-field">
          <label data-i18n="adminPassword">${escapeHTML(t('adminPassword'))}</label>
          <div class="credential-input-wrap">
            <input data-field="password" type="password" placeholder="${escapeHTML(t('passwordPlaceholder'))}" value="${escapeHTML(user.password || '')}">
            <button type="button" class="ghost icon-button" data-toggle-password="false" title="${escapeHTML(t('showPassword'))}" aria-label="${escapeHTML(t('showPassword'))}">${eyeIcon(false)}<span class="visually-hidden-inline">${escapeHTML(t('showPassword'))}</span></button>
            <button type="button" class="ghost icon-button" data-copy-field="password" data-copied="false" title="${escapeHTML(t('copyPassword'))}" aria-label="${escapeHTML(t('copyPassword'))}">${copyIcon()}<span class="visually-hidden-inline">${escapeHTML(t('copyPassword'))}</span></button>
          </div>
        </div>
      </div>
      ${userTrafficMarkup()}
    </div>
  `;
  row.querySelector('[data-remove-user]').onclick = () => {
    if (!confirm(t('confirmRemoveUser'))) return;
    row.remove();
    syncDraftUI();
  };
  row.querySelector('[data-toggle-password]').onclick = () => {
    const input = row.querySelector('[data-field="password"]');
    const button = row.querySelector('[data-toggle-password]');
    const opened = button.dataset.togglePassword === 'true';
    input.type = opened ? 'password' : 'text';
    button.dataset.togglePassword = opened ? 'false' : 'true';
    button.title = opened ? t('showPassword') : t('hidePassword');
    button.setAttribute('aria-label', opened ? t('showPassword') : t('hidePassword'));
    button.innerHTML = `${eyeIcon(!opened)}<span class="visually-hidden-inline">${escapeHTML(opened ? t('showPassword') : t('hidePassword'))}</span>`;
  };
  row.querySelectorAll('[data-copy-field]').forEach((button) => {
    button.onclick = async () => {
      const input = row.querySelector(`[data-field="${button.dataset.copyField}"]`);
      await copyText(input.value);
      setCopyFeedback(button);
    };
  });
  row.querySelectorAll('[data-field]').forEach((input) => {
    input.addEventListener('input', () => {
      updateUserCardMeta(row);
      syncDraftUI();
    });
  });
  updateUserCardMeta(row);
  $('users').appendChild(row);
}

function renderUsers(users) {
  const box = $('users');
  box.innerHTML = '';
  for (const user of users || []) addUserRow(user);
}

function escapeHTML(v) {
  return String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function renderInlineMarkdown(text) {
  return escapeHTML(text)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}

function renderMarkdown(markdown) {
  const source = markdown.replace(/\r\n/g, '\n').split('\n');
  const html = [];
  let listType = '';
  let inCode = false;
  let codeLines = [];

  function closeList() {
    if (!listType) return;
    html.push(`</${listType}>`);
    listType = '';
  }

  function openList(nextType) {
    if (listType === nextType) return;
    closeList();
    listType = nextType;
    html.push(`<${listType}>`);
  }

  for (const line of source) {
    if (line.startsWith('```')) {
      if (inCode) {
        html.push(`<pre><code>${escapeHTML(codeLines.join('\n'))}</code></pre>`);
        codeLines = [];
        inCode = false;
      } else {
        closeList();
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      codeLines.push(line);
      continue;
    }
    const trimmed = line.trim();
    if (!trimmed) {
      closeList();
      continue;
    }
    const heading = trimmed.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      closeList();
      html.push(`<h${heading[1].length}>${renderInlineMarkdown(heading[2])}</h${heading[1].length}>`);
      continue;
    }
    const unordered = trimmed.match(/^[-*]\s+(.+)$/);
    if (unordered) {
      openList('ul');
      html.push(`<li>${renderInlineMarkdown(unordered[1])}</li>`);
      continue;
    }
    const ordered = trimmed.match(/^\d+\.\s+(.+)$/);
    if (ordered) {
      openList('ol');
      html.push(`<li>${renderInlineMarkdown(ordered[1])}</li>`);
      continue;
    }
    closeList();
    html.push(`<p>${renderInlineMarkdown(trimmed)}</p>`);
  }
  if (inCode) html.push(`<pre><code>${escapeHTML(codeLines.join('\n'))}</code></pre>`);
  closeList();
  return html.join('');
}

async function loadDocs(force = false) {
  if (!$('docsPanel')?.open && !force) return;
  if (!force && docsLoadedLanguage === language) return;
  const res = await fetch(`/docs/${language}.md`, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`docs HTTP ${res.status}`);
  const markdown = await res.text();
  $('docsBody').innerHTML = renderMarkdown(markdown);
  docsLoadedLanguage = language;
}

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const input = document.createElement('textarea');
  input.value = value;
  input.setAttribute('readonly', '');
  input.style.position = 'fixed';
  input.style.left = '-9999px';
  document.body.appendChild(input);
  input.select();
  document.execCommand('copy');
  input.remove();
}

async function probeLink() {
  const rawLink = $('shareLink').value.trim();
  if (!rawLink) {
    routeProbe = emptyRouteProbe();
    syncDraftUI();
    return;
  }
  try {
    const result = await api('/api/probe-link', { method: 'POST', body: JSON.stringify({ link: rawLink }) });
    routeProbe = {
      rawLink,
      ok: Boolean(result.probe?.ok),
      outbound: result.outbound || null,
      probe: result.probe || null,
    };
  } catch (err) {
    routeProbe = {
      rawLink,
      ok: false,
      outbound: null,
      probe: { error: err.message, host: '', port: 0, latencyMs: 0 },
    };
    throw err;
  }
  syncDraftUI();
}

async function applyDraft() {
  if (!serverState || !hasPendingChanges()) return;
  const snapshot = currentSnapshot();
  if (routeCheckNeeded(snapshot)) {
    throw new Error(t('routeCheckRequired'));
  }
  const outbound = currentOutboundPreview(snapshot);
  const nextState = buildStateForApply(outbound);
  await api('/api/state', { method: 'PUT', body: JSON.stringify(nextState) });
  try {
    await api('/api/apply', { method: 'POST', body: '{}' });
  } catch (err) {
    await load();
    throw err;
  }
  await load();
}

function discardDraft() {
  if (!serverState) return;
  fill();
}

function renderStatus(data) {
  if (data.mode === 'local-only') {
    return [
      `${t('platform')}: ${data.platform}`,
      data.message || t('previewOnlyTitle'),
    ].join('\n');
  }

  const traffic = parseNetDev(data.netDev || '');
  const rows = [
    `${t('platform')}: ${data.platform || '-'}`,
    `${t('applyEnabled')}: ${data.applyEnabled ? t('enabled') : t('disabled')}`,
    `${t('xray')}: ${statusValue(data.xray)}`,
    `${t('strongswan')}: ${statusValue(data.strongswan)}`,
    `dnsmasq: ${statusValue(data.dnsmasq)}`,
    `${t('routingMode')}: ${routingModeLabel(data.routingMode || serverState?.routes?.mode || 'direct')}`,
    `${t('geodataUpdated')}: ${formatGeodataUpdated(data)}`,
    '',
    `${t('networkTraffic')}:`,
    traffic.totalRx + traffic.totalTx > 0
      ? `${t('totalTraffic')}: ${formatBytes(traffic.totalRx)} ↓ / ${formatBytes(traffic.totalTx)} ↑`
      : t('noTraffic'),
  ];
  for (const item of traffic.interfaces) {
    rows.push(`${item.name}: ${formatBytes(item.rx)} ↓ / ${formatBytes(item.tx)} ↑`);
  }
  rows.push('', `${t('gatewayRules')}: ${gatewayRulesSummary(data.tproxyChain || '', data.redirectRules || '')}`);
  rows.push(`${t('kernelProxySet')}: ${ipsetSummary(data.proxySet || '')}`);
  rows.push('', `${t('ipsecSessions')}:`);
  rows.push(cleanSwanText(data.swanSAs || '') || t('noActiveSas'));
  return rows.join('\n');
}

function ipsetSummary(text) {
  const members = String(text || '').match(/Number of entries:\s*(\d+)/);
  if (members) return members[1];
  const trimmed = String(text || '').trim();
  return trimmed ? '-' : '0';
}

function statusValue(value) {
  const text = String(value || '').trim();
  return text || '-';
}

function parseNetDev(text) {
  const interfaces = [];
  for (const line of String(text).split('\n')) {
    const match = line.match(/^\s*([^:]+):\s*(.+)$/);
    if (!match) continue;
    const name = match[1].trim();
    const values = match[2].trim().split(/\s+/).map(Number);
    if (values.length < 16 || values.some((v) => Number.isNaN(v))) continue;
    const rx = values[0];
    const tx = values[8];
    if (name === 'lo') continue;
    interfaces.push({ name, rx, tx, virtual: /^(docker|br-|veth)/.test(name) });
  }
  const totalRx = interfaces.reduce((sum, item) => sum + item.rx, 0);
  const totalTx = interfaces.reduce((sum, item) => sum + item.tx, 0);
  const primary = interfaces
    .filter((item) => !item.virtual)
    .sort((a, b) => (b.rx + b.tx) - (a.rx + a.tx))
    .slice(0, 3);
  return { totalRx, totalTx, interfaces: primary };
}

function formatBytes(value) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let next = Number(value) || 0;
  let index = 0;
  while (next >= 1024 && index < units.length - 1) {
    next /= 1024;
    index += 1;
  }
  return `${next.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatGeodataUpdated(data) {
  if (data.geodataStatus !== 'ready' || !data.geodataUpdatedAt) return t('geodataMissing');
  return formatDate(data.geodataUpdatedAt);
}

function routingModeLabel(mode) {
  if (mode === 'selective') return t('routingModeSelective');
  if (mode === 'force_proxy') return t('routingModeForceProxy');
  return t('routingModeDirect');
}

function gatewayRulesSummary(mangleRaw = '', redirectRaw = '') {
  const redirectCount = String(redirectRaw).split('\n').filter((line) => line.includes('-j REDIRECT')).length;
  const tproxyCount = String(mangleRaw).split('\n').filter((line) => line.includes('-j TPROXY')).length;
  const directBypass = `${mangleRaw}\n${redirectRaw}`.split('\n').some((line) => line.includes('-j RETURN'));
  if (tproxyCount > 0) return t('gatewayTproxyActive', { count: tproxyCount });
  if (redirectCount > 0) return t('gatewayRedirectActive', { count: redirectCount });
  if (directBypass) return t('gatewayDirectActive');
  return t('gatewayWaiting');
}

function cleanSwanText(raw) {
  return String(raw)
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => !line.includes('agent plugin requires CAP_SETUID/CAP_SETGID'))
    .filter((line) => !line.includes("plugin 'agent': failed to load"))
    .join('\n');
}

async function refreshStatus() {
  const data = await api('/api/status');
  $('pendingApplyBtn').title = data.mode === 'local-only' ? t('previewOnlyTitle') : '';
  statusLoaded = true;
  $('statusBox').textContent = renderStatus(data);
  const clientRows = buildClientTrafficRows(data);
  lastClientRows = clientRows;
  updateUserTraffic(clientRows);
}

function buildClientTrafficRows(data) {
  const clients = parseIpsecClients(data.swanSAs || '');
  const stats = parseXrayStats(data.xrayStats || '');
  const loginByTag = Object.fromEntries((serverState?.server?.users || []).map((user) => [safeTag(user.login), user.login]));
  const rows = clients.map((client) => normalizeClientTraffic({ ...client, ...(stats[safeTag(client.username)] || {}) }));
  const counterOnlyRows = Object.entries(stats)
    .filter(([tag]) => !clients.some((client) => safeTag(client.username) === tag))
    .map(([tag, values]) => normalizeClientTraffic({ username: loginByTag[tag] || tag, ip: '-', connected: false, ...values }));
  return [...rows, ...counterOnlyRows];
}

function normalizeClientTraffic(client) {
  const inDownload = Number(client.inDownload) || 0;
  const inUpload = Number(client.inUpload) || 0;
  const outDownload = Number(client.outDownload) || 0;
  const outUpload = Number(client.outUpload) || 0;
  return { ...client, inDownload, inUpload, outDownload, outUpload };
}

function updateUserTraffic(clientRows) {
  document.querySelectorAll('.user-card').forEach((row) => {
    const login = row.querySelector('[data-field="login"]')?.value.trim();
    const traffic = clientRows.find((item) => item.username === login);
    const online = row.querySelector('[data-user-status]');
    const ip = row.querySelector('[data-user-ip]');
    if (online) {
      online.textContent = traffic?.connected ? t('clientOnline') : t('clientOffline');
      online.classList.toggle('is-online', Boolean(traffic?.connected));
      online.classList.toggle('is-offline', !traffic?.connected);
    }
    if (ip) {
      ip.textContent = t('userInternalIp', { ip: traffic?.ip || '-' });
    }
    for (const key of ['inDownload', 'inUpload', 'outDownload', 'outUpload']) {
      const cell = row.querySelector(`[data-traffic="${key}"]`);
      if (cell) cell.textContent = formatBytes(traffic?.[key] || 0);
    }
  });
}

function updateUserCardMeta(row) {
  const login = row.querySelector('[data-field="login"]')?.value.trim() || t('userCardNew');
  const title = row.querySelector('[data-user-title]');
  if (title) title.textContent = login;
}

function parseIpsecClients(raw) {
  const clients = [];
  for (const line of String(raw || '').split('\n')) {
    const remote = line.match(/EAP:\s*'([^']+)'\s*\[([^\]]+)\]/);
    if (remote) {
      clients.push({ username: remote[1], ip: remote[2], connected: true });
    }
  }
  return clients;
}

function parseXrayStats(raw) {
  const stats = {};
  for (const item of readXrayStatItems(raw)) {
    const match = String(item.name || '').match(/^outbound>>>(direct|direct-[^>]+|proxy-[^>]+)>>>traffic>>>(uplink|downlink)$/);
    if (!match) continue;
    const outbound = match[1];
    const tag = tagFromOutboundTag(outbound);
    if (tag === 'primary' || outbound === 'direct') continue;
    const direction = match[2];
    const value = Number(item.value) || 0;
    const row = stats[tag] || { inDownload: 0, inUpload: 0, outDownload: 0, outUpload: 0 };
    const isOut = outbound.startsWith('proxy-');
    if (direction === 'downlink' && isOut) row.outDownload += value;
    if (direction === 'uplink' && isOut) row.outUpload += value;
    if (direction === 'downlink' && !isOut) row.inDownload += value;
    if (direction === 'uplink' && !isOut) row.inUpload += value;
    stats[tag] = row;
  }
  return stats;
}

function readXrayStatItems(raw) {
  const text = String(raw || '');
  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed.stat) ? parsed.stat : [];
  } catch (_) {
    return [...text.matchAll(/name:\s*"([^"]+)"\s+value:\s*(\d+)/g)].map((match) => ({ name: match[1], value: Number(match[2]) || 0 }));
  }
}

function tagFromOutboundTag(tag) {
  return String(tag || '').replace(/^(proxy|direct)-/, '');
}

function safeTag(value) {
  const next = String(value || '').replace(/[^A-Za-z0-9_.-]/g, '_');
  return next || 'user';
}

async function refreshLogs() {
  const data = await api('/api/logs');
  logsLoaded = true;
  logLines = (data.lines || []).slice(-60);
  renderLogs(logLines);
}

async function resetTraffic() {
  await api('/api/reset-traffic', { method: 'POST', body: '{}' });
  await refreshStatus();
  if ($('activityPanel')?.open) await refreshLogs();
}

function renderLogs(lines) {
  const box = $('logBox');
  $('logCount').textContent = String(lines.length);
  if (!lines.length) {
    box.textContent = t('noActivity');
    return;
  }
  box.innerHTML = lines.slice(-24).reverse().map((line) => {
    const event = parseActivityLine(line);
    return `
      <article class="log-entry log-${escapeHTML(event.level)}">
        <time>${escapeHTML(event.time)}</time>
        <span>${escapeHTML(event.kindLabel)}</span>
        <strong>${escapeHTML(event.message)}</strong>
        ${event.details ? `<small>${escapeHTML(event.details)}</small>` : ''}
      </article>
    `;
  }).join('');
}

function parseActivityLine(line) {
  const raw = String(line || '');
  const timeMatch = raw.match(/^(\S+)/);
  const kind = readLogField(raw, 'kind') || 'event';
  const message = readLogField(raw, 'msg') || raw.replace(/^\S+\s*/, '');
  const fields = [];
  for (const key of ['protocol', 'username', 'remote', 'users', 'warnings', 'changedFiles', 'hasOutbound', 'host', 'port', 'network', 'ok']) {
    const value = readLogField(raw, key);
    if (value) fields.push(`${key}=${value}`);
  }
  return {
    time: formatLogTime(timeMatch?.[1] || ''),
    kindLabel: logKindLabel(kind),
    level: logLevel(kind, message),
    message,
    details: fields.join('  '),
  };
}

function readLogField(line, key) {
  const match = String(line).match(new RegExp(`${key}="((?:[^"\\\\]|\\\\.)*)"`));
  if (!match) return '';
  return match[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
}

function formatLogTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || '-';
  return date.toLocaleTimeString(language === 'ru' ? 'ru-RU' : 'en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function logKindLabel(kind) {
  const last = String(kind).split('.').pop();
  const labels = {
    login: t('logLogin'),
    failed: t('logFailed'),
    read: t('logRead'),
    write: t('logWrite'),
    apply: t('logApply'),
    probe: t('logProbe'),
    parse: t('logParse'),
  };
  return labels[last] || kind;
}

function logLevel(kind, message) {
  const text = `${kind} ${message}`.toLowerCase();
  if (text.includes('failed') || text.includes('warning') || text.includes('error')) return 'warn';
  if (text.includes('apply')) return 'apply';
  if (text.includes('login')) return 'auth';
  if (text.includes('probe')) return 'probe';
  return 'info';
}

async function refreshTelemetry() {
  if (!authenticated || autoRefreshBusy) return;
  autoRefreshBusy = true;
  try {
    await refreshStatus();
    if ($('activityPanel')?.open) await refreshLogs();
  } finally {
    autoRefreshBusy = false;
  }
}

function initTooltips() {
  const tip = $('tooltip');
  document.querySelectorAll('[data-tip]').forEach((el) => {
    el.addEventListener('mousemove', (event) => {
      tip.textContent = el.getAttribute('data-tip') || '';
      tip.style.display = 'block';
      const pad = 16;
      const rect = tip.getBoundingClientRect();
      let left = event.clientX + pad;
      let top = event.clientY + pad;
      if (left + rect.width > window.innerWidth - 12) left = event.clientX - rect.width - pad;
      if (top + rect.height > window.innerHeight - 12) top = event.clientY - rect.height - pad;
      tip.style.left = `${Math.max(12, left)}px`;
      tip.style.top = `${Math.max(12, top)}px`;
    });
    el.addEventListener('mouseleave', () => {
      tip.style.display = 'none';
    });
  });
}

function attachStaticListeners() {
  $('configForm').onsubmit = (event) => event.preventDefault();
  $('loginForm').onsubmit = (event) => {
    event.preventDefault();
    login().catch((err) => showLogin(err.message));
  };
  $('logoutBtn').onclick = () => logout();
  $('probeLinkBtn').onclick = () => withBusy($('probeLinkBtn'), () => probeLink()).catch(alert);
  $('pendingApplyBtn').onclick = () => {
    if (confirm(t('confirmApply'))) {
      withBusy($('pendingApplyBtn'), () => applyDraft()).catch(alert);
    }
  };
  $('discardBtn').onclick = () => discardDraft();
  $('refreshStatus').onclick = () => refreshTelemetry().catch(alert);
  $('addUserBtn').onclick = () => {
    addUserRow({ login: `vpn_${Math.random().toString(16).slice(2, 10)}`, password: crypto.randomUUID().slice(0, 18) });
    syncDraftUI();
  };
  $('resetTrafficBtn').onclick = () => {
    if (confirm(t('confirmResetTraffic'))) {
      withBusy($('resetTrafficBtn'), () => resetTraffic()).catch(alert);
    }
  };
  $('copyIpsecEndpoint').onclick = async () => {
    await copyText($('ipsecEndpointValue').textContent);
    $('copyIpsecEndpoint').textContent = t('copied');
    setTimeout(() => { $('copyIpsecEndpoint').textContent = t('copy'); }, 1200);
  };
  $('routingMode').addEventListener('change', syncDraftUI);
  $('useRunet').addEventListener('change', syncDraftUI);
  $('mobikeEnabled').addEventListener('change', syncDraftUI);
  document.querySelectorAll('[data-route-mode]').forEach((button) => {
    button.onclick = () => {
      $('routingMode').value = button.dataset.routeMode;
      syncDraftUI();
    };
  });
  document.querySelectorAll('[data-language]').forEach((el) => {
    el.onclick = () => setLanguage(el.dataset.language);
  });
  trackedFieldIds.forEach((id) => {
    $(id).addEventListener('input', () => {
      if (id === 'shareLink' && routeProbe.rawLink !== $('shareLink').value.trim()) {
        updateRouteProbeView();
      }
      syncDraftUI();
    });
  });
  document.querySelectorAll('textarea').forEach((el) => {
    el.addEventListener('input', () => resizeTextarea(el));
  });
  $('activityPanel')?.addEventListener('toggle', () => {
    if ($('activityPanel')?.open) refreshLogs().catch(alert);
  });
  $('docsPanel')?.addEventListener('toggle', () => {
    if ($('docsPanel')?.open) {
      loadDocs().catch(() => {
        $('docsBody').textContent = t('docsLoadError');
      });
    }
  });
  $('vpnDomain').addEventListener('input', updateEndpoint);
  window.addEventListener('beforeunload', (event) => {
    if (!hasPendingChanges()) return;
    event.preventDefault();
    event.returnValue = '';
  });
}

async function withBusy(button, action) {
  const original = button.textContent;
  button.disabled = true;
  try {
    return await action();
  } finally {
    button.disabled = false;
    if (button.id === 'copyIpsecEndpoint') {
      button.textContent = t('copy');
    } else if (button.id === 'pendingApplyBtn') {
      button.textContent = t('applyToHost');
    } else if (button.id === 'probeLinkBtn') {
      button.textContent = t('checkRoute');
    } else if (button.id === 'resetTrafficBtn') {
      button.textContent = t('resetTraffic');
    } else {
      button.textContent = original;
    }
  }
}

applyLanguage();
initTooltips();
attachStaticListeners();
checkSession()
  .then((ok) => {
    if (!ok) return null;
    return load();
  })
  .catch((err) => {
    $('stateBadge').textContent = err.message;
    showLogin();
  });

setInterval(() => {
  if ($('autoRefresh').checked) refreshTelemetry().catch(() => {});
}, 3000);
