import { I18N } from './i18n.js';

const { invoke } = window.__TAURI__.core;
const { getCurrentWindow } = window.__TAURI__.window;

const ICON_DOTS =
  '<svg viewBox="0 0 20 20"><circle cx="10" cy="4" r="1.7"></circle><circle cx="10" cy="10" r="1.7"></circle><circle cx="10" cy="16" r="1.7"></circle></svg>';
const ICON_CARET =
  '<svg class="group__caret" viewBox="0 0 24 24" aria-hidden="true"><polyline points="9 6 15 12 9 18"></polyline></svg>';
const ICON_EYE =
  '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
const ICON_EYE_OFF =
  '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3l18 18"></path><path d="M10.6 10.6a3 3 0 0 0 4.2 4.2"></path><path d="M9.5 5A9.6 9.6 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.7 4.4"></path><path d="M6.2 6.2A17 17 0 0 0 2 12s3.5 7 10 7a9.6 9.6 0 0 0 3.3-.6"></path></svg>';
const ICON_COPY =
  '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"></rect><path d="M5 15V5a2 2 0 0 1 2-2h10"></path></svg>';
const ICON_CHECK = '<svg viewBox="0 0 24 24" aria-hidden="true"><polyline points="5 12 10 17 19 7"></polyline></svg>';
const ICON_STAR =
  '<svg viewBox="0 0 24 24" aria-hidden="true"><polygon points="12 3 14.9 9 21.4 9.7 16.5 14.1 17.9 20.5 12 17.3 6.1 20.5 7.5 14.1 2.6 9.7 9.1 9"></polygon></svg>';

const DOTS = '••••••••••••';

const ICON_TRASH =
  '<svg viewBox="0 0 24 24" aria-hidden="true"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path><path d="M10 11v6M14 11v6"></path><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"></path></svg>';
const TOTP_RING =
  '<svg class="totp__ring" viewBox="0 0 24 24" aria-hidden="true"><circle class="totp__ring-bg" cx="12" cy="12" r="9"></circle><circle class="totp__ring-fg" cx="12" cy="12" r="9"></circle></svg>';

let totpTimer = null;
let totpRaf = null;
let totpEntries = [];

const STRENGTH_COLORS = ['#e0483f', '#e0902f', '#cbb52f', '#3fa85f'];

function passwordStrength(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) {
    pool += 26;
  }
  if (/[A-Z]/.test(pw)) {
    pool += 26;
  }
  if (/[0-9]/.test(pw)) {
    pool += 10;
  }
  if (/[^a-zA-Z0-9]/.test(pw)) {
    pool += 32;
  }
  const entropy = pw.length * Math.log2(pool || 1);
  if (pw.length < 8 || entropy < 40) {
    return 0;
  }
  if (entropy < 70) {
    return 1;
  }
  if (entropy < 100) {
    return 2;
  }
  return 3;
}

function strengthValue(pw) {
  const score = passwordStrength(pw);
  const wrap = document.createElement('div');
  wrap.className = 'detail__strength';
  const bar = document.createElement('div');
  bar.className = 'strength__bar';
  for (let i = 0; i < 4; i += 1) {
    const seg = document.createElement('span');
    seg.className = 'strength__seg';
    if (i <= score) {
      seg.style.background = STRENGTH_COLORS[score];
    }
    bar.appendChild(seg);
  }
  const label = document.createElement('span');
  label.className = 'strength__label';
  label.textContent = t(`strength.${score}`);
  label.style.color = STRENGTH_COLORS[score];
  wrap.append(bar, label);
  return wrap;
}

const screens = {
  create: document.querySelector('#screen-create'),
  unlock: document.querySelector('#screen-unlock'),
  vault: document.querySelector('#screen-vault'),
  totpCreate: document.querySelector('#screen-totp-create'),
  totpUnlock: document.querySelector('#screen-totp-unlock'),
  totp: document.querySelector('#screen-totp')
};

const LEVELS = { normal: { fill: 1 }, fort: { fill: 2 }, parano: { fill: 3 } };
const GAUGE_TOTAL = 3;

let currentSpace = 'passwords';
let passwordTarget = 'vault';
let rotateTarget = 'vault';
let recoverTarget = 'vault';

let lang = loadLang();

function loadLang() {
  const stored = localStorage.getItem('lang');
  if (stored && I18N['tab.passwords'][stored]) {
    return stored;
  }
  const nav = (navigator.language || 'fr').slice(0, 2).toLowerCase();
  return I18N['tab.passwords'][nav] ? nav : 'fr';
}

function t(key, vars) {
  const entry = I18N[key];
  let s = entry ? entry[lang] || entry.fr : key;
  if (vars) {
    for (const k of Object.keys(vars)) {
      s = s.split(`{${k}}`).join(vars[k]);
    }
  }
  return s;
}

function errText(e) {
  return t(String(e));
}

function levelName(key) {
  return t(`level.${LEVELS[key] ? key : 'normal'}`);
}

function levelDesc(key) {
  return t(`level.${LEVELS[key] ? key : 'normal'}Desc`);
}

function applyI18n() {
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-ph]').forEach((el) => {
    el.placeholder = t(el.dataset.i18nPh);
  });
  document.querySelectorAll('[data-i18n-title]').forEach((el) => {
    const s = t(el.dataset.i18nTitle);
    el.title = s;
    el.setAttribute('aria-label', s);
  });
}

function setLang(value) {
  lang = I18N['tab.passwords'][value] ? value : 'fr';
  localStorage.setItem('lang', lang);
  applyI18n();
  applyLevel(document.documentElement.getAttribute('data-level') || 'normal');
  updateSettingsLevel();
  if (!document.querySelector('#settings-modal').hidden) {
    if (document.querySelector('#pw-settings-locked').hidden) {
      updateRecoverySetting('vault');
    }
    if (document.querySelector('#totp-settings-locked').hidden) {
      updateRecoverySetting('totp');
    }
  }
  document.querySelector('#level-desc').textContent = levelDesc(selectedLevel);
  updateTrayLabels();
  renderDetail();
}

let entries = [];
let groups = [];
let favGroups = [];
let editingId = null;
let renamingGroup = null;
let filterText = '';
let idleTimer = null;
let selectedLevel = 'normal';
let pendingLevel = 'normal';
let selectedEntryId = null;
let detailRevealed = false;
let detailPassword = null;
let revealedFields = new Set();
let entryKind = 'login';
let dragId = null;
let dragKind = null;
let dragGroup = null;
const collapsedGroups = new Set(loadCollapsed());

function loadCollapsed() {
  try {
    const raw = JSON.parse(localStorage.getItem('collapsedGroups'));
    return Array.isArray(raw) ? raw : [];
  } catch (e) {
    return [];
  }
}

function saveCollapsed() {
  localStorage.setItem('collapsedGroups', JSON.stringify([...collapsedGroups]));
}

function renderGauge(el, key) {
  el.textContent = '';
  const fill = LEVELS[key].fill;
  for (let i = 0; i < GAUGE_TOTAL; i += 1) {
    const seg = document.createElement('span');
    seg.className = 'gauge__seg';
    if (i < fill) {
      seg.classList.add('is-on');
    }
    el.appendChild(seg);
  }
}

function applyLevel(level) {
  const key = LEVELS[level] ? level : 'normal';
  document.documentElement.setAttribute('data-level', key);
  document.querySelector('#chip-name').textContent = levelName(key);
  renderGauge(document.querySelector('#gauge-bar'), key);
  invoke('set_level_icon', { level: key, theme: currentTheme() }).catch(() => {});
}

function selectLevel(level) {
  selectedLevel = LEVELS[level] ? level : 'normal';
  document.querySelectorAll('#level-picker .level').forEach((b) => {
    b.classList.toggle('is-active', b.dataset.level === selectedLevel);
  });
  document.querySelector('#level-desc').textContent = levelDesc(selectedLevel);
  applyLevel(selectedLevel);
}

async function refreshLevel() {
  try {
    applyLevel(await invoke('vault_level'));
  } catch (e) {
    applyLevel('normal');
  }
}

function selectPendingLevel(level) {
  pendingLevel = LEVELS[level] ? level : 'normal';
  document.querySelectorAll('#level-modal-picker .level').forEach((b) => {
    b.classList.toggle('is-active', b.dataset.level === pendingLevel);
  });
  document.querySelector('#level-modal-desc').textContent = levelDesc(pendingLevel);
}

function openLevelModal() {
  const current = document.documentElement.getAttribute('data-level') || 'normal';
  selectPendingLevel(current);
  document.querySelector('#level-modal-pw').value = '';
  document.querySelector('#level-modal-err').textContent = '';
  document.querySelector('#level-modal').hidden = false;
  document.querySelector('#level-modal-pw').focus();
}

function closeLevelModal() {
  document.querySelector('#level-modal').hidden = true;
  document.querySelector('#level-modal-pw').value = '';
}

async function submitLevelChange(e) {
  e.preventDefault();
  const errEl = document.querySelector('#level-modal-err');
  const pwEl = document.querySelector('#level-modal-pw');
  errEl.textContent = '';
  if (!pwEl.value) {
    errEl.textContent = t('val.masterRequired');
    return;
  }
  await withButton(document.querySelector('#level-form button[type="submit"]'), t('load.reencrypting'), async () => {
    try {
      await invoke('change_level', { masterPassword: pwEl.value, level: pendingLevel });
      pwEl.value = '';
      closeLevelModal();
      await refreshLevel();
      updateSettingsLevel();
    } catch (err) {
      pwEl.value = '';
      errEl.textContent = errText(err);
    }
  });
}

function updateSettingsLevel() {
  const current = document.documentElement.getAttribute('data-level') || 'normal';
  const key = LEVELS[current] ? current : 'normal';
  document.querySelector('#settings-level-name').textContent = levelName(key);
  renderGauge(document.querySelector('#settings-gauge'), key);
}

function openPasswordModal(target) {
  passwordTarget = target === 'totp' ? 'totp' : 'vault';
  document.querySelector('#password-modal-title').textContent =
    passwordTarget === 'totp' ? t('password.titleTotp') : t('password.title');
  document.querySelector('#cur-pw').value = '';
  document.querySelector('#new-pw').value = '';
  document.querySelector('#new-pw2').value = '';
  document.querySelector('#password-err').textContent = '';
  document.querySelector('#password-modal').hidden = false;
  document.querySelector('#cur-pw').focus();
}

function closePasswordModal() {
  document.querySelector('#password-modal').hidden = true;
  document.querySelector('#cur-pw').value = '';
  document.querySelector('#new-pw').value = '';
  document.querySelector('#new-pw2').value = '';
}

async function submitPasswordChange(e) {
  e.preventDefault();
  const errEl = document.querySelector('#password-err');
  const cur = document.querySelector('#cur-pw');
  const nw = document.querySelector('#new-pw');
  const nw2 = document.querySelector('#new-pw2');
  errEl.textContent = '';
  if (nw.value.length < 8) {
    errEl.textContent = t('val.min8');
    return;
  }
  if (nw.value !== nw2.value) {
    errEl.textContent = t('val.mismatch');
    return;
  }
  const command = passwordTarget === 'totp' ? 'change_totp_master_password' : 'change_master_password';
  await withButton(document.querySelector('#password-form button[type="submit"]'), t('load.reencrypting'), async () => {
    try {
      await invoke(command, { current: cur.value, new: nw.value });
      closePasswordModal();
    } catch (err) {
      cur.value = '';
      errEl.textContent = errText(err);
    }
  });
}

function setPwnedIndicator(state) {
  const btn = document.querySelector('#health-btn');
  if (!btn) {
    return;
  }
  btn.classList.remove('is-good', 'is-bad');
  if (state === 'good') {
    btn.classList.add('is-good');
  } else if (state === 'bad') {
    btn.classList.add('is-bad');
  }
}

let healthData = { weak: [], dups: [], leaked: null, old: [], checking: false, error: false };

function pwRotateMonths() {
  return parseInt(localStorage.getItem('pwRotateMonths') || '0', 10) || 0;
}

function isEntryPwOld(entry) {
  const months = pwRotateMonths();
  if (months <= 0 || entry.kind === 'note') {
    return false;
  }
  const ts = entry.password_modified || entry.modified || 0;
  if (!ts) {
    return false;
  }
  return Math.floor(Date.now() / 1000) - ts > months * 30 * 24 * 60 * 60;
}

function closeHealthModal() {
  document.querySelector('#health-modal').hidden = true;
}

async function openHealthModal() {
  healthData = { weak: [], dups: [], leaked: null, old: [], checking: false, error: false };
  const body = document.querySelector('#health-body');
  body.textContent = '';
  const loading = document.createElement('p');
  loading.className = 'pwned__summary';
  loading.textContent = t('health.analyzing');
  body.appendChild(loading);
  document.querySelector('#health-modal').hidden = false;
  try {
    healthData.weak = await invoke('find_weak');
    healthData.dups = await invoke('find_duplicates');
    const months = pwRotateMonths();
    healthData.old = months > 0 ? await invoke('find_old', { months }) : [];
  } catch (e) {
    body.textContent = '';
    const err = document.createElement('p');
    err.className = 'error';
    err.textContent = errText(e);
    body.appendChild(err);
    return;
  }
  await runHealthLeakCheck();
}

async function runHealthLeakCheck() {
  healthData.checking = true;
  healthData.error = false;
  renderHealth();
  try {
    const results = await invoke('check_all_pwned');
    healthData.leaked = results.filter((r) => r.count > 0).map((r) => ({ id: r.id, name: r.name }));
    healthData.checking = false;
    renderHealth();
  } catch {
    healthData.checking = false;
    healthData.error = true;
    renderHealth();
  }
}

function healthAtRisk() {
  const ids = new Set();
  healthData.weak.forEach((e) => ids.add(e.id));
  healthData.dups.forEach((g) => g.forEach((e) => ids.add(e.id)));
  healthData.old.forEach((e) => ids.add(e.id));
  if (healthData.leaked) {
    healthData.leaked.forEach((e) => ids.add(e.id));
  }
  return ids;
}

function healthSectionTitle(label, count, bad) {
  const h = document.createElement('div');
  h.className = 'health__sectionTitle';
  if (bad) {
    h.classList.add('is-bad');
  } else {
    h.classList.add('is-good');
  }
  h.textContent = `${label} · ${count}`;
  return h;
}

function healthEntryItem(id, name) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'health__item';
  b.dataset.action = 'health-select';
  b.dataset.id = id;
  b.textContent = name;
  return b;
}

function renderHealth() {
  const body = document.querySelector('#health-body');
  body.textContent = '';
  const total = entries.length;
  const atRisk = healthAtRisk();
  const healthy = Math.max(0, total - atRisk.size);
  const pct = total === 0 ? 100 : Math.round((healthy / total) * 100);
  setPwnedIndicator(atRisk.size === 0 && healthData.leaked ? 'good' : atRisk.size > 0 ? 'bad' : 'none');

  const score = document.createElement('div');
  score.className = 'health__score';
  const tone = pct >= 80 ? 'is-good' : pct >= 50 ? 'is-warn' : 'is-bad';
  score.classList.add(tone);
  const pctEl = document.createElement('div');
  pctEl.className = 'health__pct';
  pctEl.textContent = `${pct}%`;
  const label = document.createElement('div');
  label.className = 'health__scoreLabel';
  label.textContent = t('health.healthy', { n: healthy, total });
  score.append(pctEl, label);
  body.appendChild(score);

  const meter = document.createElement('div');
  meter.className = 'health__meter';
  const fill = document.createElement('div');
  fill.className = `health__meter-fill ${tone}`;
  fill.style.width = `${pct}%`;
  meter.appendChild(fill);
  body.appendChild(meter);

  if (healthData.checking) {
    const note = document.createElement('p');
    note.className = 'health__note';
    note.textContent = t('health.checkingLeaks');
    body.appendChild(note);
  } else if (healthData.error) {
    const note = document.createElement('p');
    note.className = 'health__note';
    note.textContent = t('health.leaksFailed');
    body.appendChild(note);
  }

  body.appendChild(healthSectionTitle(t('health.weak'), healthData.weak.length, healthData.weak.length > 0));
  if (healthData.weak.length > 0) {
    const list = document.createElement('div');
    list.className = 'health__list';
    healthData.weak.forEach((e) => list.appendChild(healthEntryItem(e.id, e.name)));
    body.appendChild(list);
  }

  body.appendChild(healthSectionTitle(t('health.reused'), healthData.dups.length, healthData.dups.length > 0));
  if (healthData.dups.length > 0) {
    for (const group of healthData.dups) {
      const block = document.createElement('div');
      block.className = 'health__list health__dupgroup';
      group.forEach((e) => block.appendChild(healthEntryItem(e.id, e.name)));
      body.appendChild(block);
    }
  }

  if (pwRotateMonths() > 0) {
    body.appendChild(healthSectionTitle(t('health.old'), healthData.old.length, healthData.old.length > 0));
    if (healthData.old.length > 0) {
      const list = document.createElement('div');
      list.className = 'health__list';
      healthData.old.forEach((e) => list.appendChild(healthEntryItem(e.id, e.name)));
      body.appendChild(list);
    }
  }

  const leakedCount = healthData.leaked ? healthData.leaked.length : 0;
  const leakLabel = healthData.checking ? '…' : healthData.leaked ? leakedCount : '-';
  body.appendChild(healthSectionTitle(t('health.leaks'), leakLabel, leakedCount > 0));
  if (healthData.error) {
    const actions = document.createElement('div');
    actions.className = 'health__actions';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn--ghost btn--sm';
    btn.dataset.action = 'health-check-leaks';
    btn.textContent = t('health.retry');
    actions.appendChild(btn);
    body.appendChild(actions);
  } else if (healthData.leaked && leakedCount > 0) {
    const list = document.createElement('div');
    list.className = 'health__list';
    healthData.leaked.forEach((e) => list.appendChild(healthEntryItem(e.id, e.name)));
    body.appendChild(list);
    const actions = document.createElement('div');
    actions.className = 'health__actions';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn--primary btn--sm';
    btn.dataset.action = 'health-replace-leaked';
    btn.textContent = t('health.replaceLeaked', { n: leakedCount });
    actions.appendChild(btn);
    body.appendChild(actions);
  }
}

async function onHealthClick(e) {
  const btn = e.target.closest('[data-action]');
  if (!btn) {
    return;
  }
  const action = btn.dataset.action;
  if (action === 'health-select') {
    closeHealthModal();
    selectEntry(btn.dataset.id);
  } else if (action === 'health-check-leaks') {
    await runHealthLeakCheck();
  } else if (action === 'health-replace-leaked') {
    btn.disabled = true;
    btn.textContent = t('pwned.replacing');
    try {
      const ids = healthData.leaked.map((e) => e.id);
      for (const id of ids) {
        await invoke('regenerate_password', { id });
      }
      await renderVault();
      if (ids.includes(selectedEntryId)) {
        await loadDetailSecret();
      }
      healthData.leaked = [];
      healthData.weak = await invoke('find_weak');
      healthData.dups = await invoke('find_duplicates');
      renderHealth();
    } catch (err) {
      document.querySelector('#vault-err').textContent = errText(err);
    }
  }
}

function idleSeconds() {
  const value = parseInt(localStorage.getItem('idleSeconds'), 10);
  return Number.isNaN(value) ? 300 : value;
}

function clearIdleTimer() {
  if (idleTimer !== null) {
    clearTimeout(idleTimer);
    idleTimer = null;
  }
}

function startIdleTimer() {
  clearIdleTimer();
  const seconds = idleSeconds();
  if (seconds > 0) {
    idleTimer = setTimeout(() => {
      idleLock();
    }, seconds * 1000);
  }
}

async function idleLock() {
  clearIdleTimer();
  closeModal();
  closeGroupModal();
  closeLevelModal();
  closeTotpModal();
  closeAllMenus();
  stopTotpTimer();
  selectedEntryId = null;
  detailRevealed = false;
  detailPassword = null;
  setPwnedIndicator('none');
  await invoke('lock_vault').catch(() => {});
  await invoke('lock_totp').catch(() => {});
  await refreshLevel();
  await refreshForgotLink();
  await switchSpace(currentSpace);
  if (discreetEnabled()) {
    await enterDecoy();
  }
}

function onActivity() {
  if (idleTimer !== null) {
    startIdleTimer();
  }
}

function show(name) {
  for (const [key, el] of Object.entries(screens)) {
    el.hidden = key !== name;
  }
  if (name === 'vault' || name === 'totp') {
    startIdleTimer();
  } else {
    clearIdleTimer();
  }
  if (name === 'create') {
    document.querySelector('#create-pw').focus();
  } else if (name === 'unlock') {
    document.querySelector('#unlock-pw').focus();
  }
}

function currentTheme() {
  return localStorage.getItem('theme') === 'light' ? 'light' : 'dark';
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const level = document.documentElement.getAttribute('data-level') || 'normal';
  invoke('set_level_icon', { level, theme }).catch(() => {});
}

function setTheme(theme) {
  localStorage.setItem('theme', theme);
  applyTheme(theme);
}

async function route() {
  if (await invoke('is_unlocked')) {
    await renderVault();
    show('vault');
  } else if (await invoke('vault_exists')) {
    await refreshLevel();
    await refreshForgotLink();
    show('unlock');
  } else {
    show('create');
  }
}

async function refreshForgotLink() {
  let has = false;
  try {
    has = await invoke('vault_has_recovery');
  } catch {
    has = false;
  }
  document.querySelector('#forgot-link').hidden = !has;
}

let inDecoy = false;

function discreetEnabled() {
  return localStorage.getItem('discreet.on') === '1';
}

function discreetHash() {
  return localStorage.getItem('discreet.hash') || '';
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function currentLevelAttr() {
  return document.documentElement.getAttribute('data-level') || 'normal';
}

async function enterDecoy() {
  inDecoy = true;
  clearIdleTimer();
  document.querySelector('.app').classList.add('is-decoy');
  document.querySelector('#titlebar-name').textContent = t('decoy.appName');
  for (const el of Object.values(screens)) {
    el.hidden = true;
  }
  document.querySelector('#settings-modal').hidden = true;
  const decoy = document.querySelector('#decoy');
  decoy.hidden = false;
  const ta = document.querySelector('#decoy-text');
  ta.value = localStorage.getItem('decoy.notes') || '';
  await invoke('set_disguise', {
    on: true,
    title: t('decoy.appName'),
    level: currentLevelAttr(),
    theme: currentTheme()
  }).catch(() => {});
  invoke('update_tray_labels', { show: t('decoy.trayShow'), quit: t('tray.quit') }).catch(() => {});
  ta.focus();
}

async function exitDecoy() {
  inDecoy = false;
  document.querySelector('.app').classList.remove('is-decoy');
  document.querySelector('#titlebar-name').textContent = 'gestio';
  document.querySelector('#decoy').hidden = true;
  await invoke('set_disguise', {
    on: false,
    title: 'Gestio',
    level: currentLevelAttr(),
    theme: currentTheme()
  }).catch(() => {});
  updateTrayLabels();
  await route();
  if (updatesEnabled()) {
    setTimeout(() => checkForUpdates(false), 2500);
  }
}

async function onDecoyInput() {
  const ta = document.querySelector('#decoy-text');
  localStorage.setItem('decoy.notes', ta.value);
  const target = discreetHash();
  if (!target) {
    return;
  }
  const lines = ta.value.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const candidate = lines[i].trim();
    if (!candidate) {
      continue;
    }
    const h = await sha256Hex(candidate);
    if (h === target) {
      lines.splice(i, 1);
      ta.value = lines.join('\n');
      localStorage.setItem('decoy.notes', ta.value);
      await exitDecoy();
      return;
    }
  }
}

async function switchSpace(space) {
  currentSpace = space;
  document.querySelector('#tab-passwords').classList.toggle('is-active', space === 'passwords');
  document.querySelector('#tab-totp').classList.toggle('is-active', space === 'totp');
  stopTotpTimer();
  if (space === 'totp') {
    await routeTotp();
  } else {
    await route();
  }
}

async function routeTotp() {
  if (await invoke('totp_is_unlocked')) {
    await renderTotp();
    show('totp');
    startTotpTimer();
  } else if (await invoke('totp_exists')) {
    await refreshTotpForgotLink();
    show('totpUnlock');
    document.querySelector('#totp-unlock-pw').focus();
  } else {
    show('totpCreate');
    document.querySelector('#totp-create-pw').focus();
  }
}

async function refreshTotpForgotLink() {
  let has = false;
  try {
    has = await invoke('totp_has_recovery');
  } catch {
    has = false;
  }
  document.querySelector('#totp-forgot-link').hidden = !has;
}

async function createTotpVault() {
  const errEl = document.querySelector('#totp-create-err');
  const pw = document.querySelector('#totp-create-pw');
  const pw2 = document.querySelector('#totp-create-pw2');
  errEl.textContent = '';
  if (pw.value.length < 8) {
    errEl.textContent = t('val.min8');
    return;
  }
  if (pw.value !== pw2.value) {
    errEl.textContent = t('val.mismatch');
    return;
  }
  const withRecovery = document.querySelector('#totp-create-recovery').checked;
  await withButton(document.querySelector('#totp-create-btn'), t('load.creating'), async () => {
    try {
      const code = await invoke('create_totp', { masterPassword: pw.value, withRecovery });
      pw.value = '';
      pw2.value = '';
      document.querySelector('#totp-create-recovery').checked = false;
      const enter = async () => {
        await renderTotp();
        show('totp');
        startTotpTimer();
      };
      if (code) {
        markRecoveryRotated('totp');
        showRecoveryCode(code, enter);
      } else {
        await enter();
      }
    } catch (e) {
      errEl.textContent = errText(e);
    }
  });
}

async function unlockTotpVault() {
  const errEl = document.querySelector('#totp-unlock-err');
  const pw = document.querySelector('#totp-unlock-pw');
  errEl.textContent = '';
  await withButton(document.querySelector('#totp-unlock-btn'), t('load.unlocking'), async () => {
    try {
      await invoke('unlock_totp', { masterPassword: pw.value });
      pw.value = '';
      await renderTotp();
      show('totp');
      startTotpTimer();
      checkRecoveryRotation('totp');
    } catch (e) {
      pw.value = '';
      errEl.textContent = errText(e);
    }
  });
}

async function lockTotp() {
  stopTotpTimer();
  closeTotpModal();
  await invoke('lock_totp');
  await refreshTotpForgotLink();
  show('totpUnlock');
  document.querySelector('#totp-unlock-pw').focus();
}

function formatCode(code) {
  return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
}

function buildTotpRow(entry) {
  const li = document.createElement('li');
  li.className = 'totp';
  li.dataset.id = entry.id;

  const ringWrap = document.createElement('span');
  ringWrap.innerHTML = TOTP_RING;
  const ring = ringWrap.firstElementChild;
  ring.querySelector('.totp__ring-fg').dataset.ring = entry.id;

  const main = document.createElement('div');
  main.className = 'totp__main';
  const label = document.createElement('div');
  label.className = 'totp__label';
  label.textContent = entry.label || t('detail.noName');
  main.appendChild(label);
  if (entry.issuer) {
    const issuer = document.createElement('div');
    issuer.className = 'totp__issuer';
    issuer.textContent = entry.issuer;
    main.appendChild(issuer);
  }

  const code = document.createElement('div');
  code.className = 'totp__code';
  code.dataset.codeId = entry.id;
  code.textContent = '••• •••';

  const actions = document.createElement('div');
  actions.className = 'totp__actions';
  const copy = document.createElement('button');
  copy.className = 'totp__copy';
  copy.dataset.action = 'copy-totp';
  copy.setAttribute('aria-label', 'Copier le code');
  copy.innerHTML = ICON_COPY;
  const del = document.createElement('button');
  del.className = 'totp__del';
  del.dataset.action = 'del-totp';
  del.setAttribute('aria-label', t('btn.delete'));
  del.innerHTML = ICON_TRASH;
  actions.append(copy, del);

  li.append(ring, main, code, actions);
  return li;
}

async function renderTotp() {
  document.querySelector('#totp-err').textContent = '';
  totpEntries = await invoke('list_totp');
  const list = document.querySelector('#totp-list');
  const empty = document.querySelector('#totp-empty');
  list.textContent = '';
  if (totpEntries.length === 0) {
    empty.hidden = false;
  } else {
    empty.hidden = true;
    for (const entry of totpEntries) {
      list.appendChild(buildTotpRow(entry));
    }
  }
  await updateTotpCodes();
}

async function updateTotpCodes() {
  let codes;
  try {
    codes = await invoke('totp_codes');
  } catch (e) {
    return;
  }
  for (const c of codes) {
    const codeEl = document.querySelector(`[data-code-id="${c.id}"]`);
    if (codeEl) {
      codeEl.textContent = formatCode(c.code);
    }
    const ring = document.querySelector(`[data-ring="${c.id}"]`);
    if (ring) {
      ring.dataset.period = String(c.period);
    }
  }
}

function animateRings() {
  const circumference = 2 * Math.PI * 9;
  const nowSec = Date.now() / 1000;
  document.querySelectorAll('.totp__ring-fg').forEach((ring) => {
    const period = Number(ring.dataset.period) || 30;
    const remaining = period - (nowSec % period);
    ring.style.strokeDasharray = String(circumference);
    ring.style.strokeDashoffset = String(circumference * (1 - remaining / period));
    ring.style.stroke = remaining <= 5 ? 'var(--danger)' : 'var(--accent)';
  });
  totpRaf = requestAnimationFrame(animateRings);
}

function startTotpTimer() {
  stopTotpTimer();
  updateTotpCodes();
  totpTimer = setInterval(updateTotpCodes, 1000);
  animateRings();
}

function stopTotpTimer() {
  if (totpTimer !== null) {
    clearInterval(totpTimer);
    totpTimer = null;
  }
  if (totpRaf !== null) {
    cancelAnimationFrame(totpRaf);
    totpRaf = null;
  }
}

async function onTotpListClick(e) {
  const btn = e.target.closest('[data-action]');
  if (!btn) {
    return;
  }
  const li = btn.closest('.totp');
  const id = li.dataset.id;
  const action = btn.dataset.action;
  if (action === 'copy-totp') {
    await copyTotpCode(id, btn);
  } else if (action === 'del-totp') {
    const actions = btn.closest('.totp__actions');
    actions.textContent = '';
    const yes = document.createElement('button');
    yes.className = 'totp__confirm';
    yes.dataset.action = 'confirm-del-totp';
    yes.textContent = t('btn.delete');
    const no = document.createElement('button');
    no.className = 'totp__cancel';
    no.dataset.action = 'cancel-del-totp';
    no.textContent = t('btn.cancel');
    actions.append(yes, no);
  } else if (action === 'confirm-del-totp') {
    try {
      await invoke('delete_totp', { id });
    } catch (err) {
      document.querySelector('#totp-err').textContent = errText(err);
    }
    await renderTotp();
  } else if (action === 'cancel-del-totp') {
    await renderTotp();
  }
}

async function copyTotpCode(id, btn) {
  const el = document.querySelector(`[data-code-id="${id}"]`);
  const code = el ? el.textContent.replace(/\s/g, '') : '';
  if (!code || code.includes('•')) {
    return;
  }
  document.querySelector('#totp-err').textContent = '';
  try {
    await invoke('copy_text', { text: code });
    const original = btn.innerHTML;
    btn.innerHTML = ICON_CHECK;
    setTimeout(() => {
      if (btn.isConnected) {
        btn.innerHTML = original;
      }
    }, 1500);
  } catch (e) {
    document.querySelector('#totp-err').textContent = errText(e);
  }
}

function openTotpModal() {
  document.querySelector('#t-label').value = '';
  document.querySelector('#t-issuer').value = '';
  document.querySelector('#t-secret').value = '';
  document.querySelector('#totp-modal-err').textContent = '';
  document.querySelector('#totp-modal').hidden = false;
  document.querySelector('#t-label').focus();
}

function closeTotpModal() {
  document.querySelector('#totp-modal').hidden = true;
  document.querySelector('#t-label').value = '';
  document.querySelector('#t-issuer').value = '';
  document.querySelector('#t-secret').value = '';
}

async function submitTotp(e) {
  e.preventDefault();
  const errEl = document.querySelector('#totp-modal-err');
  errEl.textContent = '';
  let label = document.querySelector('#t-label').value.trim();
  let issuer = document.querySelector('#t-issuer').value.trim();
  let secret = document.querySelector('#t-secret').value.trim();
  let digits = 6;
  let period = 30;
  if (secret.toLowerCase().startsWith('otpauth://')) {
    try {
      const url = new URL(secret);
      const s = url.searchParams.get('secret');
      if (s) {
        secret = s;
      }
      const iss = url.searchParams.get('issuer');
      const d = url.searchParams.get('digits');
      const p = url.searchParams.get('period');
      if (d && !Number.isNaN(Number(d))) {
        digits = Math.min(8, Math.max(6, Math.round(Number(d))));
      }
      if (p && !Number.isNaN(Number(p))) {
        period = Math.min(300, Math.max(5, Math.round(Number(p))));
      }
      const path = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
      if (!label) {
        label = path.includes(':') ? path.split(':').slice(1).join(':') : path;
      }
      if (!issuer) {
        issuer = iss || (path.includes(':') ? path.split(':')[0] : '');
      }
    } catch (err) {
      errEl.textContent = t('val.otpauthInvalid');
      return;
    }
  }
  if (!label) {
    errEl.textContent = t('val.nameRequired');
    return;
  }
  if (!secret) {
    errEl.textContent = t('val.secretRequired');
    return;
  }
  try {
    await invoke('add_totp', { input: { label, issuer, secret, digits, period } });
    closeTotpModal();
    await renderTotp();
  } catch (err) {
    errEl.textContent = errText(err);
  }
}

async function withButton(btn, label, task) {
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = label;
  try {
    await task();
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

async function createVault() {
  const errEl = document.querySelector('#create-err');
  const pwEl = document.querySelector('#create-pw');
  const pw2El = document.querySelector('#create-pw2');
  errEl.textContent = '';
  if (pwEl.value.length < 8) {
    errEl.textContent = t('val.min8');
    return;
  }
  if (pwEl.value !== pw2El.value) {
    errEl.textContent = t('val.mismatch');
    return;
  }
  const withRecovery = document.querySelector('#create-recovery').checked;
  await withButton(document.querySelector('#create-btn'), t('load.creating'), async () => {
    try {
      const code = await invoke('create_vault', {
        masterPassword: pwEl.value,
        level: selectedLevel,
        withRecovery
      });
      pwEl.value = '';
      pw2El.value = '';
      document.querySelector('#create-recovery').checked = false;
      const enter = async () => {
        await renderVault();
        show('vault');
      };
      if (code) {
        markRecoveryRotated('vault');
        showRecoveryCode(code, enter);
      } else {
        await enter();
      }
    } catch (e) {
      errEl.textContent = errText(e);
    }
  });
}

function formatRecovery(code) {
  return code;
}

function showRecoveryCode(code, onDone) {
  const modal = document.querySelector('#recovery-modal');
  const codeEl = document.querySelector('#recovery-code');
  const copyBtn = document.querySelector('#recovery-copy');
  const doneBtn = document.querySelector('#recovery-done');
  codeEl.textContent = formatRecovery(code);
  copyBtn.textContent = t('recovery.copy');
  const onCopy = async () => {
    try {
      await invoke('copy_text', { text: code });
      copyBtn.textContent = t('recovery.copied');
    } catch (e) {
      copyBtn.textContent = errText(e);
    }
  };
  const onDoneClick = async () => {
    cleanup();
    modal.hidden = true;
    if (onDone) {
      await onDone();
    }
  };
  function cleanup() {
    copyBtn.removeEventListener('click', onCopy);
    doneBtn.removeEventListener('click', onDoneClick);
  }
  copyBtn.addEventListener('click', onCopy);
  doneBtn.addEventListener('click', onDoneClick);
  modal.hidden = false;
}

async function unlockVault() {
  const errEl = document.querySelector('#unlock-err');
  const pwEl = document.querySelector('#unlock-pw');
  errEl.textContent = '';
  await withButton(document.querySelector('#unlock-btn'), t('load.unlocking'), async () => {
    try {
      await invoke('unlock_vault', { masterPassword: pwEl.value });
      pwEl.value = '';
      await renderVault();
      show('vault');
      checkRecoveryRotation('vault');
    } catch (e) {
      pwEl.value = '';
      errEl.textContent = errText(e);
    }
  });
}

function openRecoverModal(target) {
  recoverTarget = target === 'totp' ? 'totp' : 'vault';
  document.querySelector('#recover-modal-title').textContent =
    recoverTarget === 'totp' ? t('recover.titleTotp') : t('recover.title');
  document.querySelector('#recover-err').textContent = '';
  document.querySelector('#recover-code').value = '';
  document.querySelector('#recover-new').value = '';
  document.querySelector('#recover-new2').value = '';
  document.querySelector('#recover-modal').hidden = false;
  document.querySelector('#recover-code').focus();
}

function closeRecoverModal() {
  document.querySelector('#recover-modal').hidden = true;
  document.querySelector('#recover-code').value = '';
  document.querySelector('#recover-new').value = '';
  document.querySelector('#recover-new2').value = '';
}

async function submitRecover(e) {
  e.preventDefault();
  const errEl = document.querySelector('#recover-err');
  const codeEl = document.querySelector('#recover-code');
  const nw = document.querySelector('#recover-new');
  const nw2 = document.querySelector('#recover-new2');
  errEl.textContent = '';
  if (!codeEl.value.trim()) {
    errEl.textContent = t('e.noRecovery');
    return;
  }
  if (nw.value.length < 8) {
    errEl.textContent = t('val.min8');
    return;
  }
  if (nw.value !== nw2.value) {
    errEl.textContent = t('val.mismatch');
    return;
  }
  const cfg = RECOVERY_TARGETS[recoverTarget];
  await withButton(document.querySelector('#recover-form button[type="submit"]'), t('load.recovering'), async () => {
    try {
      await invoke(cfg.unlockRecCmd, { recovery: codeEl.value });
      await invoke(cfg.resetPwCmd, { new: nw.value });
      closeRecoverModal();
      if (recoverTarget === 'totp') {
        await switchSpace('totp');
      } else {
        await renderVault();
        show('vault');
      }
    } catch (err) {
      errEl.textContent = errText(err);
    }
  });
}

async function lockVault() {
  closeModal();
  closeGroupModal();
  closeLevelModal();
  closeAllMenus();
  selectedEntryId = null;
  detailRevealed = false;
  detailPassword = null;
  setPwnedIndicator('none');
  await invoke('lock_vault');
  await refreshLevel();
  await refreshForgotLink();
  if (discreetEnabled()) {
    await enterDecoy();
  } else {
    show('unlock');
  }
}

async function renderVault() {
  await refreshLevel();
  groups = await invoke('list_groups');
  favGroups = await invoke('list_group_favorites');
  entries = await invoke('list_entries');
  drawEntries();
  renderDetail();
}

function matches(entry, query) {
  if (!query) {
    return true;
  }
  const q = query.toLowerCase();
  return entry.name.toLowerCase().includes(q) || entry.username.toLowerCase().includes(q);
}

function buildEntryRow(entry) {
  const li = document.createElement('li');
  li.className = 'entry';
  if (entry.id === selectedEntryId) {
    li.classList.add('is-selected');
  }
  li.dataset.action = 'select';
  li.dataset.id = entry.id;
  li.draggable = filterText.trim() === '';
  const name = document.createElement('span');
  name.className = 'entry__name';
  name.textContent = entry.name;

  const actions = document.createElement('div');
  actions.className = 'entry__actions';
  const menuBtn = document.createElement('button');
  menuBtn.className = 'entry__menu-btn';
  menuBtn.dataset.action = 'entry-menu';
  menuBtn.dataset.id = entry.id;
  menuBtn.setAttribute('aria-label', 'Actions');
  menuBtn.innerHTML = ICON_DOTS;
  const menu = document.createElement('div');
  menu.className = 'menu';
  menu.hidden = true;
  actions.append(menuBtn, menu);

  if (entry.favorite) {
    const star = document.createElement('span');
    star.className = 'entry__star';
    star.innerHTML = ICON_STAR;
    li.append(star, name, actions);
  } else {
    li.append(name, actions);
  }
  return li;
}

function entryMenuItem(label, action, id, danger) {
  const b = document.createElement('button');
  b.textContent = label;
  b.dataset.action = action;
  b.dataset.id = id;
  if (danger) {
    b.classList.add('danger');
  }
  return b;
}

function toggleEntryMenu(btn) {
  const id = btn.dataset.id;
  const menu = btn.closest('.entry__actions').querySelector('.menu');
  const willOpen = menu.hidden;
  closeAllMenus();
  if (willOpen) {
    menu.textContent = '';
    menu.append(
      entryMenuItem(t('btn.edit'), 'edit-entry-row', id),
      entryMenuItem(t('btn.delete'), 'delete-entry-row', id, true)
    );
    menu.hidden = false;
    positionMenu(menu, btn);
  }
}

async function startEditEntry(id) {
  const entry = entries.find((e) => e.id === id);
  if (!entry) {
    return;
  }
  let password = '';
  try {
    password = await invoke('reveal_password', { id });
  } catch (e) {
    password = '';
  }
  openModal(entry, password);
}

async function deleteEntryById(id) {
  document.querySelector('#vault-err').textContent = '';
  try {
    await invoke('delete_entry', { id });
  } catch (e) {
    document.querySelector('#vault-err').textContent = errText(e);
  }
  if (selectedEntryId === id) {
    selectedEntryId = null;
    detailRevealed = false;
    detailPassword = null;
  }
  setPwnedIndicator('none');
  await renderVault();
}

function clearDropIndicators() {
  document.querySelectorAll('.drop-before, .drop-into').forEach((el) => {
    el.classList.remove('drop-before', 'drop-into');
  });
}

async function handleEntryDrop(id, target) {
  if (!id) {
    return;
  }
  if (target && target.classList.contains('entry') && target.dataset.id === id) {
    return;
  }
  const arr = entries.map((e) => ({ id: e.id, group: e.group }));
  const fromIdx = arr.findIndex((x) => x.id === id);
  if (fromIdx < 0) {
    return;
  }
  const moved = arr.splice(fromIdx, 1)[0];
  if (target && target.classList.contains('entry')) {
    const tIdx = arr.findIndex((x) => x.id === target.dataset.id);
    moved.group = tIdx >= 0 ? arr[tIdx].group : '';
    arr.splice(tIdx < 0 ? arr.length : tIdx, 0, moved);
  } else if (target && target.classList.contains('group')) {
    moved.group = target.dataset.group;
    let insertAt = arr.length;
    for (let i = arr.length - 1; i >= 0; i -= 1) {
      if (arr[i].group === moved.group) {
        insertAt = i + 1;
        break;
      }
    }
    arr.splice(insertAt, 0, moved);
  } else {
    moved.group = '';
    let insertAt = 0;
    for (let i = 0; i < arr.length; i += 1) {
      if (arr[i].group === '') {
        insertAt = i + 1;
      }
    }
    arr.splice(insertAt, 0, moved);
  }
  try {
    await invoke('reorder_entries', { order: arr });
  } catch (e) {
    document.querySelector('#vault-err').textContent = errText(e);
  }
  await renderVault();
}

async function handleGroupDrop(name, target) {
  if (!name) {
    return;
  }
  const order = groups.slice();
  const from = order.indexOf(name);
  if (from < 0) {
    return;
  }
  order.splice(from, 1);
  let insertAt = order.length;
  if (target && target.classList.contains('group')) {
    if (target.dataset.group === name) {
      return;
    }
    const tIdx = order.indexOf(target.dataset.group);
    insertAt = tIdx < 0 ? order.length : tIdx;
  } else if (target && target.classList.contains('entry')) {
    const entry = entries.find((x) => x.id === target.dataset.id);
    if (entry && entry.group) {
      const tIdx = order.indexOf(entry.group);
      insertAt = tIdx < 0 ? order.length : tIdx;
    }
  }
  order.splice(insertAt, 0, name);
  try {
    await invoke('reorder_groups', { order });
  } catch (e) {
    document.querySelector('#vault-err').textContent = errText(e);
  }
  await renderVault();
}

function buildGroupHeader(name, count, collapsed) {
  const li = document.createElement('li');
  li.className = 'group';
  if (collapsed) {
    li.classList.add('is-collapsed');
  }
  li.dataset.group = name;
  li.draggable = filterText.trim() === '';

  const toggle = document.createElement('button');
  toggle.className = 'group__toggle';
  toggle.dataset.action = 'toggle-group';
  toggle.dataset.group = name;
  toggle.innerHTML = ICON_CARET;
  const nameEl = document.createElement('span');
  nameEl.className = 'group__name';
  nameEl.textContent = name;
  const countEl = document.createElement('span');
  countEl.className = 'group__count';
  countEl.textContent = count;
  if (favGroups.includes(name)) {
    const star = document.createElement('span');
    star.className = 'group__star';
    star.innerHTML = ICON_STAR;
    toggle.append(star);
  }
  toggle.append(nameEl, countEl);

  const actions = document.createElement('div');
  actions.className = 'group__actions';
  const menuBtn = document.createElement('button');
  menuBtn.className = 'group__menu-btn';
  menuBtn.dataset.action = 'group-menu';
  menuBtn.dataset.group = name;
  menuBtn.setAttribute('aria-label', 'Actions du groupe');
  menuBtn.innerHTML = ICON_DOTS;
  const menu = document.createElement('div');
  menu.className = 'menu';
  menu.hidden = true;
  actions.append(menuBtn, menu);

  li.append(toggle, actions);
  return li;
}

function buildFavHeader(count) {
  const li = document.createElement('li');
  li.className = 'group group--fav';
  const label = document.createElement('div');
  label.className = 'group__toggle group__toggle--static';
  const star = document.createElement('span');
  star.className = 'group__star';
  star.innerHTML = ICON_STAR;
  const nameEl = document.createElement('span');
  nameEl.className = 'group__name';
  nameEl.textContent = t('fav.title');
  const countEl = document.createElement('span');
  countEl.className = 'group__count';
  countEl.textContent = count;
  label.append(star, nameEl, countEl);
  li.appendChild(label);
  return li;
}

function drawEntries() {
  document.querySelector('#vault-err').textContent = '';
  const list = document.querySelector('#entry-list');
  const empty = document.querySelector('#vault-empty');
  list.textContent = '';
  const searching = filterText.trim() !== '';
  const shown = entries.filter((e) => matches(e, filterText));

  if (!searching) {
    const favs = shown.filter((e) => e.favorite);
    if (favs.length > 0) {
      list.appendChild(buildFavHeader(favs.length));
      for (const entry of favs) {
        const row = buildEntryRow(entry);
        row.classList.add('entry--grouped');
        list.appendChild(row);
      }
    }
  }

  const pool = searching ? shown : shown.filter((e) => !e.favorite);

  for (const entry of pool.filter((e) => !e.group)) {
    list.appendChild(buildEntryRow(entry));
  }

  const orderedGroups = searching
    ? groups
    : [...groups.filter((g) => favGroups.includes(g)), ...groups.filter((g) => !favGroups.includes(g))];

  for (const name of orderedGroups) {
    const members = pool.filter((e) => e.group === name);
    if (searching && members.length === 0) {
      continue;
    }
    const collapsed = !searching && collapsedGroups.has(name);
    list.appendChild(buildGroupHeader(name, members.length, collapsed));
    if (!collapsed) {
      for (const entry of members) {
        const row = buildEntryRow(entry);
        row.classList.add('entry--grouped');
        list.appendChild(row);
      }
    }
  }

  empty.hidden = list.children.length !== 0;
}

function groupMenuItem(label, action, group, danger) {
  const b = document.createElement('button');
  b.textContent = label;
  b.dataset.action = action;
  b.dataset.group = group;
  if (danger) {
    b.classList.add('danger');
  }
  return b;
}

function closeAllMenus() {
  document.querySelectorAll('.menu').forEach((m) => {
    m.hidden = true;
  });
}

function positionMenu(menu, btn) {
  const r = btn.getBoundingClientRect();
  const mh = menu.offsetHeight;
  const mw = menu.offsetWidth;
  let top = r.bottom + 4;
  if (top + mh > window.innerHeight - 8) {
    top = r.top - mh - 4;
  }
  if (top < 8) {
    top = 8;
  }
  let left = r.right - mw;
  if (left < 8) {
    left = 8;
  }
  menu.style.top = `${top}px`;
  menu.style.left = `${left}px`;
}

function toggleGroup(name) {
  if (collapsedGroups.has(name)) {
    collapsedGroups.delete(name);
  } else {
    collapsedGroups.add(name);
  }
  saveCollapsed();
  drawEntries();
}

function toggleGroupMenu(btn) {
  const group = btn.dataset.group;
  const menu = btn.closest('.group__actions').querySelector('.menu');
  const willOpen = menu.hidden;
  closeAllMenus();
  if (willOpen) {
    menu.textContent = '';
    const favLabel = favGroups.includes(group) ? t('group.unpin') : t('group.pin');
    menu.append(
      groupMenuItem(favLabel, 'toggle-group-fav', group),
      groupMenuItem(t('btn.rename'), 'rename-group', group),
      groupMenuItem(t('btn.delete'), 'delete-group', group, true)
    );
    menu.hidden = false;
    positionMenu(menu, btn);
  }
}

async function toggleGroupFavorite(group) {
  try {
    const now = await invoke('toggle_group_favorite', { name: group });
    if (now) {
      if (!favGroups.includes(group)) {
        favGroups.push(group);
      }
    } else {
      favGroups = favGroups.filter((g) => g !== group);
    }
    drawEntries();
  } catch (e) {
    document.querySelector('#vault-err').textContent = errText(e);
  }
}

async function onListClick(e) {
  const btn = e.target.closest('[data-action]');
  if (!btn) {
    return;
  }
  const action = btn.dataset.action;
  if (action === 'select') {
    selectEntry(btn.dataset.id);
  } else if (action === 'entry-menu') {
    toggleEntryMenu(btn);
  } else if (action === 'edit-entry-row') {
    closeAllMenus();
    await startEditEntry(btn.dataset.id);
  } else if (action === 'delete-entry-row') {
    const menu = btn.closest('.menu');
    menu.textContent = '';
    menu.append(
      entryMenuItem(t('btn.confirm'), 'confirm-del-row', btn.dataset.id, true),
      entryMenuItem(t('btn.cancel'), 'cancel-del-row', btn.dataset.id)
    );
  } else if (action === 'confirm-del-row') {
    closeAllMenus();
    await deleteEntryById(btn.dataset.id);
  } else if (action === 'cancel-del-row') {
    closeAllMenus();
  } else if (action === 'toggle-group') {
    toggleGroup(btn.dataset.group);
  } else if (action === 'group-menu') {
    toggleGroupMenu(btn);
  } else if (action === 'toggle-group-fav') {
    closeAllMenus();
    await toggleGroupFavorite(btn.dataset.group);
  } else if (action === 'rename-group') {
    closeAllMenus();
    openGroupModal(btn.dataset.group);
  } else if (action === 'delete-group') {
    const menu = btn.closest('.menu');
    menu.textContent = '';
    menu.append(
      groupMenuItem(t('btn.delete'), 'confirm-del-group', btn.dataset.group, true),
      groupMenuItem(t('btn.cancel'), 'cancel-del-group', btn.dataset.group)
    );
  } else if (action === 'confirm-del-group') {
    closeAllMenus();
    await doDeleteGroup(btn.dataset.group);
  } else if (action === 'cancel-del-group') {
    closeAllMenus();
  }
}

async function selectEntry(id) {
  document.querySelector('#detail-edit').hidden = true;
  document.querySelector('#detail').hidden = false;
  editingId = null;
  selectedEntryId = id;
  detailRevealed = false;
  detailPassword = null;
  revealedFields = new Set();
  drawEntries();
  renderDetail();
  await loadDetailSecret();
}

async function loadDetailSecret() {
  const id = selectedEntryId;
  if (!id) {
    return;
  }
  try {
    detailPassword = await invoke('reveal_password', { id });
  } catch (e) {
    detailPassword = null;
  }
  if (selectedEntryId === id) {
    renderDetail();
  }
}

function detailMenuItem(label, action, danger) {
  const b = document.createElement('button');
  b.textContent = label;
  b.dataset.action = action;
  if (danger) {
    b.classList.add('danger');
  }
  return b;
}

function toggleDetailMenu(btn) {
  const menu = btn.closest('.detail__actions').querySelector('.menu');
  const willOpen = menu.hidden;
  closeAllMenus();
  if (willOpen) {
    menu.textContent = '';
    menu.append(detailMenuItem(t('btn.edit'), 'edit-entry'), detailMenuItem(t('btn.delete'), 'delete-entry', true));
    menu.hidden = false;
    positionMenu(menu, btn);
  }
}

function detailField(label, valueNode) {
  const row = document.createElement('div');
  row.className = 'detail__field';
  const lab = document.createElement('span');
  lab.className = 'detail__label';
  lab.textContent = label;
  row.append(lab, valueNode);
  return row;
}

function detailIcon(action, svg, label) {
  const b = document.createElement('button');
  b.className = 'detail__ico';
  b.dataset.action = action;
  b.setAttribute('aria-label', label);
  b.innerHTML = svg;
  return b;
}

function identBlock(username) {
  const wrap = document.createElement('div');
  wrap.className = 'detail__copyrow';
  const val = document.createElement('span');
  val.className = 'detail__ident';
  val.textContent = username;
  wrap.append(val, detailIcon('copy-username', ICON_COPY, "Copier l'identifiant"));
  return wrap;
}

function passwordBlock() {
  const wrap = document.createElement('div');
  wrap.className = 'detail__pw';
  const val = document.createElement('span');
  val.className = 'detail__pw-val';
  val.textContent = detailRevealed && detailPassword !== null ? detailPassword : DOTS;
  wrap.append(
    val,
    detailIcon('reveal', detailRevealed ? ICON_EYE_OFF : ICON_EYE, 'Afficher ou masquer'),
    detailIcon('copy', ICON_COPY, 'Copier')
  );
  return wrap;
}

function fieldValueBlock(field, index) {
  const wrap = document.createElement('div');
  wrap.className = 'detail__pw';
  const val = document.createElement('span');
  val.className = 'detail__pw-val';
  val.textContent = field.secret && !revealedFields.has(index) ? DOTS : field.value;
  wrap.appendChild(val);
  if (field.secret) {
    const eye = detailIcon('reveal-field', revealedFields.has(index) ? ICON_EYE_OFF : ICON_EYE, t('entry.fieldSecret'));
    eye.dataset.i = String(index);
    wrap.appendChild(eye);
  }
  const copyBtn = detailIcon('copy-field', ICON_COPY, t('btn.copy'));
  copyBtn.dataset.i = String(index);
  wrap.appendChild(copyBtn);
  return wrap;
}

async function copyFieldValue(index, btn) {
  const entry = entries.find((e) => e.id === selectedEntryId);
  if (!entry || !Array.isArray(entry.fields) || !entry.fields[index]) {
    return;
  }
  const field = entry.fields[index];
  document.querySelector('#vault-err').textContent = '';
  try {
    await invoke('copy_text', { text: field.value });
    const original = btn.innerHTML;
    btn.innerHTML = ICON_CHECK;
    setTimeout(() => {
      if (btn.isConnected) {
        btn.innerHTML = original;
      }
    }, 1500);
    if (field.secret) {
      setTimeout(() => {
        invoke('clear_clipboard').catch(() => {});
      }, 20000);
    }
  } catch (e) {
    document.querySelector('#vault-err').textContent = errText(e);
  }
}

function renderDetail() {
  const el = document.querySelector('#detail');
  el.textContent = '';
  const entry = entries.find((e) => e.id === selectedEntryId);
  if (!entry) {
    const ph = document.createElement('div');
    ph.className = 'detail__placeholder';
    ph.textContent = entries.length ? t('detail.select') : '';
    el.appendChild(ph);
    return;
  }

  const head = document.createElement('div');
  head.className = 'detail__head';
  const headText = document.createElement('div');
  const name = document.createElement('h2');
  name.className = 'detail__name';
  name.textContent = entry.name;
  headText.appendChild(name);
  if (entry.url) {
    const url = document.createElement('div');
    url.className = 'detail__url';
    url.textContent = entry.url;
    headText.appendChild(url);
  }
  const actions = document.createElement('div');
  actions.className = 'detail__actions';
  const favBtn = document.createElement('button');
  favBtn.className = 'detail__fav' + (entry.favorite ? ' is-on' : '');
  favBtn.dataset.action = 'toggle-fav';
  const favLabel = entry.favorite ? t('title.unfavorite') : t('title.favorite');
  favBtn.setAttribute('aria-label', favLabel);
  favBtn.title = favLabel;
  favBtn.innerHTML = ICON_STAR;
  const menuBtn = document.createElement('button');
  menuBtn.className = 'detail__menu-btn';
  menuBtn.dataset.action = 'detail-menu';
  menuBtn.setAttribute('aria-label', 'Actions');
  menuBtn.innerHTML = ICON_DOTS;
  const menu = document.createElement('div');
  menu.className = 'menu';
  menu.hidden = true;
  actions.append(favBtn, menuBtn, menu);
  head.append(headText, actions);
  el.appendChild(head);

  const rule = document.createElement('hr');
  rule.className = 'detail__rule';
  el.appendChild(rule);

  if (entry.username) {
    el.appendChild(detailField(t('detail.identifiant'), identBlock(entry.username)));
  }

  if (entry.kind !== 'note') {
    el.appendChild(detailField(t('detail.password'), passwordBlock()));
    if (typeof detailPassword === 'string' && detailPassword.length > 0) {
      el.appendChild(detailField(t('detail.strength'), strengthValue(detailPassword)));
    }
  }

  if (entry.note) {
    const note = document.createElement('span');
    note.className = 'detail__pw-val detail__note-val';
    note.textContent = entry.note;
    el.appendChild(detailField(t('detail.note'), note));
  }

  if (Array.isArray(entry.fields)) {
    entry.fields.forEach((f, i) => {
      if (!f.label && !f.value) {
        return;
      }
      el.appendChild(detailField(f.label || '-', fieldValueBlock(f, i)));
    });
  }

  const meta = document.createElement('div');
  meta.className = 'detail__meta';
  const rel = relativeTime(entry.modified);
  meta.textContent = t('detail.lastChange', { v: rel || t('detail.unknown') });
  el.appendChild(meta);

  if (isEntryPwOld(entry)) {
    const warn = document.createElement('div');
    warn.className = 'detail__oldwarn';
    warn.textContent = t('detail.pwOld');
    el.appendChild(warn);
  }

  if (typeof detailPassword === 'string' && detailPassword.length > 0) {
    const leak = document.createElement('div');
    leak.className = 'detail__leak';
    const leakBtn = document.createElement('button');
    leakBtn.className = 'btn btn--ghost btn--sm';
    leakBtn.dataset.action = 'check-pwned';
    leakBtn.textContent = t('detail.checkLeaks');
    const leakRes = document.createElement('span');
    leakRes.className = 'detail__leak-result';
    leakRes.id = 'leak-result';
    leak.append(leakBtn, leakRes);
    el.appendChild(leak);
  }
}

function relativeTime(secs) {
  if (!secs) {
    return null;
  }
  let d = Math.floor(Date.now() / 1000) - secs;
  if (d < 0) {
    d = 0;
  }
  const mins = Math.floor(d / 60);
  const hours = Math.floor(d / 3600);
  const days = Math.floor(d / 86400);
  const months = Math.floor(days / 30);
  const years = Math.floor(days / 365);
  if (d < 60) {
    return t('time.now');
  }
  if (mins < 60) {
    return t('time.min', { n: mins });
  }
  if (hours < 24) {
    return t('time.hour', { n: hours });
  }
  if (days < 30) {
    return t('time.day', { n: days });
  }
  if (months < 12) {
    return t('time.month', { n: months });
  }
  return t(years === 1 ? 'time.yearOne' : 'time.yearMany', { n: years });
}

async function onDetailClick(e) {
  const btn = e.target.closest('[data-action]');
  if (!btn) {
    return;
  }
  const action = btn.dataset.action;
  if (action === 'reveal') {
    toggleDetailReveal();
  } else if (action === 'copy') {
    await copyDetail(btn);
  } else if (action === 'copy-username') {
    await copyUsername(btn);
  } else if (action === 'detail-menu') {
    toggleDetailMenu(btn);
  } else if (action === 'edit-entry') {
    closeAllMenus();
    await startEditDetail();
  } else if (action === 'delete-entry') {
    const menu = btn.closest('.menu');
    menu.textContent = '';
    menu.append(
      detailMenuItem(t('btn.confirm'), 'confirm-del-entry', true),
      detailMenuItem(t('btn.cancel'), 'cancel-del-entry')
    );
  } else if (action === 'confirm-del-entry') {
    closeAllMenus();
    await deleteDetail();
  } else if (action === 'cancel-del-entry') {
    closeAllMenus();
  } else if (action === 'check-pwned') {
    await checkPwned(btn);
  } else if (action === 'regen-detail') {
    await regenDetail(btn);
  } else if (action === 'toggle-fav') {
    await toggleFavorite();
  } else if (action === 'reveal-field') {
    const i = Number(btn.dataset.i);
    if (revealedFields.has(i)) {
      revealedFields.delete(i);
    } else {
      revealedFields.add(i);
    }
    renderDetail();
  } else if (action === 'copy-field') {
    await copyFieldValue(Number(btn.dataset.i), btn);
  }
}

async function toggleFavorite() {
  const id = selectedEntryId;
  if (!id) {
    return;
  }
  try {
    const now = await invoke('toggle_favorite', { id });
    const entry = entries.find((e) => e.id === id);
    if (entry) {
      entry.favorite = now;
    }
    drawEntries();
    renderDetail();
  } catch (e) {
    document.querySelector('#vault-err').textContent = errText(e);
  }
}

async function regenDetail(btn) {
  const id = selectedEntryId;
  if (!id) {
    return;
  }
  btn.disabled = true;
  btn.textContent = t('load.generating');
  try {
    detailPassword = await invoke('regenerate_password', { id });
    detailRevealed = true;
    setPwnedIndicator('none');
    await renderVault();
  } catch (e) {
    document.querySelector('#vault-err').textContent = errText(e);
  }
}

async function checkPwned(btn) {
  const result = document.querySelector('#leak-result');
  const staleRegen = result.closest('.detail__leak').querySelector('[data-action="regen-detail"]');
  if (staleRegen) {
    staleRegen.remove();
  }
  result.className = 'detail__leak-result';
  result.textContent = t('leak.checking');
  btn.disabled = true;
  try {
    const n = await invoke('check_pwned', { id: selectedEntryId });
    if (n > 0) {
      result.textContent = t(n === 1 ? 'leak.seenOne' : 'leak.seenMany', { n });
      result.classList.add('is-bad');
      const leak = result.closest('.detail__leak');
      if (leak && !leak.querySelector('[data-action="regen-detail"]')) {
        const regen = document.createElement('button');
        regen.className = 'btn btn--ghost btn--sm';
        regen.dataset.action = 'regen-detail';
        regen.textContent = t('detail.replaceGen');
        leak.appendChild(regen);
      }
    } else {
      result.textContent = t('leak.none');
      result.classList.add('is-good');
    }
  } catch (e) {
    result.textContent = errText(e);
    result.classList.add('is-bad');
  } finally {
    btn.disabled = false;
  }
}

function toggleDetailReveal() {
  detailRevealed = !detailRevealed;
  renderDetail();
}

async function copyDetail(btn) {
  document.querySelector('#vault-err').textContent = '';
  try {
    await invoke('copy_password', { id: selectedEntryId });
    const original = btn.innerHTML;
    btn.innerHTML = ICON_CHECK;
    setTimeout(() => {
      if (btn.isConnected) {
        btn.innerHTML = original;
      }
    }, 1500);
    setTimeout(() => {
      invoke('clear_clipboard').catch(() => {});
    }, 20000);
  } catch (e) {
    document.querySelector('#vault-err').textContent = errText(e);
  }
}

async function copyUsername(btn) {
  const entry = entries.find((e) => e.id === selectedEntryId);
  if (!entry) {
    return;
  }
  document.querySelector('#vault-err').textContent = '';
  try {
    await invoke('copy_text', { text: entry.username });
    const original = btn.innerHTML;
    btn.innerHTML = ICON_CHECK;
    setTimeout(() => {
      if (btn.isConnected) {
        btn.innerHTML = original;
      }
    }, 1500);
  } catch (e) {
    document.querySelector('#vault-err').textContent = errText(e);
  }
}

async function startEditDetail() {
  const entry = entries.find((e) => e.id === selectedEntryId);
  if (!entry) {
    return;
  }
  let password = detailPassword;
  if (password === null) {
    try {
      password = await invoke('reveal_password', { id: selectedEntryId });
    } catch (e) {
      password = '';
    }
  }
  openModal(entry, password);
}

async function deleteDetail() {
  const id = selectedEntryId;
  document.querySelector('#vault-err').textContent = '';
  try {
    await invoke('delete_entry', { id });
  } catch (e) {
    document.querySelector('#vault-err').textContent = errText(e);
  }
  selectedEntryId = null;
  detailRevealed = false;
  detailPassword = null;
  setPwnedIndicator('none');
  await renderVault();
}

function populateGroupSelect(selected) {
  const sel = document.querySelector('#f-group');
  sel.textContent = '';
  const none = document.createElement('option');
  none.value = '';
  none.textContent = t('group.none');
  sel.appendChild(none);
  for (const name of groups) {
    const opt = document.createElement('option');
    opt.value = name;
    opt.textContent = name;
    sel.appendChild(opt);
  }
  sel.value = selected || '';
}

function openGroupModal(existing) {
  renamingGroup = existing || null;
  document.querySelector('#group-modal-title').textContent = existing ? t('group.renameTitle') : t('group.newTitle');
  const nameEl = document.querySelector('#group-name');
  nameEl.value = existing || '';
  document.querySelector('#group-err').textContent = '';
  document.querySelector('#group-modal').hidden = false;
  nameEl.focus();
}

function closeGroupModal() {
  document.querySelector('#group-modal').hidden = true;
  document.querySelector('#group-name').value = '';
  renamingGroup = null;
}

async function submitGroup(e) {
  e.preventDefault();
  const errEl = document.querySelector('#group-err');
  const name = document.querySelector('#group-name').value.trim();
  errEl.textContent = '';
  if (!name) {
    errEl.textContent = t('val.groupRequired');
    return;
  }
  try {
    if (renamingGroup) {
      await invoke('rename_group', { from: renamingGroup, to: name });
      if (collapsedGroups.delete(renamingGroup)) {
        collapsedGroups.add(name);
        saveCollapsed();
      }
    } else {
      await invoke('create_group', { name });
    }
    closeGroupModal();
    await renderVault();
  } catch (err) {
    errEl.textContent = errText(err);
  }
}

async function doDeleteGroup(name) {
  document.querySelector('#vault-err').textContent = '';
  try {
    await invoke('delete_group', { name });
  } catch (e) {
    document.querySelector('#vault-err').textContent = errText(e);
  }
  collapsedGroups.delete(name);
  saveCollapsed();
  await renderVault();
}

function setEntryType(kind) {
  entryKind = kind === 'note' ? 'note' : 'login';
  document.querySelectorAll('#entry-type .gen__mode').forEach((b) => {
    b.classList.toggle('is-active', b.dataset.kind === entryKind);
  });
  document.querySelector('#f-login-fields').hidden = entryKind === 'note';
  document.querySelector('#entry-form').classList.toggle('is-note', entryKind === 'note');
}

const FIELD_LOCK =
  '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"></rect><path d="M8 11V8a4 4 0 0 1 8 0v3"></path></svg>';
const FIELD_X =
  '<svg viewBox="0 0 24 24" aria-hidden="true"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>';

function addFieldRow(label, value, secret) {
  const row = document.createElement('div');
  row.className = 'field-row';
  const lab = document.createElement('input');
  lab.className = 'field field--sm';
  lab.dataset.fieldlabel = '1';
  lab.placeholder = t('entry.fieldLabel');
  lab.value = label || '';
  const val = document.createElement('input');
  val.className = 'field field--sm';
  val.dataset.fieldvalue = '1';
  val.placeholder = t('entry.fieldValue');
  val.type = secret ? 'password' : 'text';
  val.value = value || '';
  const secretBtn = document.createElement('button');
  secretBtn.type = 'button';
  secretBtn.className = 'field-row__btn' + (secret ? ' is-on' : '');
  secretBtn.dataset.fieldsecret = '1';
  secretBtn.setAttribute('aria-label', t('entry.fieldSecret'));
  secretBtn.title = t('entry.fieldSecret');
  secretBtn.innerHTML = FIELD_LOCK;
  const delBtn = document.createElement('button');
  delBtn.type = 'button';
  delBtn.className = 'field-row__btn';
  delBtn.dataset.fielddel = '1';
  delBtn.setAttribute('aria-label', t('btn.delete'));
  delBtn.innerHTML = FIELD_X;
  row.append(lab, val, secretBtn, delBtn);
  document.querySelector('#f-fields').appendChild(row);
}

function gatherFields() {
  return [...document.querySelectorAll('#f-fields .field-row')]
    .map((row) => ({
      label: row.querySelector('[data-fieldlabel]').value.trim(),
      value: row.querySelector('[data-fieldvalue]').value,
      secret: row.querySelector('[data-fieldsecret]').classList.contains('is-on')
    }))
    .filter((f) => f.label || f.value);
}

function openModal(entry, password) {
  editingId = entry ? entry.id : null;
  document.querySelector('#edit-title').textContent = entry ? t('entry.editTitle') : t('entry.newTitle');
  document.querySelector('#f-name').value = entry ? entry.name : '';
  document.querySelector('#f-username').value = entry ? entry.username : '';
  document.querySelector('#f-url').value = entry ? entry.url : '';
  document.querySelector('#f-note').value = entry ? entry.note : '';
  populateGroupSelect(entry ? entry.group : '');
  const pwField = document.querySelector('#f-password');
  pwField.type = 'password';
  pwField.value = password || '';
  setGenMode('chars');
  setEntryType(entry && entry.kind === 'note' ? 'note' : 'login');
  const fieldsWrap = document.querySelector('#f-fields');
  fieldsWrap.textContent = '';
  if (entry && Array.isArray(entry.fields)) {
    entry.fields.forEach((f) => addFieldRow(f.label, f.value, f.secret));
  }
  document.querySelector('#entry-err').textContent = '';
  document.querySelector('#detail').hidden = true;
  const editPane = document.querySelector('#detail-edit');
  editPane.hidden = false;
  editPane.scrollTop = 0;
  document.querySelector('#f-name').focus();
}

function closeModal() {
  const editPane = document.querySelector('#detail-edit');
  if (editPane.hidden) {
    return;
  }
  editPane.hidden = true;
  document.querySelector('#detail').hidden = false;
  document
    .querySelector('#entry-form')
    .querySelectorAll('.field')
    .forEach((f) => {
      f.value = '';
    });
  document.querySelector('#f-fields').textContent = '';
  editingId = null;
  renderDetail();
}

let genMode = 'chars';

function setGenMode(mode) {
  genMode = mode === 'phrase' ? 'phrase' : 'chars';
  document.querySelectorAll('#gen-modes .gen__mode').forEach((b) => {
    b.classList.toggle('is-active', b.dataset.genmode === genMode);
  });
  document.querySelector('#gen-chars').hidden = genMode !== 'chars';
  document.querySelector('#gen-phrase').hidden = genMode !== 'phrase';
}

async function generatePassword() {
  const errEl = document.querySelector('#entry-err');
  errEl.textContent = '';
  try {
    let pw;
    if (genMode === 'phrase') {
      const options = {
        words: Number(document.querySelector('#gen-words').value),
        separator: document.querySelector('#gen-sep').value,
        capitalize: document.querySelector('#gen-cap').checked,
        number: document.querySelector('#gen-num').checked
      };
      pw = await invoke('generate_passphrase', { options });
    } else {
      const options = {
        length: Number(document.querySelector('#gen-length').value),
        lowercase: document.querySelector('#gen-lower').checked,
        uppercase: document.querySelector('#gen-upper').checked,
        digits: document.querySelector('#gen-digits').checked,
        symbols: document.querySelector('#gen-symbols').checked
      };
      pw = await invoke('generate_password', { options });
    }
    const field = document.querySelector('#f-password');
    field.type = 'text';
    field.value = pw;
  } catch (e) {
    errEl.textContent = errText(e);
  }
}

async function saveEntry(e) {
  e.preventDefault();
  const errEl = document.querySelector('#entry-err');
  errEl.textContent = '';
  const isNote = entryKind === 'note';
  const input = {
    name: document.querySelector('#f-name').value.trim(),
    username: isNote ? '' : document.querySelector('#f-username').value,
    password: isNote ? '' : document.querySelector('#f-password').value,
    url: isNote ? '' : document.querySelector('#f-url').value.trim(),
    note: document.querySelector('#f-note').value.trim(),
    group: document.querySelector('#f-group').value,
    kind: entryKind,
    fields: gatherFields()
  };
  if (!input.name) {
    errEl.textContent = t('val.nameRequired');
    return;
  }
  try {
    let id;
    if (editingId) {
      id = editingId;
      await invoke('update_entry', { id, input });
    } else {
      id = await invoke('add_entry', { input });
    }
    closeModal();
    setPwnedIndicator('none');
    await renderVault();
    selectEntry(id);
  } catch (err) {
    errEl.textContent = errText(err);
  }
}

function showSettingsSection(section) {
  document.querySelectorAll('#settings-nav .settings-nav__item').forEach((b) => {
    b.classList.toggle('is-active', b.dataset.section === section);
  });
  document.querySelectorAll('.settings-section').forEach((s) => {
    s.hidden = s.dataset.section !== section;
  });
  closeAllMenus();
}

function closeSettings() {
  closeAllMenus();
  document.querySelector('#settings-modal').hidden = true;
}

async function openSettings() {
  document.querySelector('#settings-modal').hidden = false;
  document.querySelector('#settings-err').textContent = '';
  document.querySelector('#idle-select').value = String(idleSeconds());
  await applyAutostartToggle();
  applyDiscreetToggle();
  await applyUpdatesToggle();

  let vaultUnlocked = false;
  let totpUnlocked = false;
  try {
    vaultUnlocked = await invoke('is_unlocked');
  } catch {
    vaultUnlocked = false;
  }
  try {
    totpUnlocked = await invoke('totp_is_unlocked');
  } catch {
    totpUnlocked = false;
  }

  document.querySelector('#pw-settings-body').hidden = !vaultUnlocked;
  document.querySelector('#pw-settings-locked').hidden = vaultUnlocked;
  document.querySelector('#totp-settings-body').hidden = !totpUnlocked;
  document.querySelector('#totp-settings-locked').hidden = totpUnlocked;

  if (vaultUnlocked) {
    await refreshLevel();
    updateSettingsLevel();
    await updateRecoverySetting('vault');
    document.querySelector('#pw-rotate').value = String(pwRotateMonths());
    backupStatus('', false);
    const restoreBtn = document.querySelector('#restore-btn');
    restoreBtn.dataset.confirm = '';
    restoreBtn.classList.remove('btn--danger');
    restoreBtn.textContent = t('backup.restore');
    const pathEl = document.querySelector('#settings-vault-path');
    try {
      pathEl.textContent = await invoke('vault_location');
    } catch (e) {
      pathEl.textContent = errText(e);
    }
  }
  if (totpUnlocked) {
    await updateRecoverySetting('totp');
  }

  showSettingsSection(currentSpace === 'totp' ? 'totp' : 'vault');
}

const RECOVERY_TARGETS = {
  vault: {
    stateEl: '#recovery-state',
    menuBtnEl: '#recovery-menu-btn',
    menuEl: '#recovery-menu',
    rowEl: '#recovery-rotate-row',
    selEl: '#recovery-rotate',
    hasCmd: 'has_recovery',
    setupCmd: 'setup_recovery',
    removeCmd: 'remove_recovery',
    unlockRecCmd: 'unlock_vault_recovery',
    resetPwCmd: 'reset_master_password',
    kMonths: 'recoveryRotateMonths',
    kAt: 'recoveryRotatedAt',
    kSnooze: 'recoveryRotateSnooze'
  },
  totp: {
    stateEl: '#totp-recovery-state',
    menuBtnEl: '#totp-recovery-menu-btn',
    menuEl: '#totp-recovery-menu',
    rowEl: '#totp-recovery-rotate-row',
    selEl: '#totp-recovery-rotate',
    hasCmd: 'has_totp_recovery',
    setupCmd: 'setup_totp_recovery',
    removeCmd: 'remove_totp_recovery',
    unlockRecCmd: 'unlock_totp_recovery',
    resetPwCmd: 'reset_totp_master_password',
    kMonths: 'totpRecoveryRotateMonths',
    kAt: 'totpRecoveryRotatedAt',
    kSnooze: 'totpRecoveryRotateSnooze'
  }
};

function recoveryRotateMonths(target) {
  return parseInt(localStorage.getItem(RECOVERY_TARGETS[target].kMonths) || '0', 10) || 0;
}

function markRecoveryRotated(target) {
  const cfg = RECOVERY_TARGETS[target];
  localStorage.setItem(cfg.kAt, String(Date.now()));
  localStorage.removeItem(cfg.kSnooze);
}

async function hasRecovery(target) {
  try {
    return await invoke(RECOVERY_TARGETS[target].hasCmd);
  } catch {
    return false;
  }
}

async function updateRecoverySetting(target) {
  const cfg = RECOVERY_TARGETS[target];
  const has = await hasRecovery(target);
  const stateEl = document.querySelector(cfg.stateEl);
  stateEl.textContent = has ? t('recovery.on') : t('recovery.off');
  stateEl.classList.toggle('is-off', !has);
  document.querySelector(cfg.rowEl).hidden = !has;
  document.querySelector(cfg.selEl).value = String(recoveryRotateMonths(target));
}

function recoveryMenuItem(label, onClick, danger) {
  const b = document.createElement('button');
  b.className = 'menu__item';
  b.type = 'button';
  b.textContent = label;
  if (danger) {
    b.classList.add('danger');
  }
  b.addEventListener('click', () => {
    closeAllMenus();
    onClick();
  });
  return b;
}

async function toggleRecoveryMenu(target, btn) {
  const cfg = RECOVERY_TARGETS[target];
  const menu = document.querySelector(cfg.menuEl);
  const willOpen = menu.hidden;
  closeAllMenus();
  if (!willOpen) {
    return;
  }
  const has = await hasRecovery(target);
  menu.textContent = '';
  if (has) {
    menu.append(
      recoveryMenuItem(t('recovery.reset'), () => runRecoverySetup(target)),
      recoveryMenuItem(t('recovery.disable'), () => disableRecovery(target), true)
    );
  } else {
    menu.append(recoveryMenuItem(t('recovery.setup'), () => runRecoverySetup(target)));
  }
  menu.hidden = false;
  positionMenu(menu, btn);
}

async function runRecoverySetup(target) {
  const cfg = RECOVERY_TARGETS[target];
  const errEl = document.querySelector('#settings-err');
  errEl.textContent = '';
  try {
    const code = await invoke(cfg.setupCmd);
    markRecoveryRotated(target);
    showRecoveryCode(code, () => updateRecoverySetting(target));
  } catch (e) {
    errEl.textContent = errText(e);
  }
}

async function disableRecovery(target) {
  const cfg = RECOVERY_TARGETS[target];
  const errEl = document.querySelector('#settings-err');
  errEl.textContent = '';
  try {
    await invoke(cfg.removeCmd);
    localStorage.removeItem(cfg.kAt);
    localStorage.removeItem(cfg.kSnooze);
  } catch (e) {
    errEl.textContent = errText(e);
  }
  await updateRecoverySetting(target);
}

function changeRecoveryRotate(target, value) {
  const cfg = RECOVERY_TARGETS[target];
  const months = parseInt(value, 10) || 0;
  localStorage.setItem(cfg.kMonths, String(months));
  if (months > 0 && !localStorage.getItem(cfg.kAt)) {
    localStorage.setItem(cfg.kAt, String(Date.now()));
  }
  localStorage.removeItem(cfg.kSnooze);
}

async function checkRecoveryRotation(target) {
  const cfg = RECOVERY_TARGETS[target];
  if (!(await hasRecovery(target))) {
    return;
  }
  const months = recoveryRotateMonths(target);
  if (months <= 0) {
    return;
  }
  const rotatedAt = parseInt(localStorage.getItem(cfg.kAt) || '0', 10);
  if (!rotatedAt) {
    localStorage.setItem(cfg.kAt, String(Date.now()));
    return;
  }
  const snooze = parseInt(localStorage.getItem(cfg.kSnooze) || '0', 10);
  const now = Date.now();
  if (now < snooze) {
    return;
  }
  const dueMs = months * 30 * 24 * 60 * 60 * 1000;
  if (now - rotatedAt >= dueMs) {
    rotateTarget = target;
    document.querySelector('#rotate-modal').hidden = false;
  }
}

async function rotateNow() {
  const cfg = RECOVERY_TARGETS[rotateTarget];
  await withButton(document.querySelector('#rotate-now'), t('load.generating'), async () => {
    try {
      const code = await invoke(cfg.setupCmd);
      markRecoveryRotated(rotateTarget);
      document.querySelector('#rotate-modal').hidden = true;
      showRecoveryCode(code, null);
    } catch {
      document.querySelector('#rotate-modal').hidden = true;
    }
  });
}

function rotateLater() {
  localStorage.setItem(RECOVERY_TARGETS[rotateTarget].kSnooze, String(Date.now() + 7 * 24 * 60 * 60 * 1000));
  document.querySelector('#rotate-modal').hidden = true;
}

async function applyAutostartToggle() {
  let on = true;
  try {
    on = await invoke('get_autostart');
  } catch {
    on = true;
  }
  const sw = document.querySelector('#autostart-switch');
  sw.classList.toggle('is-on', on);
  sw.setAttribute('aria-checked', on ? 'true' : 'false');
}

async function toggleAutostart() {
  const on = document.querySelector('#autostart-switch').getAttribute('aria-checked') !== 'true';
  await invoke('set_autostart', { enabled: on }).catch(() => {});
  await applyAutostartToggle();
}

function updateTrayLabels() {
  invoke('update_tray_labels', { show: t('tray.show'), quit: t('tray.quit') }).catch(() => {});
}

function applyDiscreetToggle() {
  const sw = document.querySelector('#discreet-switch');
  const on = discreetEnabled();
  sw.classList.toggle('is-on', on);
  sw.setAttribute('aria-checked', on ? 'true' : 'false');
  document.querySelector('#discreet-config').hidden = true;
  document.querySelector('#discreet-code').value = '';
  document.querySelector('#discreet-note').textContent = on ? t('discreet.active') : '';
}

function toggleDiscreet() {
  if (discreetEnabled()) {
    localStorage.removeItem('discreet.on');
    localStorage.removeItem('discreet.hash');
    invoke('set_discreet', { on: false }).catch(() => {});
    applyDiscreetToggle();
  } else {
    document.querySelector('#discreet-config').hidden = false;
    document.querySelector('#discreet-note').textContent = '';
    document.querySelector('#discreet-code').value = '';
    document.querySelector('#discreet-code').focus();
  }
}

async function saveDiscreetCode() {
  const code = document.querySelector('#discreet-code').value.trim();
  const note = document.querySelector('#discreet-note');
  if (code.length < 3) {
    note.textContent = t('discreet.tooShort');
    return;
  }
  const hash = await sha256Hex(code);
  localStorage.setItem('discreet.hash', hash);
  localStorage.setItem('discreet.on', '1');
  await invoke('set_discreet', { on: true }).catch(() => {});
  applyDiscreetToggle();
}

function cancelDiscreetCode() {
  applyDiscreetToggle();
}

function updatesEnabled() {
  return localStorage.getItem('updates.on') !== '0';
}

async function applyUpdatesToggle() {
  const sw = document.querySelector('#updates-switch');
  const on = updatesEnabled();
  sw.classList.toggle('is-on', on);
  sw.setAttribute('aria-checked', on ? 'true' : 'false');
  document.querySelector('#update-status').textContent = '';
  try {
    const v = await invoke('app_version');
    document.querySelector('#update-current').textContent = t('update.current', { v });
  } catch {
    document.querySelector('#update-current').textContent = '';
  }
}

function toggleUpdates() {
  localStorage.setItem('updates.on', updatesEnabled() ? '0' : '1');
  applyUpdatesToggle();
}

async function checkForUpdates(manual) {
  if (inDecoy) {
    return;
  }
  const status = document.querySelector('#update-status');
  if (manual) {
    status.textContent = t('update.checking');
  }
  let info = null;
  try {
    info = await invoke('check_update');
  } catch (e) {
    if (manual) {
      status.textContent = errText(e);
    }
    return;
  }
  if (info) {
    if (manual) {
      status.textContent = '';
    }
    openUpdateModal(info);
  } else if (manual) {
    status.textContent = t('update.upToDate');
  }
}

function openUpdateModal(info) {
  if (inDecoy) {
    return;
  }
  document.querySelector('#update-desc').textContent = t('update.available', { v: info.version });
  const notes = document.querySelector('#update-notes');
  if (info.notes && info.notes.trim()) {
    notes.textContent = info.notes.trim();
    notes.hidden = false;
  } else {
    notes.hidden = true;
  }
  document.querySelector('#update-progress').textContent = '';
  document.querySelector('#update-now').disabled = false;
  document.querySelector('#update-modal').hidden = false;
}

function closeUpdateModal() {
  document.querySelector('#update-modal').hidden = true;
}

async function runUpdateInstall() {
  const now = document.querySelector('#update-now');
  now.disabled = true;
  document.querySelector('#update-progress').textContent = t('update.installing');
  try {
    await invoke('install_update');
  } catch (e) {
    now.disabled = false;
    document.querySelector('#update-progress').textContent = errText(e);
  }
}

function changeIdle(e) {
  localStorage.setItem('idleSeconds', e.target.value);
  startIdleTimer();
}

async function changeVaultLocation() {
  const errEl = document.querySelector('#settings-err');
  errEl.textContent = '';
  const pathEl = document.querySelector('#settings-vault-path');
  try {
    pathEl.textContent = await invoke('change_vault_location');
  } catch (e) {
    errEl.textContent = errText(e);
  }
}

function backupStatus(msg, isError) {
  const el = document.querySelector('#backup-status');
  el.textContent = msg;
  el.classList.toggle('is-error', !!isError);
  el.classList.toggle('is-ok', !isError && msg !== '');
}

async function exportVault() {
  backupStatus('', false);
  await withButton(document.querySelector('#export-btn'), t('backup.exporting'), async () => {
    try {
      const done = await invoke('export_vault');
      if (done) {
        backupStatus(t('backup.exported'), false);
      }
    } catch (e) {
      backupStatus(errText(e), true);
    }
  });
}

async function restoreVault() {
  const btn = document.querySelector('#restore-btn');
  backupStatus('', false);
  if (btn.dataset.confirm !== '1') {
    btn.dataset.confirm = '1';
    btn.textContent = t('btn.confirm');
    btn.classList.add('btn--danger');
    backupStatus(t('backup.confirmRestore'), true);
    return;
  }
  btn.dataset.confirm = '';
  btn.classList.remove('btn--danger');
  btn.textContent = t('backup.restore');
  try {
    const done = await invoke('restore_vault');
    if (done) {
      closeSettings();
      await switchSpace('passwords');
    }
  } catch (e) {
    backupStatus(errText(e), true);
  }
}

function closeEmergencyModal() {
  document.querySelector('#emergency-modal').hidden = true;
}

async function openEmergencyModal() {
  let location = '';
  try {
    location = await invoke('vault_location');
  } catch {
    location = '';
  }
  document.querySelector('#emergency-location').textContent = location;
  let hasRec = false;
  try {
    hasRec = await invoke('vault_has_recovery');
  } catch {
    hasRec = false;
  }
  document.querySelector('#emergency-recovery').textContent = hasRec
    ? t('emergency.recoveryOn')
    : t('emergency.recoveryOff');
  document.querySelector('#emergency-modal').hidden = false;
}

function printEmergency() {
  window.print();
}

async function importCsv() {
  backupStatus('', false);
  await withButton(document.querySelector('#import-csv-btn'), t('backup.importing'), async () => {
    try {
      const n = await invoke('import_csv');
      if (n > 0) {
        await renderVault();
        backupStatus(t('backup.imported', { n }), false);
      }
    } catch (e) {
      backupStatus(errText(e), true);
    }
  });
}

function onSearch(e) {
  filterText = e.target.value;
  drawEntries();
}

function onEnter(el, fn) {
  el.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      fn();
    }
  });
}

const SELECT_CHEVRON =
  '<svg viewBox="0 0 24 24" aria-hidden="true"><polyline points="6 9 12 15 18 9"></polyline></svg>';

function enhanceSelects() {
  document.querySelectorAll('select.field').forEach((sel) => {
    if (sel.parentElement && sel.parentElement.classList.contains('select-wrap')) {
      return;
    }
    const wrap = document.createElement('span');
    wrap.className = 'select-wrap';
    if (sel.id === 'f-group') {
      wrap.classList.add('select-wrap--full');
    }
    sel.parentNode.insertBefore(wrap, sel);
    wrap.appendChild(sel);
    const arrow = document.createElement('span');
    arrow.className = 'select-wrap__arrow';
    arrow.innerHTML = SELECT_CHEVRON;
    wrap.appendChild(arrow);
    sel.addEventListener('change', () => sel.blur());
  });
}

window.addEventListener('DOMContentLoaded', () => {
  const appWindow = getCurrentWindow();
  document.querySelector('#win-min').addEventListener('click', () => appWindow.minimize());
  document.querySelector('#win-max').addEventListener('click', () => appWindow.toggleMaximize());
  document.querySelector('#win-close').addEventListener('click', async () => {
    if (discreetEnabled() && !inDecoy) {
      await enterDecoy();
    }
    appWindow.close();
  });

  document.querySelector('#create-btn').addEventListener('click', createVault);
  document.querySelector('#unlock-btn').addEventListener('click', unlockVault);
  document.querySelector('#forgot-link').addEventListener('click', () => openRecoverModal('vault'));
  document.querySelector('#totp-forgot-link').addEventListener('click', () => openRecoverModal('totp'));
  document.querySelector('#recover-cancel').addEventListener('click', closeRecoverModal);
  document.querySelector('#recover-close-x').addEventListener('click', closeRecoverModal);
  document.querySelector('#recover-backdrop').addEventListener('click', closeRecoverModal);
  document.querySelector('#recover-form').addEventListener('submit', submitRecover);
  document.querySelector('#lock-btn').addEventListener('click', lockVault);
  document.querySelector('#add-btn').addEventListener('click', () => openModal(null, ''));
  document.querySelector('#add-group-btn').addEventListener('click', () => openGroupModal(null));
  document.querySelector('#group-cancel').addEventListener('click', closeGroupModal);
  document.querySelector('#group-backdrop').addEventListener('click', closeGroupModal);
  document.querySelector('#group-form').addEventListener('submit', submitGroup);
  document.querySelector('#cancel-btn').addEventListener('click', closeModal);
  document.querySelector('#gen-btn').addEventListener('click', generatePassword);
  document.querySelector('#gen-modes').addEventListener('click', (e) => {
    const b = e.target.closest('[data-genmode]');
    if (b) {
      setGenMode(b.dataset.genmode);
    }
  });
  document.querySelector('#entry-type').addEventListener('click', (e) => {
    const b = e.target.closest('[data-kind]');
    if (b) {
      setEntryType(b.dataset.kind);
    }
  });
  document.querySelector('#add-field-btn').addEventListener('click', () => addFieldRow('', '', false));
  document.querySelector('#f-fields').addEventListener('click', (e) => {
    const del = e.target.closest('[data-fielddel]');
    if (del) {
      del.closest('.field-row').remove();
      return;
    }
    const sec = e.target.closest('[data-fieldsecret]');
    if (sec) {
      sec.classList.toggle('is-on');
      const val = sec.closest('.field-row').querySelector('[data-fieldvalue]');
      val.type = sec.classList.contains('is-on') ? 'password' : 'text';
    }
  });
  document.querySelector('#entry-form').addEventListener('submit', saveEntry);
  const entryList = document.querySelector('#entry-list');
  entryList.addEventListener('click', onListClick);
  entryList.addEventListener('scroll', closeAllMenus);
  entryList.addEventListener('dragstart', (e) => {
    const entryLi = e.target.closest('.entry');
    const groupLi = e.target.closest('.group');
    e.dataTransfer.effectAllowed = 'move';
    if (entryLi) {
      dragKind = 'entry';
      dragId = entryLi.dataset.id;
      entryLi.classList.add('is-dragging');
    } else if (groupLi) {
      dragKind = 'group';
      dragGroup = groupLi.dataset.group;
      groupLi.classList.add('is-dragging');
    } else {
      return;
    }
    try {
      e.dataTransfer.setData('text/plain', dragId || dragGroup);
    } catch (err) {
      e.dataTransfer.dropEffect = 'move';
    }
  });
  entryList.addEventListener('dragover', (e) => {
    if (!dragKind) {
      return;
    }
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    clearDropIndicators();
    const t = e.target.closest('.entry, .group');
    if (dragKind === 'group') {
      if (t && t.classList.contains('group') && t.dataset.group !== dragGroup) {
        t.classList.add('drop-before');
      }
    } else if (t && t.classList.contains('entry') && t.dataset.id !== dragId) {
      t.classList.add('drop-before');
    } else if (t && t.classList.contains('group')) {
      t.classList.add('drop-into');
    }
  });
  entryList.addEventListener('drop', async (e) => {
    if (!dragKind) {
      return;
    }
    e.preventDefault();
    const t = e.target.closest('.entry, .group');
    const kind = dragKind;
    const id = dragId;
    const name = dragGroup;
    dragKind = null;
    dragId = null;
    dragGroup = null;
    clearDropIndicators();
    if (kind === 'group') {
      await handleGroupDrop(name, t);
    } else {
      await handleEntryDrop(id, t);
    }
  });
  entryList.addEventListener('dragend', () => {
    dragKind = null;
    dragId = null;
    dragGroup = null;
    document.querySelectorAll('.is-dragging').forEach((el) => el.classList.remove('is-dragging'));
    clearDropIndicators();
  });
  const detailEl = document.querySelector('#detail');
  detailEl.addEventListener('click', onDetailClick);
  detailEl.addEventListener('scroll', closeAllMenus);
  document.querySelector('#search').addEventListener('input', onSearch);
  document.querySelector('#health-btn').addEventListener('click', openHealthModal);
  document.querySelector('#health-close-x').addEventListener('click', closeHealthModal);
  document.querySelector('#health-backdrop').addEventListener('click', closeHealthModal);
  document.querySelector('#health-body').addEventListener('click', onHealthClick);
  document.querySelector('#group-close-x').addEventListener('click', closeGroupModal);
  document.querySelector('#level-close-x').addEventListener('click', closeLevelModal);
  document.querySelector('#password-close-x').addEventListener('click', closePasswordModal);
  document.querySelector('#open-settings-btn').addEventListener('click', openSettings);
  document.querySelector('#settings-close-x').addEventListener('click', closeSettings);
  document.querySelector('#settings-backdrop').addEventListener('click', closeSettings);
  document.querySelector('#settings-nav').addEventListener('click', (e) => {
    const item = e.target.closest('.settings-nav__item');
    if (item) {
      showSettingsSection(item.dataset.section);
    }
  });
  document.querySelector('#theme-toggle').addEventListener('click', () => {
    setTheme(currentTheme() === 'dark' ? 'light' : 'dark');
  });
  document.querySelector('#idle-select').addEventListener('change', changeIdle);
  document.querySelector('#pw-rotate').addEventListener('change', (e) => {
    localStorage.setItem('pwRotateMonths', String(parseInt(e.target.value, 10) || 0));
  });
  document.querySelector('#autostart-switch').addEventListener('click', toggleAutostart);
  document.querySelector('#discreet-switch').addEventListener('click', toggleDiscreet);
  document.querySelector('#discreet-save').addEventListener('click', saveDiscreetCode);
  document.querySelector('#discreet-cancel').addEventListener('click', cancelDiscreetCode);
  onEnter(document.querySelector('#discreet-code'), saveDiscreetCode);
  document.querySelector('#decoy-text').addEventListener('input', onDecoyInput);
  document.querySelector('#updates-switch').addEventListener('click', toggleUpdates);
  document.querySelector('#update-check-btn').addEventListener('click', () => checkForUpdates(true));
  document.querySelector('#update-now').addEventListener('click', runUpdateInstall);
  document.querySelector('#update-later').addEventListener('click', closeUpdateModal);
  document.querySelector('#update-close-x').addEventListener('click', closeUpdateModal);
  document.querySelector('#update-backdrop').addEventListener('click', closeUpdateModal);
  document.querySelector('#change-totp-password-btn').addEventListener('click', () => openPasswordModal('totp'));
  document
    .querySelector('#recovery-menu-btn')
    .addEventListener('click', (e) => toggleRecoveryMenu('vault', e.currentTarget));
  document
    .querySelector('#totp-recovery-menu-btn')
    .addEventListener('click', (e) => toggleRecoveryMenu('totp', e.currentTarget));
  document
    .querySelector('#recovery-rotate')
    .addEventListener('change', (e) => changeRecoveryRotate('vault', e.target.value));
  document
    .querySelector('#totp-recovery-rotate')
    .addEventListener('change', (e) => changeRecoveryRotate('totp', e.target.value));
  document.querySelector('#rotate-now').addEventListener('click', rotateNow);
  document.querySelector('#rotate-later').addEventListener('click', rotateLater);
  document.querySelector('#rotate-backdrop').addEventListener('click', rotateLater);
  document.querySelector('#change-location-btn').addEventListener('click', changeVaultLocation);
  document.querySelector('#export-btn').addEventListener('click', exportVault);
  document.querySelector('#restore-btn').addEventListener('click', restoreVault);
  document.querySelector('#import-csv-btn').addEventListener('click', importCsv);
  document.querySelector('#emergency-btn').addEventListener('click', openEmergencyModal);
  document.querySelector('#emergency-close-x').addEventListener('click', closeEmergencyModal);
  document.querySelector('#emergency-backdrop').addEventListener('click', closeEmergencyModal);
  document.querySelector('#emergency-cancel').addEventListener('click', closeEmergencyModal);
  document.querySelector('#emergency-print').addEventListener('click', printEmergency);
  document.querySelector('#change-level-btn').addEventListener('click', openLevelModal);
  document.querySelector('#change-password-btn').addEventListener('click', () => openPasswordModal('vault'));
  document.querySelector('#password-cancel').addEventListener('click', closePasswordModal);
  document.querySelector('#password-backdrop').addEventListener('click', closePasswordModal);
  document.querySelector('#password-form').addEventListener('submit', submitPasswordChange);
  document.querySelector('#level-cancel').addEventListener('click', closeLevelModal);
  document.querySelector('#level-backdrop').addEventListener('click', closeLevelModal);
  document.querySelector('#level-form').addEventListener('submit', submitLevelChange);
  document.querySelector('#level-modal-picker').addEventListener('click', (e) => {
    const btn = e.target.closest('.level');
    if (btn) {
      selectPendingLevel(btn.dataset.level);
    }
  });
  document.querySelector('#level-picker').addEventListener('click', (e) => {
    const btn = e.target.closest('.level');
    if (btn) {
      selectLevel(btn.dataset.level);
    }
  });
  document.querySelector('#tab-passwords').addEventListener('click', () => switchSpace('passwords'));
  document.querySelector('#tab-totp').addEventListener('click', () => switchSpace('totp'));
  document.querySelector('#totp-create-btn').addEventListener('click', createTotpVault);
  document.querySelector('#totp-unlock-btn').addEventListener('click', unlockTotpVault);
  document.querySelector('#totp-lock-btn').addEventListener('click', lockTotp);
  document.querySelector('#totp-add-btn').addEventListener('click', openTotpModal);
  document.querySelector('#totp-cancel').addEventListener('click', closeTotpModal);
  document.querySelector('#totp-backdrop').addEventListener('click', closeTotpModal);
  document.querySelector('#totp-close-x').addEventListener('click', closeTotpModal);
  document.querySelector('#totp-form').addEventListener('submit', submitTotp);
  document.querySelector('#totp-list').addEventListener('click', onTotpListClick);
  onEnter(document.querySelector('#create-pw'), createVault);
  onEnter(document.querySelector('#create-pw2'), createVault);
  onEnter(document.querySelector('#unlock-pw'), unlockVault);
  onEnter(document.querySelector('#totp-create-pw'), createTotpVault);
  onEnter(document.querySelector('#totp-create-pw2'), createTotpVault);
  onEnter(document.querySelector('#totp-unlock-pw'), unlockTotpVault);

  document.addEventListener('click', (e) => {
    if (!e.target.isConnected) {
      return;
    }
    if (
      !e.target.closest('.group__actions') &&
      !e.target.closest('.detail__actions') &&
      !e.target.closest('.entry__actions') &&
      !e.target.closest('.setting__actions')
    ) {
      closeAllMenus();
    }
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeModal();
      closeGroupModal();
      closeLevelModal();
      closePasswordModal();
      closeHealthModal();
      closeTotpModal();
      closeRecoverModal();
      closeEmergencyModal();
      closeUpdateModal();
      closeSettings();
      closeAllMenus();
    } else if ((e.ctrlKey || e.metaKey) && (e.key === 'l' || e.key === 'L')) {
      if (!screens.vault.hidden || !screens.totp.hidden) {
        e.preventDefault();
        idleLock();
      }
    }
  });
  document.addEventListener('mousedown', onActivity);
  document.addEventListener('keydown', onActivity);

  document.querySelector('#lang-select').addEventListener('change', (e) => setLang(e.target.value));
  document.querySelector('#lang-select').value = lang;
  applyI18n();
  updateTrayLabels();
  applyTheme(currentTheme());
  enhanceSelects();
  selectLevel('normal');
  if (discreetEnabled()) {
    enterDecoy();
  } else {
    route();
  }
  if (updatesEnabled()) {
    setTimeout(() => checkForUpdates(false), 2500);
  }
});
