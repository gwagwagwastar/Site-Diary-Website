(() => {
  'use strict';
  const el = id => document.getElementById(`vault-${id}`);
  const text = message => { el('status').textContent = message; };
  const encoder = new TextEncoder();
  const magic = 'QCSD1';
  const limit = 20 * 1024 * 1024;
  const repoSetting = `diary-repository:${location.pathname.replace(/index\.html$/, '')}`;
  let session, timer;
  el('repo').value = localStorage.getItem(repoSetting) || '';

  function base64(bytes) {
    let str = '';
    for (let i = 0; i < bytes.length; i += 8192) str += String.fromCharCode(...bytes.subarray(i, i + 8192));
    return btoa(str);
  }
  const decode = str => Uint8Array.from(atob(str), ch => ch.charCodeAt(0));
  async function keyFor(s, salt) {
    const tag = base64(salt);
    if (s.salt !== tag) {
      s.key = await crypto.subtle.deriveKey({name: 'PBKDF2', hash: 'SHA-256', iterations: 600000, salt},
        s.password, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
      s.salt = tag;
    }
    return s.key;
  }
  async function seal(s, records) {
    const bytes = encoder.encode(JSON.stringify(records));
    if (bytes.length + 49 > limit) throw Error('Vault exceeds 20 MiB. Keep a local backup; sync has not written this change.');
    const salt = s.salt ? decode(s.salt) : crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({name:'AES-GCM', iv}, await keyFor(s, salt), bytes);
    const packet = new Uint8Array(33 + cipher.byteLength);
    packet.set(encoder.encode(magic)); packet.set(salt, 5); packet.set(iv, 21); packet.set(new Uint8Array(cipher), 33);
    return base64(packet);
  }
  async function unseal(s, encoded) {
    const packet = decode(encoded);
    if (packet.length < 49 || new TextDecoder().decode(packet.subarray(0, 5)) !== magic) throw Error('Unrecognized encrypted vault; nothing overwritten.');
    const key = await keyFor(s, packet.subarray(5, 21));
    let plain;
    try {
      plain = await crypto.subtle.decrypt({name:'AES-GCM', iv:packet.subarray(21, 33)}, key, packet.subarray(33));
    } catch (error) {
      if (error.name !== 'OperationError') throw error;
      throw Error('Wrong passphrase or damaged vault. Lock and try again; nothing overwritten.');
    }
    return JSON.parse(new TextDecoder().decode(plain));
  }

  async function api(s, path, options = {}, missing = false) {
    const response = await fetch(`https://api.github.com/repos/${s.repo}${path}`, {
      ...options, signal:s.controller.signal, credentials:'omit', cache:'no-store', redirect:'error',
      headers:{Authorization:`Bearer ${s.token}`, Accept:'application/vnd.github+json', 'Content-Type':'application/json'}
    });
    if (missing && response.status === 404) return null;
    if (!response.ok) {
      const hint = response.status === 409 || response.status === 422 ? 'Remote changed or write rejected. Retry; check branch rules.'
        : 'Check the private repo, token permissions, expiry, and GitHub rate limit.';
      throw Error(`GitHub ${response.status}. ${hint}`);
    }
    return response.json();
  }

  function indexed(records) {
    const result = new Map();
    const idOK = value => typeof value === 'string' && /^[a-zA-Z0-9_-]+$/.test(value);
    if (!Array.isArray(records)) throw Error('Invalid diary list.');
    for (const d of records) {
      if (!/^\d\d\/\d\d\/\d{4}$/.test(d.dateKey) || d.meta?.date !== d.dateKey || result.has(d.dateKey) ||
          !Array.isArray(d.inspections) || !d.inspections.every(i => idOK(i.id) && ['Morning','Afternoon'].includes(i.session) &&
            (i.defects || []).every(v => idOK(v.id)) && (i.photos || []).every(p => idOK(p.id) &&
              /^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(p.dataUrl)))) {
        throw Error('Unsupported diary date, entry or photo. Export a backup and check the records before syncing.');
      }
      result.set(d.dateKey, d);
    }
    return result;
  }
  const content = d => JSON.stringify({...d, updatedAt:0});
  async function hashes(records) {
    return Object.fromEntries(await Promise.all([...records].map(async ([date, d]) => [
      date, base64(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(content(d)))))
    ])));
  }
  function read(db, store, key) {
    return new Promise((resolve, reject) => {
      const table = db.transaction(store).objectStore(store);
      const req = key === undefined ? table.getAll() : table.get(key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  function checkStorage() {
    if (Object.keys(localStorage).some(k => k.startsWith('qcs_fallback_'))) {
      throw Error('Some dates are in fallback storage. Sync paused to avoid an incomplete backup.');
    }
  }
  function commit(db, s, baseKey, before, merged, base) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction([STORE_NAME, 'syncBases'], 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const req = store.getAll();
      req.onsuccess = () => {
        if (s !== session || JSON.stringify(req.result) !== JSON.stringify(before)) return tx.abort();
        for (const d of before) if (!merged.has(d.dateKey)) store.delete(d.dateKey);
        for (const [k,d] of merged) if (s.changedDates.has(k)) store.put(d);
        tx.objectStore('syncBases').put(base, baseKey);
      };
      tx.oncomplete = resolve;
      tx.onabort = () => reject(tx.error || Error('Local diary changed during sync; retrying on the next sync.'));
    });
  }

  async function sync(s, review) {
    checkStorage();
    const repo = await api(s, '');
    if (repo.private !== true || repo.full_name?.toLowerCase() !== s.repo) throw Error('Sync requires the exact name of a PRIVATE repository. No upload made.');
    const branch = repo.default_branch;
    const path = '/contents/diary.vault';
    const db = await openPhoneDB();
    const baseKey = `${repo.id}:${branch}`;
    const base = await read(db, 'syncBases', baseKey);
    const info = await api(s, `${path}?ref=${encodeURIComponent(branch)}`, {}, true);
    if (!info && base) throw Error('The previous vault is missing. Restore it from Git history before syncing.');
    if (info && (info.type !== 'file' || !/^[0-9a-f]{40}$/.test(info.sha) || info.size > limit)) throw Error('Unsupported vault file or vault exceeds 20 MiB.');
    let remote = new Map();
    if (info) {
      if (s.remoteSha === info.sha) remote = s.remote;
      else {
        const blob = info.encoding === 'base64' ? info : await api(s, `/git/blobs/${info.sha}`);
        if (blob.encoding !== 'base64' || !blob.content) throw Error('Could not read the encrypted GitHub file.');
        remote = indexed(await unseal(s, blob.content));
        s.remote = remote; s.remoteSha = info.sha;
      }
    }
    const before = await read(db, STORE_NAME);
    const local = indexed(before);
    const lh = await hashes(local), rh = await hashes(remote);
    const merged = new Map(), conflicts = [];
    let push = !info;
    s.changedDates = new Set();
    const next = {};
    for (const date of new Set([...local.keys(), ...remote.keys(), ...Object.keys(base || {})])) {
      const l = lh[date], r = rh[date], b = base?.[date];
      let chosen;
      if (l === r || r === b) chosen = l;
      else if (l === b || (!base && local.has(date) && content(local.get(date)) === content(buildDefaultDiaryForDate(date)))) chosen = r;
      else {
        conflicts.push(date);
        if (!review) continue;
        const answer = prompt(`Both devices changed ${date}. Type DEVICE or GITHUB to keep that version (including a deletion). Cancel to keep both unchanged. Back up first if unsure.`);
        if (!answer || !['DEVICE','GITHUB'].includes(answer.trim().toUpperCase())) throw Error('Conflict unresolved; no changes written.');
        chosen = answer.trim().toUpperCase() === 'DEVICE' ? l : r;
      }
      if (chosen) { next[date] = chosen; merged.set(date, chosen === l ? local.get(date) : remote.get(date)); }
      if (chosen !== l) s.changedDates.add(date);
      if (chosen !== r) push = true;
    }
    el('resolve').hidden = !conflicts.length;
    if (conflicts.length && !review) throw Error(`Conflict: ${conflicts.join(', ')}. Back up locally, then review conflicting dates. Neither copy was overwritten.`);
    if (!merged.size) throw Error('No diary dates available; refusing to sync an empty vault.');
    if (s.changedDates.size && (document.activeElement?.matches('input, textarea, select') || document.querySelector('[id$="-modal"]:not(.hidden)'))) {
      throw Error('Finish editing and close the dialog to receive updates.');
    }
    if (push) {
      const encrypted = await seal(s, [...merged.values()]);
      checkStorage();
      const saved = await api(s, path, {method:'PUT', body:JSON.stringify({
        message:'Update encrypted diary', branch, content:encrypted, ...(info ? {sha:info.sha} : {})
      })});
      s.remote = merged; s.remoteSha = saved.content.sha;
    }
    if (s !== session) return;
    await commit(db, s, baseKey, before, merged, next);
    if (s.changedDates.size) {
      diaryCache = [...merged.values()];
      if (s.changedDates.has(appState.dateKey)) {
        appState = merged.get(appState.dateKey) || diaryCache[0];
        localStorage.setItem(ACTIVE_DATE_KEY, appState.dateKey);
        initUI();
      } else renderSavedDaysBar();
    }
    el('resolve').hidden = true;
    text(`Encrypted sync complete at ${new Date().toLocaleTimeString()}.`);
  }

  async function run(review = false) {
    const s = session;
    if (!s || s.busy) return;
    if (!navigator.onLine) { text('Offline. Changes stay on this device until sync resumes.'); return; }
    s.busy = true;
    text('Checking private repository...');
    try { await sync(s, review); }
    catch (error) { if (s === session) text(`Sync paused: ${error.message}`); }
    finally { s.busy = false; if (s === session && s.pending) { s.pending = false; schedule(); } }
  }
  function schedule() {
    if (!session) return;
    text('Pending encrypted sync.');
    if (session.busy) { session.pending = true; return; }
    clearTimeout(timer);
    timer = setTimeout(() => run(), 1500);
  }
  el('form').onsubmit = async event => {
    event.preventDefault();
    const repo = el('repo').value.trim().toLowerCase();
    if (!/^[a-z0-9_-]+\/[a-z0-9_.-]+$/.test(repo) || ['.', '..'].includes(repo.split('/')[1])) {
      text('Enter a repository as owner/name, not a URL.'); return;
    }
    if (!window.isSecureContext || !crypto.subtle) { text('Encryption requires HTTPS or localhost.'); return; }
    el('unlock').disabled = true;
    try {
      const password = await crypto.subtle.importKey('raw', encoder.encode(el('password').value), 'PBKDF2', false, ['deriveKey']);
      localStorage.setItem(repoSetting, repo);
      session = {repo, token:el('token').value.trim(), password, controller:new AbortController()};
      el('password').value = el('token').value = '';
      el('form').hidden = true; el('actions').hidden = false;
      await run();
    } catch (error) { text(`Unlock failed: ${error.message}`); }
    finally { el('unlock').disabled = false; }
  };
  el('lock').onclick = () => {
    session?.controller.abort(); session = null; clearTimeout(timer);
    el('form').hidden = false; el('actions').hidden = true; el('resolve').hidden = true;
    text('Private sync locked. Local edits will sync after unlocking.');
  };
  el('now').onclick = () => run();
  el('resolve').onclick = () => run(true);
  window.addEventListener('diary-saved', schedule);
  window.addEventListener('online', schedule);
  window.addEventListener('offline', () => { if (session) text('Offline. Changes stay on this device.'); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) schedule(); });
  setInterval(() => { if (!document.hidden) run(); }, 60000);
})();
