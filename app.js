/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
   SECURITY CHECKPOINT PWA â€” COMPLETE APPLICATION
   â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

'use strict';

// â”€â”€â”€ UUID Generator â”€â”€â”€
function uuid() {
  return 'xxxx-xxxx-4xxx-yxxx-xxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  }) + '-' + Date.now().toString(36);
}

// â”€â”€â”€ Device ID â”€â”€â”€
function getDeviceId() {
  let id = localStorage.getItem('sc_device_id');
  if (!id) { id = 'DEV-' + uuid(); localStorage.setItem('sc_device_id', id); }
  return id;
}

// Security helpers
const Auth = {
  encoder: new TextEncoder(),

  async sha256(value) {
    const bytes = this.encoder.encode(value);
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  async hashPin(pin) {
    return this.sha256(`sc:v1:${pin}`);
  },

  validUsername(username) {
    return /^[a-z0-9._-]{3,24}$/.test(username);
  }
};

// â”€â”€â”€ Time Helpers â”€â”€â”€
const T = {
  now: () => new Date().toISOString(),
  localISO: (d = new Date()) => {
    const off = d.getTimezoneOffset();
    const local = new Date(d.getTime() - off * 60000);
    return local.toISOString().slice(0, 16);
  },
  display: (iso) => {
    if (!iso) return '--';
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }) +
      ' ' + d.toLocaleDateString([], { day: '2-digit', month: 'short' });
  },
  displayTime: (iso) => {
    if (!iso) return '--';
    return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  },
  displayDate: (iso) => {
    if (!iso) return '--';
    return new Date(iso).toLocaleDateString([], { year: 'numeric', month: 'short', day: '2-digit' });
  },
  duration: (isoIn, isoOut) => {
    if (!isoIn || !isoOut) return '--';
    const mins = Math.round((new Date(isoOut) - new Date(isoIn)) / 60000);
    if (mins < 0) return '--';
    const h = Math.floor(mins / 60);
    const m = mins % 60;
    return `${h}:${String(m).padStart(2, '0')}`;
  },
  durationMins: (isoIn, isoOut) => {
    if (!isoIn || !isoOut) return 0;
    return Math.max(0, Math.round((new Date(isoOut) - new Date(isoIn)) / 60000));
  },
  todayStart: () => {
    const d = new Date(); d.setHours(0, 0, 0, 0);
    return d.toISOString();
  },
  todayEnd: () => {
    const d = new Date(); d.setHours(23, 59, 59, 999);
    return d.toISOString();
  },
  yesterdayStart: () => {
    const d = new Date(); d.setDate(d.getDate() - 1); d.setHours(0, 0, 0, 0);
    return d.toISOString();
  },
  yesterdayEnd: () => {
    const d = new Date(); d.setDate(d.getDate() - 1); d.setHours(23, 59, 59, 999);
    return d.toISOString();
  },
  weekStart: () => {
    const d = new Date();
    const day = d.getDay();
    d.setDate(d.getDate() - (day === 0 ? 6 : day - 1));
    d.setHours(0, 0, 0, 0);
    return d.toISOString();
  },
  minsOnSite: (isoIn) => {
    return Math.max(0, Math.round((Date.now() - new Date(isoIn).getTime()) / 60000));
  },
  formatMins: (mins) => {
    const h = Math.floor(mins / 60);
    const m = mins % 60;
    return `${h}:${String(m).padStart(2, '0')}`;
  },
  toDateInput: (d = new Date()) => {
    return d.toISOString().slice(0, 10);
  }
};


/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
   DATABASE â€” IndexedDB Wrapper
   â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
const DB = {
  db: null,
  DB_NAME: 'SecurityCheckpointDB',
  DB_VERSION: 3,

  async init() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.DB_NAME, this.DB_VERSION);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        let visitorStore;

        if (!db.objectStoreNames.contains('visitors')) {
          visitorStore = db.createObjectStore('visitors', { keyPath: 'id' });
        } else {
          visitorStore = e.target.transaction.objectStore('visitors');
        }

        if (!visitorStore.indexNames.contains('status')) visitorStore.createIndex('status', 'status', { unique: false });
        if (!visitorStore.indexNames.contains('time_in')) visitorStore.createIndex('time_in', 'time_in', { unique: false });
        if (!visitorStore.indexNames.contains('visitor_name')) visitorStore.createIndex('visitor_name', 'visitor_name', { unique: false });
        if (!visitorStore.indexNames.contains('cell_no')) visitorStore.createIndex('cell_no', 'cell_no', { unique: false });
        if (!visitorStore.indexNames.contains('synced')) visitorStore.createIndex('synced', 'synced', { unique: false });
        if (!visitorStore.indexNames.contains('status_time_in')) visitorStore.createIndex('status_time_in', ['status', 'time_in'], { unique: false });

        if (!db.objectStoreNames.contains('users')) {
          db.createObjectStore('users', { keyPath: 'username' });
        }
        if (!db.objectStoreNames.contains('settings')) {
          db.createObjectStore('settings', { keyPath: 'key' });
        }
      };
      req.onsuccess = (e) => { this.db = e.target.result; resolve(); };
      req.onerror = (e) => reject(e.target.error);
    });
  },

  _tx(store, mode = 'readonly') {
    const tx = this.db.transaction(store, mode);
    return tx.objectStore(store);
  },

  async addVisitor(record) {
    return new Promise((resolve, reject) => {
      const store = this._tx('visitors', 'readwrite');
      const req = store.put(record);
      req.onsuccess = () => resolve(record);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async getVisitor(id) {
    return new Promise((resolve, reject) => {
      const store = this._tx('visitors');
      const req = store.get(id);
      req.onsuccess = () => resolve(req.result);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async getAllVisitors() {
    return new Promise((resolve, reject) => {
      const store = this._tx('visitors');
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async getOnSite() {
    return new Promise((resolve, reject) => {
      const store = this._tx('visitors');
      const idx = store.index('status');
      const req = idx.getAll('ON_SITE');
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async getByDateRange(start, end) {
    return new Promise((resolve, reject) => {
      const store = this._tx('visitors');
      const idx = store.index('time_in');
      const range = IDBKeyRange.bound(start, end);
      const req = idx.getAll(range);
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async getUnsynced() {
    return new Promise((resolve, reject) => {
      const store = this._tx('visitors');
      const idx = store.index('synced');
      const req = idx.getAll(false);
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async findActive(name, cell_no) {
    const onSite = await this.getOnSite();
    return onSite.find(v =>
      v.visitor_name.toLowerCase() === name.toLowerCase() &&
      v.cell_no.replace(/\s/g, '') === cell_no.replace(/\s/g, '')
    );
  },

  async search(query) {
    const all = await this.getOnSite();
    const q = query.toLowerCase().trim();
    if (!q) return all;
    return all.filter(v =>
      v.visitor_name.toLowerCase().includes(q) ||
      v.cell_no.includes(q) ||
      (v.company || '').toLowerCase().includes(q) ||
      (v.vehicle_reg || '').toLowerCase().includes(q)
    );
  },

  async searchAll(query, records) {
    const q = query.toLowerCase().trim();
    if (!q) return records;
    return records.filter(v =>
      v.visitor_name.toLowerCase().includes(q) ||
      v.cell_no.includes(q) ||
      (v.company || '').toLowerCase().includes(q) ||
      (v.vehicle_reg || '').toLowerCase().includes(q)
    );
  },

  async deleteOlderThan(days) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);
    const cutoffIso = cutoff.toISOString();

    return new Promise((resolve, reject) => {
      const store = this._tx('visitors', 'readwrite');
      const idx = store.index('status_time_in');
      const range = IDBKeyRange.bound(['EXITED', '0000-01-01T00:00:00.000Z'], ['EXITED', cutoffIso]);
      let count = 0;
      const req = idx.openCursor(range);
      req.onsuccess = (e) => {
        const cursor = e.target.result;
        if (!cursor) return resolve(count);
        cursor.delete();
        count++;
        cursor.continue();
      };
      req.onerror = (e) => reject(e.target.error);
    });
  },

  // â”€â”€â”€ Settings â”€â”€â”€
  async getSetting(key) {
    return new Promise((resolve, reject) => {
      const store = this._tx('settings');
      const req = store.get(key);
      req.onsuccess = () => resolve(req.result ? req.result.value : null);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async setSetting(key, value) {
    return new Promise((resolve, reject) => {
      const store = this._tx('settings', 'readwrite');
      const req = store.put({ key, value });
      req.onsuccess = () => resolve();
      req.onerror = (e) => reject(e.target.error);
    });
  },

  // â”€â”€â”€ Users â”€â”€â”€
  async getUser(username) {
    return new Promise((resolve, reject) => {
      const store = this._tx('users');
      const req = store.get(username);
      req.onsuccess = () => resolve(req.result);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async getAllUsers() {
    return new Promise((resolve, reject) => {
      const store = this._tx('users');
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async putUser(user) {
    return new Promise((resolve, reject) => {
      const store = this._tx('users', 'readwrite');
      const req = store.put(user);
      req.onsuccess = () => resolve();
      req.onerror = (e) => reject(e.target.error);
    });
  },

  async deleteUser(username) {
    return new Promise((resolve, reject) => {
      const store = this._tx('users', 'readwrite');
      const req = store.delete(username);
      req.onsuccess = () => resolve();
      req.onerror = (e) => reject(e.target.error);
    });
  }
};




/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
   SYNC ENGINE â€” Static Token Auth
   â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
const Sync = {
  config: null,
  timer: null,
  backoff: 1000,
  maxBackoff: 60000,
  isOnline: navigator.onLine,

  async init() {
    const url = await DB.getSetting('sync_api_url');
    const token = await DB.getSetting('sync_api_token');
    if (url && token) this.config = { url, token };

    window.addEventListener('online', () => { this.isOnline = true; this.updateUI(); this.startSync(); });
    window.addEventListener('offline', () => { this.isOnline = false; this.updateUI(); });
    this.updateUI();

    if (this.config && this.isOnline) this.startSync();
  },

  getAuthHeader() {
    if (!this.config || !this.config.token) return {};
    // Support Frappe "token api_key:api_secret" and "Bearer xxx" formats
    const t = this.config.token.trim();
    if (t.toLowerCase().startsWith('token ') || t.toLowerCase().startsWith('bearer ')) {
      return { 'Authorization': t };
    }
    // Default: assume Frappe token format
    return { 'Authorization': 'token ' + t };
  },

  // Convert ISO datetime to MySQL-compatible format: YYYY-MM-DD HH:MM:SS
  toMySQL(iso) {
    if (!iso) return null;
    const d = new Date(iso);
    if (isNaN(d.getTime())) return null;
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  },

  // Prepare record for Frappe API â€” convert all datetime fields
  preparePayload(record) {
    const payload = { ...record };
    payload.time_in = this.toMySQL(payload.time_in);
    payload.time_out = this.toMySQL(payload.time_out);
    payload.created_at = this.toMySQL(payload.created_at);
    payload.updated_at = this.toMySQL(payload.updated_at);
    // Remove local-only fields that Frappe doesn't need
    delete payload.synced;
    delete payload.sync_error;
    return payload;
  },

  updateUI() {
    const badge = document.getElementById('sync-status-badge');
    if (!badge) return;
    if (!this.config) {
      badge.className = 'status-badge status-offline';
      badge.innerHTML = '<span class="pulse-dot red"></span>No Sync';
    } else if (this.isOnline) {
      badge.className = 'status-badge status-online';
      badge.innerHTML = '<span class="pulse-dot green"></span>Online';
    } else {
      badge.className = 'status-badge status-offline';
      badge.innerHTML = '<span class="pulse-dot red"></span>Offline';
    }
  },

  startSync() {
    if (this.timer) clearTimeout(this.timer);
    this.doSync();
  },

  async doSync() {
    if (!this.config || !this.isOnline) return;
    try {
      const unsynced = await DB.getUnsynced();
      if (unsynced.length === 0) {
        this.backoff = 30000;
        this.scheduleNext();
        return;
      }

      let corsBlocked = false;

      for (const record of unsynced) {
        try {
          const resp = await fetch(this.config.url, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...this.getAuthHeader()
            },
            body: JSON.stringify(this.preparePayload(record))
          });

          if (resp.ok) {
            record.synced = true;
            record.sync_error = null;
          } else {
            const errText = await resp.text().catch(() => '');
            record.sync_error = `HTTP ${resp.status}: ${errText.slice(0, 150)}`;
          }

          record.updated_at = T.now();
          await DB.addVisitor(record);
        } catch (err) {
          if (err instanceof TypeError && err.message.includes('Failed to fetch')) {
            record.sync_error = 'CORS blocked â€” server must allow this origin';
            corsBlocked = true;
          } else {
            record.sync_error = err.message;
          }
          record.updated_at = T.now();
          await DB.addVisitor(record);
          if (corsBlocked) break;
        }
      }

      if (corsBlocked) {
        this.backoff = this.maxBackoff;
        this.scheduleNext();
        App.toast('Sync blocked by CORS â€” configure server headers', 'error');
        return;
      }

      this.backoff = 5000;
      this.scheduleNext();
      await DB.setSetting('last_sync', T.now());
      App.toast('Sync complete', 'success');
    } catch (err) {
      console.warn('Sync error:', err.message);
      this.backoff = Math.min(this.backoff * 2, this.maxBackoff);
      this.scheduleNext();
    }
  },

  scheduleNext() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.doSync(), this.backoff);
  },

  async testConnection(url, token) {
    // Build auth header
    const t = (token || '').trim();
    let authHeader = {};
    if (t) {
      if (t.toLowerCase().startsWith('token ') || t.toLowerCase().startsWith('bearer ')) {
        authHeader = { 'Authorization': t };
      } else {
        authHeader = { 'Authorization': 'token ' + t };
      }
    }

    try {
      // Use POST since Frappe API endpoints typically only accept POST
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeader
        },
        body: JSON.stringify({ _test_connection: true })
      });
      // 401/403 = auth rejected; anything else (200, 400, 422, 500) = connection works
      if (resp.status === 401 || resp.status === 403) {
        return { ok: false, error: `Authentication failed (HTTP ${resp.status}). Check your API token.` };
      }
      return { ok: true, status: resp.status };
    } catch (err) {
      if (err instanceof TypeError && (
        err.message.includes('Failed to fetch') ||
        err.message.includes('NetworkError') ||
        err.message.includes('CORS')
      )) {
        return { ok: false, cors: true, error: 'CORS blocked â€” server must allow this origin' };
      }
      return { ok: false, error: err.message };
    }
  },

  async getSyncStats() {
    const all = await DB.getAllVisitors();
    const synced = all.filter(v => v.synced).length;
    const unsynced = all.filter(v => !v.synced).length;
    const failed = all.filter(v => v.sync_error).length;
    const lastSync = await DB.getSetting('last_sync');
    return { total: all.length, synced, unsynced, failed, lastSync };
  }
};


/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
   EXPORT ENGINE
   â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
const Export = {
  formatRecords(records) {
    return records.map(r => ({
      'Name': r.visitor_name,
      'Cell No': r.cell_no,
      'Company': r.company,
      'Vehicle Reg': r.vehicle_reg || '',
      'Time In': T.display(r.time_in),
      'Time Out': r.time_out ? T.display(r.time_out) : '',
      'Total Time': r.time_out ? T.duration(r.time_in, r.time_out) : (r.status === 'ON_SITE' ? 'On Site' : ''),
      'Status': r.status,
      'Notes': r.notes || ''
    }));
  },

  async exportXLSX(records, filename) {
    if (typeof XLSX === 'undefined') {
      App.toast('Excel library not loaded', 'error');
      return;
    }
    const data = this.formatRecords(records);
    const ws = XLSX.utils.json_to_sheet(data);

    // Column widths
    ws['!cols'] = [
      { wch: 22 }, { wch: 16 }, { wch: 20 }, { wch: 14 },
      { wch: 18 }, { wch: 18 }, { wch: 10 }, { wch: 10 }, { wch: 24 }
    ];

    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Visitor Log');
    XLSX.writeFile(wb, filename);
  },

  async exportCSV(records, filename) {
    const data = this.formatRecords(records);
    if (data.length === 0) { App.toast('No records to export', 'warning'); return; }
    const headers = Object.keys(data[0]);
    const csv = [
      headers.join(','),
      ...data.map(row => headers.map(h => `"${(row[h] || '').toString().replace(/"/g, '""')}"`).join(','))
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  }
};


/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
   MAIN APPLICATION
   â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
const App = {
  currentView: 'dashboard',
  currentUser: null,
  pendingCheckin: null,
  pendingCheckout: null,
  pendingForcedPinUser: null,
  logFilter: 'today',
  clockInterval: null,
  refreshInterval: null,

  // â”€â”€â”€ INIT â”€â”€â”€
  async init() {
    try {
      await DB.init();
      await this.ensureDefaultAdmin();
      await this.migrateLegacyPins();
      await Sync.init();
      await this.loadSettings();
      this.bindEvents();
      this.checkSession();

      // Dismiss loading
      setTimeout(() => {
        const loader = document.getElementById('app-loading');
        loader.classList.add('fade-out');
        setTimeout(() => loader.classList.add('d-none'), 400);
      }, 600);
    } catch (err) {
      console.error('Init error:', err);
      document.getElementById('app-loading').innerHTML =
        '<div class="app-init-error">' +
        '<i class="bi bi-exclamation-triangle app-init-error-icon"></i>' +
        'Failed to initialize database.<br><small>Please clear site data and reload.</small></div>';
    }
  },

  async ensureDefaultAdmin() {
    const admin = await DB.getUser('admin');
    if (!admin) {
      await DB.putUser({
        username: 'admin',
        pin_hash: await Auth.hashPin('1234'),
        role: 'admin',
        created_at: T.now(),
        must_change_pin: true
      });
      return;
    }

    if (admin.pin === '1234' || admin.must_change_pin == null) {
      admin.must_change_pin = true;
      await DB.putUser(admin);
    }
  },

  async migrateLegacyPins() {
    const users = await DB.getAllUsers();
    for (const user of users) {
      if (user.pin_hash || !user.pin) continue;
      user.pin_hash = await Auth.hashPin(user.pin);
      delete user.pin;
      await DB.putUser(user);
    }
  },

  async loadSettings() {
    const gateName = await DB.getSetting('gate_name');
    if (gateName) {
      document.getElementById('topbar-gate-name').textContent = gateName;
      document.getElementById('login-gate-name').textContent = gateName;
    }
    const deviceEl = document.getElementById('device-id-display');
    if (deviceEl) deviceEl.textContent = 'Device: ' + getDeviceId();
  },

  // â”€â”€â”€ AUTH â”€â”€â”€
  checkSession() {
    const session = sessionStorage.getItem('sc_session');
    if (session) {
      try {
        this.currentUser = JSON.parse(session);
        this.showApp();
      } catch { this.showLogin(); }
    } else { this.showLogin(); }
  },

  showLogin() {
    document.getElementById('login-screen').hidden = false;
    document.getElementById('main-app').hidden = true;
    document.getElementById('login-user').value = '';
    document.getElementById('login-pass').value = '';
    document.getElementById('login-error').classList.add('d-none');
  },

  showApp() {
    document.getElementById('login-screen').hidden = true;
    document.getElementById('main-app').hidden = false;

    // Hide settings nav if guard
    const settingsNav = document.getElementById('nav-settings');
    if (this.currentUser && this.currentUser.role !== 'admin') {
      settingsNav.classList.add('d-none');
    } else {
      settingsNav.classList.remove('d-none');
    }

    this.navigate('dashboard');
    this.startClock();
    this.startAutoRefresh();
  },

  getLoginLockState() {
    const failedCount = parseInt(localStorage.getItem('sc_failed_count') || '0', 10);
    const lockUntil = parseInt(localStorage.getItem('sc_lock_until') || '0', 10);
    return { failedCount, lockUntil };
  },

  setLoginLockState(failedCount, lockUntil) {
    localStorage.setItem('sc_failed_count', String(failedCount));
    localStorage.setItem('sc_lock_until', String(lockUntil));
  },

  clearLoginLockState() {
    this.setLoginLockState(0, 0);
  },

  async authenticate(username, pin) {
    const user = await DB.getUser(username.toLowerCase());
    if (!user) return { ok: false };

    const inputHash = await Auth.hashPin(pin);
    const storedHash = user.pin_hash || (user.pin ? await Auth.hashPin(user.pin) : null);
    if (!storedHash || storedHash !== inputHash) return { ok: false };

    // If user still has legacy plain pin, remove it after successful auth.
    if (user.pin) {
      user.pin_hash = inputHash;
      delete user.pin;
      await DB.putUser(user);
    }

    this.currentUser = { username: user.username, role: user.role };
    if (user.must_change_pin) {
      this.pendingForcedPinUser = user.username;
      return { ok: true, forcePin: true };
    }
    sessionStorage.setItem('sc_session', JSON.stringify(this.currentUser));
    return { ok: true, forcePin: false };
  },

  showForcePinModal() {
    document.getElementById('force-pin-current').value = '';
    document.getElementById('force-pin-new').value = '';
    document.getElementById('force-pin-confirm').value = '';
    const error = document.getElementById('force-pin-error');
    error.classList.add('d-none');
    error.textContent = '';
    new bootstrap.Modal(document.getElementById('forcePinModal')).show();
  },

  async completeForcedPinChange() {
    const currentPin = document.getElementById('force-pin-current').value.trim();
    const newPin = document.getElementById('force-pin-new').value.trim();
    const confirmPin = document.getElementById('force-pin-confirm').value.trim();
    const error = document.getElementById('force-pin-error');
    const fail = (msg) => {
      error.textContent = msg;
      error.classList.remove('d-none');
    };

    if (!this.pendingForcedPinUser) return fail('No pending user.');
    if (!currentPin || !newPin || !confirmPin) return fail('All fields are required.');
    if (newPin.length < 6) return fail('New PIN must be at least 6 characters.');
    if (newPin !== confirmPin) return fail('New PIN and confirmation do not match.');

    const user = await DB.getUser(this.pendingForcedPinUser);
    if (!user) return fail('User account not found.');

    const currentHash = await Auth.hashPin(currentPin);
    const storedHash = user.pin_hash || (user.pin ? await Auth.hashPin(user.pin) : null);
    if (storedHash !== currentHash) return fail('Current PIN is incorrect.');

    user.pin_hash = await Auth.hashPin(newPin);
    delete user.pin;
    user.must_change_pin = false;
    await DB.putUser(user);

    bootstrap.Modal.getInstance(document.getElementById('forcePinModal'))?.hide();
    this.pendingForcedPinUser = null;
    sessionStorage.setItem('sc_session', JSON.stringify(this.currentUser));
    this.toast('Admin PIN updated', 'success');
    this.showApp();
  },

  lock() {
    sessionStorage.removeItem('sc_session');
    this.currentUser = null;
    this.pendingForcedPinUser = null;
    if (this.clockInterval) clearInterval(this.clockInterval);
    if (this.refreshInterval) clearInterval(this.refreshInterval);
    this.showLogin();
  },

  isAdmin() {
    return this.currentUser && this.currentUser.role === 'admin';
  },

  // â”€â”€â”€ NAVIGATION â”€â”€â”€
  navigate(view) {
    // Redirect guard from settings
    if (view === 'settings' && !this.isAdmin()) {
      view = 'dashboard';
      this.toast('Admin access required', 'warning');
    }

    this.currentView = view;
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    const target = document.getElementById('view-' + view);
    if (target) target.classList.add('active');

    document.querySelectorAll('.nav-item').forEach(n => {
      n.classList.toggle('active', n.dataset.view === view);
    });

    // Refresh view data
    switch (view) {
      case 'dashboard': this.refreshDashboard(); break;
      case 'checkin': this.resetCheckinForm(); break;
      case 'exit': this.refreshExitSearch(); break;
      case 'logs': this.refreshLogs(); break;
      case 'settings': this.refreshSettings(); break;
    }
  },

  // â”€â”€â”€ CLOCK â”€â”€â”€
  startClock() {
    const update = () => {
      const el = document.getElementById('ci-time-in');
      if (el) el.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    };
    update();
    this.clockInterval = setInterval(update, 1000);
  },

  startAutoRefresh() {
    this.refreshInterval = setInterval(() => {
      if (this.currentView === 'dashboard') this.refreshDashboard();
    }, 15000);
  },

  // â”€â”€â”€ DASHBOARD â”€â”€â”€
  async refreshDashboard() {
    const onSite = await DB.getOnSite();
    const todayLogs = await DB.getByDateRange(T.todayStart(), T.todayEnd());

    const exits = todayLogs.filter(v => v.status === 'EXITED');
    const avgMins = exits.length > 0
      ? Math.round(exits.reduce((sum, v) => sum + (v.total_minutes_on_site || 0), 0) / exits.length)
      : 0;

    document.getElementById('stat-onsite').textContent = onSite.length;
    document.getElementById('stat-checkins').textContent = todayLogs.length;
    document.getElementById('stat-exits').textContent = exits.length;
    document.getElementById('stat-avg-time').textContent = avgMins > 0 ? T.formatMins(avgMins) : '--';
    document.getElementById('onsite-count-label').textContent = onSite.length;

    const list = document.getElementById('onsite-list');
    if (onSite.length === 0) {
      list.innerHTML = '<div class="empty-state"><i class="bi bi-shield-check"></i><p>No visitors currently on site</p></div>';
      return;
    }

    // Sort by time_in descending
    onSite.sort((a, b) => new Date(b.time_in) - new Date(a.time_in));

    list.innerHTML = onSite.map(v => `
      <div class="visitor-item" data-action="checkout" data-id="${this.escAttr(v.id)}" role="button" tabindex="0">
        <div class="visitor-info">
          <div class="v-name">${this.esc(v.visitor_name)}</div>
          <div class="v-meta">
            <span><i class="bi bi-building"></i> ${this.esc(v.company)}</span>
            <span><i class="bi bi-clock"></i> ${T.formatMins(T.minsOnSite(v.time_in))}</span>
            ${v.vehicle_reg ? `<span><i class="bi bi-car-front"></i> ${this.esc(v.vehicle_reg)}</span>` : ''}
          </div>
        </div>
        <button class="btn btn-danger-soft btn-sm" data-action="checkout" data-id="${this.escAttr(v.id)}">
          <i class="bi bi-box-arrow-right"></i> Exit
        </button>
      </div>
    `).join('');
  },

  // â”€â”€â”€ CHECK-IN â”€â”€â”€
  resetCheckinForm() {
    document.getElementById('checkin-form').reset();
  },

  async handleCheckin(e) {
    e.preventDefault();

    const name = document.getElementById('ci-name').value.trim();
    const cell_no = document.getElementById('ci-cell').value.trim();
    const company = document.getElementById('ci-company').value.trim();
    const vehicle_reg = document.getElementById('ci-vehicle').value.trim();
    const notes = document.getElementById('ci-notes').value.trim();

    if (!name || !cell_no || !company) {
      this.toast('Please fill in all required fields', 'error');
      return;
    }

    // Check for active record
    const existing = await DB.findActive(name, cell_no);
    if (existing) {
      this.toast('This person is already on site!', 'warning');
      return;
    }

    this.pendingCheckin = { visitor_name: name, cell_no, company, vehicle_reg, notes };

    document.getElementById('confirm-checkin-body').innerHTML = `
      <div class="detail-row"><span class="detail-label">Name</span><span class="detail-value">${this.esc(name)}</span></div>
      <div class="detail-row"><span class="detail-label">Cell</span><span class="detail-value">${this.esc(cell_no)}</span></div>
      <div class="detail-row"><span class="detail-label">Company</span><span class="detail-value">${this.esc(company)}</span></div>
      ${vehicle_reg ? `<div class="detail-row"><span class="detail-label">Vehicle</span><span class="detail-value">${this.esc(vehicle_reg)}</span></div>` : ''}
      <div class="detail-row"><span class="detail-label">Time In</span><span class="detail-value">${T.displayTime(T.now())}</span></div>
    `;

    new bootstrap.Modal(document.getElementById('confirmCheckinModal')).show();
  },

  async confirmCheckin() {
    if (!this.pendingCheckin) return;
    const d = this.pendingCheckin;

    const record = {
      id: uuid(),
      visitor_name: d.visitor_name,
      cell_no: d.cell_no,
      company: d.company,
      vehicle_reg: d.vehicle_reg || '',
      time_in: T.now(),
      time_out: null,
      status: 'ON_SITE',
      total_minutes_on_site: null,
      notes: d.notes || '',
      created_at: T.now(),
      updated_at: T.now(),
      device_id: getDeviceId(),
      synced: false,
      sync_error: null,
      version: 1
    };

    await DB.addVisitor(record);
    bootstrap.Modal.getInstance(document.getElementById('confirmCheckinModal'))?.hide();
    this.pendingCheckin = null;
    this.resetCheckinForm();
    this.toast(`${d.visitor_name} checked in successfully`, 'success');

    // Trigger sync if online
    if (Sync.isOnline && Sync.config) Sync.startSync();
  },

  // â”€â”€â”€ CHECK-OUT â”€â”€â”€
  async showCheckoutPrompt(id) {
    const record = await DB.getVisitor(id);
    if (!record || record.status !== 'ON_SITE') {
      this.toast('Record not found or already exited', 'error');
      return;
    }

    this.pendingCheckout = record;
    const duration = T.formatMins(T.minsOnSite(record.time_in));

    document.getElementById('confirm-checkout-body').innerHTML = `
      <div class="detail-row"><span class="detail-label">Name</span><span class="detail-value">${this.esc(record.visitor_name)}</span></div>
      <div class="detail-row"><span class="detail-label">Company</span><span class="detail-value">${this.esc(record.company)}</span></div>
      <div class="detail-row"><span class="detail-label">Time In</span><span class="detail-value">${T.display(record.time_in)}</span></div>
      <div class="detail-row"><span class="detail-label">Time Out</span><span class="detail-value">${T.displayTime(T.now())}</span></div>
      <div class="time-display mt-3">${duration} on site</div>
    `;

    new bootstrap.Modal(document.getElementById('confirmCheckoutModal')).show();
  },

  async confirmCheckout() {
    if (!this.pendingCheckout) return;
    const record = this.pendingCheckout;

    record.time_out = T.now();
    record.status = 'EXITED';
    record.total_minutes_on_site = T.durationMins(record.time_in, record.time_out);
    record.updated_at = T.now();
    record.synced = false;
    record.version = (record.version || 1) + 1;

    await DB.addVisitor(record);
    bootstrap.Modal.getInstance(document.getElementById('confirmCheckoutModal'))?.hide();

    const name = record.visitor_name;
    const dur = T.duration(record.time_in, record.time_out);
    this.pendingCheckout = null;
    this.toast(`${name} checked out (${dur})`, 'success');
    this.refreshDashboard();

    if (Sync.isOnline && Sync.config) Sync.startSync();
  },

  // â”€â”€â”€ EXIT SEARCH â”€â”€â”€
  async refreshExitSearch() {
    const query = document.getElementById('exit-search')?.value || '';
    const results = await DB.search(query);

    const container = document.getElementById('exit-search-results');
    if (results.length === 0) {
      container.innerHTML = query
        ? '<div class="empty-state"><i class="bi bi-search"></i><p>No matching visitors on site</p></div>'
        : '<div class="empty-state"><i class="bi bi-shield-check"></i><p>No visitors currently on site<br><small class="text-muted">Search across all on-site visitors</small></p></div>';
      return;
    }

    container.innerHTML = results.map(v => `
      <div class="visitor-item">
        <div class="visitor-info">
          <div class="v-name">${this.esc(v.visitor_name)}</div>
          <div class="v-meta">
            <span><i class="bi bi-telephone"></i> ${this.esc(v.cell_no)}</span>
            <span><i class="bi bi-building"></i> ${this.esc(v.company)}</span>
            <span><i class="bi bi-clock"></i> ${T.formatMins(T.minsOnSite(v.time_in))}</span>
          </div>
        </div>
        <button class="btn btn-danger-soft btn-sm" data-action="checkout" data-id="${this.escAttr(v.id)}">
          <i class="bi bi-box-arrow-right me-1"></i>Exit
        </button>
      </div>
    `).join('');
  },

  // â”€â”€â”€ LOGS â”€â”€â”€
  async refreshLogs() {
    let start, end;
    const filter = this.logFilter;

    switch (filter) {
      case 'today': start = T.todayStart(); end = T.todayEnd(); break;
      case 'yesterday': start = T.yesterdayStart(); end = T.yesterdayEnd(); break;
      case 'week': start = T.weekStart(); end = T.todayEnd(); break;
      case 'custom':
        const from = document.getElementById('log-date-from').value;
        const to = document.getElementById('log-date-to').value;
        if (!from || !to) return;
        start = new Date(from + 'T00:00:00').toISOString();
        end = new Date(to + 'T23:59:59').toISOString();
        break;
    }

    let records = await DB.getByDateRange(start, end);
    const searchQuery = document.getElementById('log-search')?.value || '';
    if (searchQuery) records = await DB.searchAll(searchQuery, records);

    records.sort((a, b) => new Date(b.time_in) - new Date(a.time_in));

    const container = document.getElementById('logs-list');
    if (records.length === 0) {
      container.innerHTML = '<div class="empty-state"><i class="bi bi-journal-x"></i><p>No logs for this period</p></div>';
      return;
    }

    container.innerHTML = records.map(v => `
      <div class="visitor-item" data-action="detail" data-id="${this.escAttr(v.id)}" role="button" tabindex="0">
        <div class="visitor-info">
          <div class="v-name">${this.esc(v.visitor_name)}</div>
          <div class="v-meta">
            <span><i class="bi bi-building"></i> ${this.esc(v.company)}</span>
            <span><i class="bi bi-clock"></i> ${T.displayTime(v.time_in)}</span>
            <span>${v.time_out ? T.duration(v.time_in, v.time_out) : 'On Site'}</span>
            ${!v.synced ? '<span class="text-warning-custom"><i class="bi bi-cloud-slash"></i></span>' : ''}
          </div>
        </div>
        <span class="visitor-status ${v.status === 'ON_SITE' ? 'status-onsite' : 'status-exited'}">
          ${v.status === 'ON_SITE' ? 'On Site' : 'Exited'}
        </span>
      </div>
    `).join('');
  },

  async showVisitorDetail(id) {
    const v = await DB.getVisitor(id);
    if (!v) return;

    const body = document.getElementById('visitor-detail-body');
    body.innerHTML = `
      <div class="detail-row"><span class="detail-label">Name</span><span class="detail-value">${this.esc(v.visitor_name)}</span></div>
      <div class="detail-row"><span class="detail-label">Cell No</span><span class="detail-value">${this.esc(v.cell_no)}</span></div>
      <div class="detail-row"><span class="detail-label">Company</span><span class="detail-value">${this.esc(v.company)}</span></div>
      <div class="detail-row"><span class="detail-label">Vehicle Reg</span><span class="detail-value">${this.esc(v.vehicle_reg || '--')}</span></div>
      <div class="detail-row"><span class="detail-label">Time In</span><span class="detail-value">${T.display(v.time_in)}</span></div>
      <div class="detail-row"><span class="detail-label">Time Out</span><span class="detail-value">${v.time_out ? T.display(v.time_out) : '--'}</span></div>
      <div class="detail-row"><span class="detail-label">Duration</span><span class="detail-value">${v.time_out ? T.duration(v.time_in, v.time_out) : (v.status === 'ON_SITE' ? T.formatMins(T.minsOnSite(v.time_in)) + ' (ongoing)' : '--')}</span></div>
      <div class="detail-row"><span class="detail-label">Status</span><span class="detail-value"><span class="visitor-status ${v.status === 'ON_SITE' ? 'status-onsite' : 'status-exited'}">${v.status}</span></span></div>
      <div class="detail-row"><span class="detail-label">Notes</span><span class="detail-value">${this.esc(v.notes || '--')}</span></div>
      <div class="detail-row"><span class="detail-label">Synced</span><span class="detail-value">${v.synced ? '<span class="text-success-custom">Yes</span>' : '<span class="text-warning-custom">No</span>'}</span></div>
      ${v.sync_error ? `<div class="detail-row"><span class="detail-label">Sync Error</span><span class="detail-value text-danger-custom">${this.esc(v.sync_error)}</span></div>` : ''}
    `;

    const footer = document.getElementById('visitor-detail-footer');
    let actions = '';
    if (v.status === 'ON_SITE') {
      actions += `<button class="btn btn-danger-soft btn-sm" data-action="detail-checkout" data-id="${this.escAttr(v.id)}"><i class="bi bi-box-arrow-right me-1"></i>Mark Exit</button>`;
    }
    if (this.isAdmin()) {
      actions += `<button class="btn btn-outline-accent btn-sm" data-action="detail-edit" data-id="${this.escAttr(v.id)}"><i class="bi bi-pencil me-1"></i>Edit</button>`;
    }
    actions += `<button class="btn btn-ghost btn-sm" data-bs-dismiss="modal">Close</button>`;
    footer.innerHTML = actions;

    new bootstrap.Modal(document.getElementById('visitorDetailModal')).show();
  },

  // â”€â”€â”€ ADMIN EDIT â”€â”€â”€
  async showEditModal(id) {
    const v = await DB.getVisitor(id);
    if (!v) return;

    document.getElementById('edit-record-id').value = v.id;
    document.getElementById('edit-name').value = v.visitor_name;
    document.getElementById('edit-cell').value = v.cell_no;
    document.getElementById('edit-company').value = v.company;
    document.getElementById('edit-vehicle').value = v.vehicle_reg || '';
    document.getElementById('edit-time-in').value = T.localISO(new Date(v.time_in));
    document.getElementById('edit-time-out').value = v.time_out ? T.localISO(new Date(v.time_out)) : '';
    document.getElementById('edit-notes').value = v.notes || '';

    new bootstrap.Modal(document.getElementById('editTimeModal')).show();
  },

  async saveEdit() {
    const id = document.getElementById('edit-record-id').value;
    const v = await DB.getVisitor(id);
    if (!v) return;

    v.visitor_name = document.getElementById('edit-name').value.trim();
    v.cell_no = document.getElementById('edit-cell').value.trim();
    v.company = document.getElementById('edit-company').value.trim();
    v.vehicle_reg = document.getElementById('edit-vehicle').value.trim();
    v.notes = document.getElementById('edit-notes').value.trim();

    const time_inVal = document.getElementById('edit-time-in').value;
    const time_outVal = document.getElementById('edit-time-out').value;

    if (time_inVal) v.time_in = new Date(time_inVal).toISOString();
    if (time_outVal) {
      v.time_out = new Date(time_outVal).toISOString();
      v.status = 'EXITED';
      v.total_minutes_on_site = T.durationMins(v.time_in, v.time_out);
    }

    v.updated_at = T.now();
    v.synced = false;
    v.version = (v.version || 1) + 1;

    await DB.addVisitor(v);
    bootstrap.Modal.getInstance(document.getElementById('editTimeModal'))?.hide();
    this.toast('Record updated', 'success');
    this.refreshLogs();
    this.refreshDashboard();
  },

  // â”€â”€â”€ EXPORT â”€â”€â”€
  async exportToday() {
    const records = await DB.getByDateRange(T.todayStart(), T.todayEnd());
    if (records.length === 0) { this.toast('No records to export', 'warning'); return; }
    const gateName = (await DB.getSetting('gate_name')) || 'Gate';
    const filename = `VisitorLog_${T.toDateInput()}_${gateName.replace(/\s/g, '_')}.xlsx`;
    Export.exportXLSX(records, filename);
    this.toast('Export downloaded', 'success');
  },

  exportLogs() {
    // Set default dates
    document.getElementById('export-from').value = T.toDateInput();
    document.getElementById('export-to').value = T.toDateInput();
    new bootstrap.Modal(document.getElementById('exportModal')).show();
  },

  async doExport(format) {
    const from = document.getElementById('export-from').value;
    const to = document.getElementById('export-to').value;
    if (!from || !to) { this.toast('Select date range', 'error'); return; }

    const start = new Date(from + 'T00:00:00').toISOString();
    const end = new Date(to + 'T23:59:59').toISOString();
    const records = await DB.getByDateRange(start, end);

    if (records.length === 0) { this.toast('No records in range', 'warning'); return; }

    const gateName = (await DB.getSetting('gate_name')) || 'Gate';
    const filename = `VisitorLog_${from}_to_${to}_${gateName.replace(/\s/g, '_')}`;

    if (format === 'xlsx') {
      Export.exportXLSX(records, filename + '.xlsx');
    } else {
      Export.exportCSV(records, filename + '.csv');
    }

    bootstrap.Modal.getInstance(document.getElementById('exportModal'))?.hide();
    this.toast('Export downloaded', 'success');
  },

  // â”€â”€â”€ SETTINGS â”€â”€â”€
  async refreshSettings() {
    // Load settings
    const gateName = await DB.getSetting('gate_name');
    const apiUrl = await DB.getSetting('sync_api_url');
    const apiToken = await DB.getSetting('sync_api_token');
    const retention = await DB.getSetting('retention_days');

    if (gateName) document.getElementById('set-gate-name').value = gateName;
    if (apiUrl) document.getElementById('set-api-url').value = apiUrl;
    const tokenInput = document.getElementById('set-api-token');
    tokenInput.value = '';
    tokenInput.placeholder = apiToken ? 'Saved token (leave blank to keep current token)' : 'token api_key:api_secret';
    if (retention) document.getElementById('set-retention').value = retention;

    // Users
    const users = await DB.getAllUsers();
    const userList = document.getElementById('user-list');
    userList.innerHTML = users.map(u => `
      <div class="setting-item">
        <div>
          <div class="si-label">${this.esc(u.username)}</div>
          <div class="si-desc">${u.role === 'admin' ? 'Administrator' : 'Guard'}</div>
        </div>
        <div class="d-flex gap-1">
          ${u.username !== 'admin' ? `<button class="btn btn-danger-soft btn-sm" data-action="remove-user" data-user="${this.escAttr(u.username)}"><i class="bi bi-trash"></i></button>` : ''}
          <button class="btn btn-ghost btn-sm" data-action="reset-user-pin" data-user="${this.escAttr(u.username)}"><i class="bi bi-key"></i></button>
        </div>
      </div>
    `).join('');

    // Sync stats
    const stats = await Sync.getSyncStats();
    document.getElementById('sync-stats').innerHTML = `
      Total records: ${stats.total} | Synced: ${stats.synced} | Pending: ${stats.unsynced} | Failed: ${stats.failed}
      ${stats.lastSync ? `<br>Last sync: ${T.display(stats.lastSync)}` : ''}
    `;
  },

  async saveSettings() {
    const gateName = document.getElementById('set-gate-name').value.trim();
    await DB.setSetting('gate_name', gateName);
    document.getElementById('topbar-gate-name').textContent = gateName || 'Checkpoint';
    document.getElementById('login-gate-name').textContent = gateName || 'Gate Control System';
    this.toast('Branding saved', 'success');
  },

  async saveSyncConfig() {
    const url = document.getElementById('set-api-url').value.trim();
    const enteredToken = document.getElementById('set-api-token').value.trim();
    const existingToken = await DB.getSetting('sync_api_token');
    const token = enteredToken || existingToken || '';

    await DB.setSetting('sync_api_url', url);
    await DB.setSetting('sync_api_token', token);

    Sync.config = (url && token) ? { url, token } : null;
    Sync.updateUI();
    this.toast('Sync configuration saved', 'success');
  },

  async testConnection() {
    const url = document.getElementById('set-api-url').value.trim();
    const token = document.getElementById('set-api-token').value.trim() || await DB.getSetting('sync_api_token') || '';
    const el = document.getElementById('sync-test-result');

    if (!url) { el.innerHTML = '<span class="text-danger-custom">Please enter an API endpoint URL</span>'; return; }
    if (!token) { el.innerHTML = '<span class="text-danger-custom">Please enter an API token</span>'; return; }

    el.innerHTML = '<span class="text-info-custom"><i class="bi bi-arrow-repeat spin me-1"></i>Testing connection...</span>';

    const result = await Sync.testConnection(url, token);

    if (result.ok) {
      el.innerHTML = `<span class="text-success-custom"><i class="bi bi-check-circle-fill me-1"></i>Connection successful (HTTP ${result.status})</span>`;
    } else if (result.cors) {
      const origin = window.location.origin;
      el.innerHTML = `
        <div class="text-danger-custom mb-2">
          <i class="bi bi-shield-exclamation me-1"></i><strong>CORS Policy Blocked</strong>
        </div>
        <div class="sync-cors-details">
          The server at <code class="text-accent">${this.esc(url)}</code>
          must return CORS headers allowing this origin.<br><br>
          <strong>For Frappe/ERPNext:</strong> Add to <code>site_config.json</code>:<br>
          <code class="sync-cors-code">
            "allow_cors": ["${this.esc(origin)}"]
          </code>
          Then restart: <code class="text-accent">bench restart</code>
        </div>
      `;
    } else {
      el.innerHTML = `<span class="text-danger-custom"><i class="bi bi-x-circle-fill me-1"></i>Connection failed: ${result.error}</span>`;
    }
  },

  async syncNow() {
    if (!Sync.config) { this.toast('No sync configured', 'warning'); return; }
    if (!Sync.isOnline) { this.toast('Device is offline', 'error'); return; }
    this.toast('Syncing...', 'info');
    await Sync.doSync();
    this.refreshSettings();
  },

  async retryFailed() {
    const all = await DB.getAllVisitors();
    let count = 0;
    for (const v of all) {
      if (v.sync_error) {
        v.sync_error = null;
        v.synced = false;
        await DB.addVisitor(v);
        count++;
      }
    }
    this.toast(`${count} records queued for retry`, 'info');
    if (Sync.isOnline && Sync.config) Sync.startSync();
  },

  async exportSyncDiag() {
    const all = await DB.getAllVisitors();
    const failed = all.filter(v => v.sync_error);
    const data = {
      device_id: getDeviceId(),
      timestamp: T.now(),
      config: Sync.config ? { url: Sync.config.url, hasToken: !!Sync.config.token } : null,
      online: Sync.isOnline,
      totalRecords: all.length,
      syncedCount: all.filter(v => v.synced).length,
      unsyncedCount: all.filter(v => !v.synced).length,
      failedCount: failed.length,
      failedRecords: failed.map(v => ({ id: v.id, visitor_name: v.visitor_name, error: v.sync_error }))
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `sync_diagnostics_${T.toDateInput()}.json`; a.click();
    URL.revokeObjectURL(url);
    this.toast('Diagnostics exported', 'success');
  },

  // â”€â”€â”€ USER MANAGEMENT â”€â”€â”€
  async addUser() {
    const username = document.getElementById('new-user-name').value.trim().toLowerCase();
    const pin = document.getElementById('new-user-pin').value.trim();

    if (!username || !pin) { this.toast('Username and PIN required', 'error'); return; }
    if (pin.length < 6) { this.toast('PIN must be at least 6 characters', 'error'); return; }
    if (!Auth.validUsername(username)) {
      this.toast('Username must be 3-24 chars: a-z, 0-9, dot, dash, underscore', 'error');
      return;
    }

    const existing = await DB.getUser(username);
    if (existing) { this.toast('Username already exists', 'error'); return; }

    await DB.putUser({
      username,
      pin_hash: await Auth.hashPin(pin),
      role: 'guard',
      created_at: T.now(),
      must_change_pin: false
    });
    bootstrap.Modal.getInstance(document.getElementById('addUserModal'))?.hide();
    document.getElementById('new-user-name').value = '';
    document.getElementById('new-user-pin').value = '';
    this.toast(`Guard "${username}" created`, 'success');
    this.refreshSettings();
  },

  async removeUser(username) {
    if (!confirm(`Remove guard "${username}"?`)) return;
    await DB.deleteUser(username);
    this.toast(`User "${username}" removed`, 'success');
    this.refreshSettings();
  },

  async resetUserPin(username) {
    const newPin = prompt(`Enter new PIN for "${username}":`);
    if (!newPin || newPin.length < 6) { this.toast('PIN must be at least 6 characters', 'error'); return; }
    const user = await DB.getUser(username);
    if (user) {
      user.pin_hash = await Auth.hashPin(newPin);
      delete user.pin;
      user.must_change_pin = false;
      await DB.putUser(user);
    }
    this.toast(`PIN reset for "${username}"`, 'success');
  },

  async archiveOld() {
    const days = parseInt(document.getElementById('set-retention').value) || 90;
    if (!confirm(`Archive records older than ${days} days?`)) return;
    const count = await DB.deleteOlderThan(days);
    await DB.setSetting('retention_days', days.toString());
    this.toast(`${count} records archived`, 'success');
  },

  // â”€â”€â”€ EVENT BINDING â”€â”€â”€
  bindEvents() {
    // Login
    document.getElementById('login-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const user = document.getElementById('login-user').value.trim();
      const pass = document.getElementById('login-pass').value;
      const errEl = document.getElementById('login-error');

      const { failedCount, lockUntil } = this.getLoginLockState();
      if (lockUntil > Date.now()) {
        const secs = Math.ceil((lockUntil - Date.now()) / 1000);
        errEl.textContent = `Too many attempts. Try again in ${secs}s.`;
        errEl.classList.remove('d-none');
        return;
      }

      const result = await this.authenticate(user, pass);
      if (result.ok) {
        this.clearLoginLockState();
        errEl.classList.add('d-none');
        if (result.forcePin) {
          this.showForcePinModal();
          return;
        }
        this.showApp();
      } else {
        const nextCount = failedCount + 1;
        if (nextCount >= 5) {
          const nextLockUntil = Date.now() + 60000;
          this.setLoginLockState(0, nextLockUntil);
          errEl.textContent = 'Too many failed attempts. Login locked for 60 seconds.';
        } else {
          this.setLoginLockState(nextCount, 0);
          errEl.textContent = `Invalid credentials. ${5 - nextCount} attempts remaining before lockout.`;
        }
        errEl.classList.remove('d-none');
        document.getElementById('login-pass').value = '';
      }
    });

    // Lock
    document.getElementById('btn-lock').addEventListener('click', () => this.lock());
    document.getElementById('btn-new-entry').addEventListener('click', () => this.navigate('checkin'));
    document.getElementById('btn-export-today').addEventListener('click', () => this.exportToday());
    document.getElementById('btn-export-logs').addEventListener('click', () => this.exportLogs());
    document.getElementById('btn-save-branding').addEventListener('click', () => this.saveSettings());
    document.getElementById('btn-test-connection').addEventListener('click', () => this.testConnection());
    document.getElementById('btn-save-sync').addEventListener('click', () => this.saveSyncConfig());
    document.getElementById('btn-sync-now').addEventListener('click', () => this.syncNow());
    document.getElementById('btn-retry-failed').addEventListener('click', () => this.retryFailed());
    document.getElementById('btn-export-sync-diag').addEventListener('click', () => this.exportSyncDiag());
    document.getElementById('btn-archive-old').addEventListener('click', () => this.archiveOld());
    document.getElementById('btn-add-user').addEventListener('click', () => this.addUser());
    document.getElementById('btn-save-edit').addEventListener('click', () => this.saveEdit());
    document.getElementById('btn-do-export-xlsx').addEventListener('click', () => this.doExport('xlsx'));
    document.getElementById('btn-do-export-csv').addEventListener('click', () => this.doExport('csv'));

    // Check-in form
    document.getElementById('checkin-form').addEventListener('submit', (e) => this.handleCheckin(e));

    // Confirm actions
    document.getElementById('btn-confirm-checkin').addEventListener('click', () => this.confirmCheckin());
    document.getElementById('btn-confirm-checkout').addEventListener('click', () => this.confirmCheckout());
    document.getElementById('btn-force-pin-save').addEventListener('click', () => this.completeForcedPinChange());

    document.querySelectorAll('.nav-item[data-view]').forEach((button) => {
      button.addEventListener('click', () => this.navigate(button.dataset.view));
    });

    document.getElementById('onsite-list').addEventListener('click', (e) => {
      const actionEl = e.target.closest('[data-action="checkout"]');
      if (!actionEl) return;
      const id = actionEl.dataset.id;
      if (id) this.showCheckoutPrompt(id);
    });

    document.getElementById('exit-search-results').addEventListener('click', (e) => {
      const actionEl = e.target.closest('[data-action="checkout"]');
      if (!actionEl) return;
      const id = actionEl.dataset.id;
      if (id) this.showCheckoutPrompt(id);
    });

    document.getElementById('logs-list').addEventListener('click', (e) => {
      const detailEl = e.target.closest('[data-action="detail"]');
      if (!detailEl) return;
      const id = detailEl.dataset.id;
      if (id) this.showVisitorDetail(id);
    });

    document.getElementById('visitor-detail-footer').addEventListener('click', (e) => {
      const actionEl = e.target.closest('[data-action]');
      if (!actionEl) return;
      const action = actionEl.dataset.action;
      const id = actionEl.dataset.id;
      if (!id) return;
      bootstrap.Modal.getInstance(document.getElementById('visitorDetailModal'))?.hide();
      if (action === 'detail-checkout') this.showCheckoutPrompt(id);
      if (action === 'detail-edit') this.showEditModal(id);
    });

    document.getElementById('user-list').addEventListener('click', (e) => {
      const actionEl = e.target.closest('[data-action]');
      if (!actionEl) return;
      const action = actionEl.dataset.action;
      const username = actionEl.dataset.user;
      if (!username) return;
      if (action === 'remove-user') this.removeUser(username);
      if (action === 'reset-user-pin') this.resetUserPin(username);
    });

    // Exit search with debounce
    let searchTimeout;
    document.getElementById('exit-search').addEventListener('input', () => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => this.refreshExitSearch(), 300);
    });

    // Log search with debounce
    let logSearchTimeout;
    document.getElementById('log-search').addEventListener('input', () => {
      clearTimeout(logSearchTimeout);
      logSearchTimeout = setTimeout(() => this.refreshLogs(), 300);
    });

    // Log filters
    document.querySelectorAll('.filter-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        this.logFilter = pill.dataset.filter;

        const customRange = document.getElementById('custom-date-range');
        if (this.logFilter === 'custom') {
          customRange.classList.remove('d-none');
        } else {
          customRange.classList.add('d-none');
          this.refreshLogs();
        }
      });
    });

    // Custom date range
    document.getElementById('log-date-from').addEventListener('change', () => this.refreshLogs());
    document.getElementById('log-date-to').addEventListener('change', () => this.refreshLogs());
  },

  // â”€â”€â”€ TOAST â”€â”€â”€
  toast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const icons = { success: 'check-circle-fill', error: 'x-circle-fill', warning: 'exclamation-triangle-fill', info: 'info-circle-fill' };
    const toast = document.createElement('div');
    toast.className = `sc-toast toast-${type}`;
    toast.innerHTML = `<i class="bi bi-${icons[type] || icons.info}"></i><span>${this.esc(message)}</span>`;
    container.appendChild(toast);
    requestAnimationFrame(() => { requestAnimationFrame(() => toast.classList.add('show')); });
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  },

  // â”€â”€â”€ ESCAPE HTML â”€â”€â”€
  esc(str) {
    if (!str) return '';
    const el = document.createElement('span');
    el.textContent = str;
    return el.innerHTML;
  },

  escAttr(str) {
    return this.esc(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
};

// â”€â”€â”€ SERVICE WORKER REGISTRATION â”€â”€â”€
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(err => {
    console.warn('SW registration failed:', err);
  });
}

// â”€â”€â”€ BOOT â”€â”€â”€
document.addEventListener('DOMContentLoaded', () => App.init());
