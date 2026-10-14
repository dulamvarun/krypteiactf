// =====================================================================
// KRYPTEIA CTF — Admin Command Center Controller
// St. Peter's Engineering College Cyber Security Technical Club
// =====================================================================

(function () {
  'use strict';

  const state = {
    token: localStorage.getItem('krypteia_admin_token') || '',
    config: null,
    challenges: [],
    leaderboard: [],
    pollTimer: null,
    clockTimer: null
  };

  // DOM Elements
  const el = {};

  function init() {
    cacheElements();
    setupEventListeners();
    startLiveISTClock();
    checkAuthStatus();
  }

  function cacheElements() {
    el.loginView = document.getElementById('login-view');
    el.dashboardView = document.getElementById('dashboard-view');
    el.loginForm = document.getElementById('admin-login-form');
    el.adminIdInput = document.getElementById('admin-id-input');
    el.adminPassInput = document.getElementById('admin-pass-input');
    el.loginFeedback = document.getElementById('login-feedback');
    el.loginSubmitBtn = document.getElementById('login-submit-btn');

    el.adminBadge = document.getElementById('admin-badge');
    el.adminIdLabel = document.getElementById('admin-id-label');
    el.adminLogoutBtn = document.getElementById('admin-logout-btn');
    el.liveIstClock = document.getElementById('live-ist-clock');

    // Metrics
    el.metricArenaStatus = document.getElementById('metric-arena-status');
    el.metricChallengesRatio = document.getElementById('metric-challenges-ratio');
    el.metricTeamsCount = document.getElementById('metric-teams-count');
    el.metricSolvesCount = document.getElementById('metric-solves-count');

    // Timer Section
    el.currentStateText = document.getElementById('current-state-text');
    el.dispStartIst = document.getElementById('disp-start-ist');
    el.dispUserView = document.getElementById('disp-user-view');
    el.dispTimerDiff = document.getElementById('disp-timer-diff');
    el.timerForm = document.getElementById('timer-form');
    el.startTimeInput = document.getElementById('start-time-input');
    el.btnSaveTimer = document.getElementById('btn-save-timer');
    el.currentStatusBadgeContainer = document.getElementById('current-status-badge-container');

    // Presets
    el.presetNow = document.getElementById('preset-now');
    el.preset5m = document.getElementById('preset-5m');
    el.preset15m = document.getElementById('preset-15m');
    el.preset30m = document.getElementById('preset-30m');
    el.preset1h = document.getElementById('preset-1h');

    // Challenges Section
    el.challengesTableBody = document.getElementById('challenges-table-body');
    el.btnUnlockAll = document.getElementById('btn-unlock-all');
    el.btnLockAll = document.getElementById('btn-lock-all');

    // Leaderboard Section
    el.leaderboardTableBody = document.getElementById('leaderboard-table-body');
    el.lbAdminSearch = document.getElementById('lb-admin-search');
    el.btnRefreshLb = document.getElementById('btn-refresh-lb');
    el.btnExportSheet = document.getElementById('btn-export-sheet');

    // Danger Zone
    el.btnResetData = document.getElementById('btn-reset-data');

    // Toasts
    el.toastContainer = document.getElementById('admin-toast-container');
  }

  function setupEventListeners() {
    // Login form
    if (el.loginForm) {
      el.loginForm.addEventListener('submit', handleLogin);
    }

    // Logout
    if (el.adminLogoutBtn) {
      el.adminLogoutBtn.addEventListener('click', handleLogout);
    }

    // Timer form
    if (el.timerForm) {
      el.timerForm.addEventListener('submit', handleTimerSubmit);
    }

    // Presets
    if (el.presetNow) el.presetNow.addEventListener('click', () => applyPresetOffset(-60));
    if (el.preset5m) el.preset5m.addEventListener('click', () => applyPresetOffset(5 * 60));
    if (el.preset15m) el.preset15m.addEventListener('click', () => applyPresetOffset(15 * 60));
    if (el.preset30m) el.preset30m.addEventListener('click', () => applyPresetOffset(30 * 60));
    if (el.preset1h) el.preset1h.addEventListener('click', () => applyPresetOffset(60 * 60));

    // Bulk challenge actions
    if (el.btnUnlockAll) {
      el.btnUnlockAll.addEventListener('click', () => handleBulkLock(false));
    }
    if (el.btnLockAll) {
      el.btnLockAll.addEventListener('click', () => handleBulkLock(true));
    }

    // Leaderboard
    if (el.btnRefreshLb) {
      el.btnRefreshLb.addEventListener('click', async () => {
        el.btnRefreshLb.disabled = true;
        await fetchAdminData();
        el.btnRefreshLb.disabled = false;
        showToast('Leaderboard refreshed', 'success');
      });
    }

    if (el.lbAdminSearch) {
      el.lbAdminSearch.addEventListener('input', (e) => {
        renderLeaderboard(e.target.value.toLowerCase().trim());
      });
    }

    if (el.btnExportSheet) {
      el.btnExportSheet.addEventListener('click', handleExportSheet);
    }

    // Danger reset
    if (el.btnResetData) {
      el.btnResetData.addEventListener('click', handleResetData);
    }
  }

  // --- API Client Helper ---
  async function adminFetch(endpoint, options = {}) {
    const headers = options.headers || {};
    if (state.token && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${state.token}`;
    }

    if (options.body && typeof options.body === 'object') {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(options.body);
    }

    const res = await fetch(endpoint, {
      method: options.method || 'GET',
      headers,
      body: options.body,
      credentials: 'same-origin'
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      throw new Error(data.error || data.message || `Request failed (${res.status})`);
    }

    return data;
  }

  // --- Live IST Clock ---
  function startLiveISTClock() {
    function updateClock() {
      const now = new Date();
      if (el.liveIstClock) {
        const istStr = now.toLocaleTimeString('en-IN', {
          timeZone: 'Asia/Kolkata',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: true
        });
        el.liveIstClock.textContent = `${istStr} IST`;
      }
      updateTimerDiffDisplay();
    }

    updateClock();
    state.clockTimer = setInterval(updateClock, 1000);
  }

  function updateTimerDiffDisplay() {
    if (!state.config || !state.config.startTime) return;

    const now = Date.now();
    const start = new Date(state.config.startTime).getTime();
    const diff = start - now;

    if (diff > 0) {
      // Event has not started yet
      const days = Math.floor(diff / (1000 * 60 * 60 * 24));
      const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((diff % (1000 * 60)) / 1000);

      const totalH = days * 24 + hours;
      const fmt = `-${String(totalH).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')} until kickoff`;
      if (el.dispTimerDiff) {
        el.dispTimerDiff.textContent = fmt;
        el.dispTimerDiff.style.color = 'var(--accent-amber)';
      }
    } else {
      // Event is Live / Elapsed
      const elapsed = Math.abs(diff);
      const hours = Math.floor(elapsed / (1000 * 60 * 60));
      const minutes = Math.floor((elapsed % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((elapsed % (1000 * 60)) / 1000);

      const fmt = `+${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')} elapsed live`;
      if (el.dispTimerDiff) {
        el.dispTimerDiff.textContent = fmt;
        el.dispTimerDiff.style.color = 'var(--accent-green)';
      }
    }
  }

  // --- Auth Checks ---
  async function checkAuthStatus() {
    try {
      const data = await adminFetch('/api/admin/status');
      if (data.authenticated) {
        onAuthenticated(data);
      } else {
        onUnauthenticated();
      }
    } catch (e) {
      onUnauthenticated();
    }
  }

  function onAuthenticated(data) {
    if (el.loginView) el.loginView.style.display = 'none';
    if (el.dashboardView) el.dashboardView.style.display = 'flex';
    if (el.adminBadge) el.adminBadge.style.display = 'inline-flex';
    if (el.adminLogoutBtn) el.adminLogoutBtn.style.display = 'inline-flex';

    if (data.admin && data.admin.id && el.adminIdLabel) {
      el.adminIdLabel.textContent = `Commander ${data.admin.id}`;
    }

    populateDashboard(data);
    startPolling();
  }

  function onUnauthenticated() {
    if (el.loginView) el.loginView.style.display = 'flex';
    if (el.dashboardView) el.dashboardView.style.display = 'none';
    if (el.adminBadge) el.adminBadge.style.display = 'none';
    if (el.adminLogoutBtn) el.adminLogoutBtn.style.display = 'none';

    stopPolling();
  }

  // --- Login Handler ---
  async function handleLogin(e) {
    e.preventDefault();
    const id = el.adminIdInput.value.trim();
    const password = el.adminPassInput.value;

    if (!id || !password) {
      showLoginFeedback('Please enter both Administrator ID and Password', 'error');
      return;
    }

    el.loginSubmitBtn.disabled = true;
    el.loginSubmitBtn.textContent = 'Verifying credentials...';

    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, password })
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Invalid administrator credentials');
      }

      state.token = data.token;
      localStorage.setItem('krypteia_admin_token', data.token);

      showLoginFeedback('Authentication verified! Loading console...', 'success');
      showToast(`Welcome Commander ${id}!`, 'success');

      setTimeout(async () => {
        await checkAuthStatus();
        el.loginSubmitBtn.disabled = false;
        el.loginSubmitBtn.textContent = '⚡ Authenticate & Enter Portal';
      }, 500);

    } catch (err) {
      showLoginFeedback(err.message, 'error');
      el.loginSubmitBtn.disabled = false;
      el.loginSubmitBtn.textContent = '⚡ Authenticate & Enter Portal';
    }
  }

  function showLoginFeedback(msg, type) {
    if (!el.loginFeedback) return;
    el.loginFeedback.className = `feedback-msg ${type}`;
    el.loginFeedback.textContent = msg;
    el.loginFeedback.style.display = 'block';
  }

  // --- Logout Handler ---
  async function handleLogout() {
    try {
      await adminFetch('/api/admin/logout', { method: 'POST' });
    } catch (_) {}
    state.token = '';
    localStorage.removeItem('krypteia_admin_token');
    showToast('Logged out of Admin Portal', 'info');
    onUnauthenticated();
  }

  // --- Live Polling ---
  function startPolling() {
    stopPolling();
    state.pollTimer = setInterval(fetchAdminData, 5000);
  }

  function stopPolling() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  async function fetchAdminData() {
    try {
      const data = await adminFetch('/api/admin/status');
      if (data.authenticated) {
        populateDashboard(data);
      } else {
        onUnauthenticated();
      }
    } catch (_) {
      // background polling silent
    }
  }

  // --- Dashboard Population ---
  function populateDashboard(data) {
    state.config = data.config;
    state.challenges = data.challenges || [];
    state.leaderboard = data.leaderboard || [];

    const isStarted = data.config.isStarted !== false;
    const isEnded = Boolean(data.config.isEnded);

    // 1. Metrics Row
    if (el.metricArenaStatus) {
      if (!isStarted) {
        el.metricArenaStatus.innerHTML = `<span class="status-pill upcoming"><span class="pulse-dot amber"></span> STANDBY (IST)</span>`;
      } else if (isEnded) {
        el.metricArenaStatus.innerHTML = `<span class="status-pill ended">COMPETITION ENDED</span>`;
      } else {
        el.metricArenaStatus.innerHTML = `<span class="status-pill live"><span class="pulse-dot"></span> LIVE</span>`;
      }
    }

    const lockedCount = state.challenges.filter(c => c.isLocked).length;
    const unlockedCount = state.challenges.length - lockedCount;
    if (el.metricChallengesRatio) {
      el.metricChallengesRatio.textContent = `${unlockedCount} 🔓 / ${lockedCount} 🔒 (${state.challenges.length})`;
    }

    if (el.metricTeamsCount) {
      el.metricTeamsCount.textContent = data.totalUsers || 0;
    }

    if (el.metricSolvesCount) {
      el.metricSolvesCount.textContent = data.totalSolves || 0;
    }

    // 2. Timer Overview
    if (el.currentStateText) {
      el.currentStateText.textContent = isStarted ? 'ARENA IS LIVE' : 'STANDBY (SCHEDULED)';
      el.currentStateText.style.color = isStarted ? 'var(--accent-green)' : 'var(--accent-amber)';
    }

    if (el.dispStartIst) {
      el.dispStartIst.textContent = data.config.startTimeIST || 'N/A';
    }

    if (el.dispUserView) {
      if (!isStarted) {
        el.dispUserView.innerHTML = `<span style="color:#ecc94b;">🔒 Standby Screen: "Event Has Not Started Yet" Countdown</span>`;
      } else {
        el.dispUserView.innerHTML = `<span style="color:#68d391;">⚡ Active Arena: Challenge Questions Open for Solves</span>`;
      }
    }

    if (el.currentStatusBadgeContainer) {
      if (!isStarted) {
        el.currentStatusBadgeContainer.innerHTML = `<span class="status-pill upcoming"><span class="pulse-dot amber"></span> NOT STARTED (WAITING ROOM ACTIVE)</span>`;
      } else if (isEnded) {
        el.currentStatusBadgeContainer.innerHTML = `<span class="status-pill ended">CONCLUDED</span>`;
      } else {
        el.currentStatusBadgeContainer.innerHTML = `<span class="status-pill live"><span class="pulse-dot"></span> ARENA LIVE</span>`;
      }
    }

    // Populate datetime-local input if not touched
    if (el.startTimeInput && !el.startTimeInput.dataset.modified) {
      const startIso = data.config.startTime;
      if (startIso) {
        const localDate = new Date(startIso);
        el.startTimeInput.value = formatForDateTimeLocal(localDate);
      }
    }

    // 3. Render Challenges Table
    renderChallengesTable();

    // 4. Render Leaderboard Table
    renderLeaderboard(el.lbAdminSearch ? el.lbAdminSearch.value.toLowerCase().trim() : '');
  }

  function formatForDateTimeLocal(date) {
    const pad = (n) => String(n).padStart(2, '0');
    const year = date.getFullYear();
    const month = pad(date.getMonth() + 1);
    const day = pad(date.getDate());
    const hours = pad(date.getHours());
    const minutes = pad(date.getMinutes());
    return `${year}-${month}-${day}T${hours}:${minutes}`;
  }

  // --- Timer Form & Preset Logic ---
  async function applyPresetOffset(secondsFromNow) {
    const targetDate = new Date(Date.now() + secondsFromNow * 1000);
    if (el.startTimeInput) {
      el.startTimeInput.value = formatForDateTimeLocal(targetDate);
      el.startTimeInput.dataset.modified = 'true';
    }

    // Instantly save
    await saveTimerIso(targetDate.toISOString());
  }

  async function handleTimerSubmit(e) {
    e.preventDefault();
    const val = el.startTimeInput.value;
    if (!val) {
      showToast('Please select a valid date & time', 'error');
      return;
    }

    const targetDate = new Date(val);
    if (isNaN(targetDate.getTime())) {
      showToast('Invalid date format', 'error');
      return;
    }

    await saveTimerIso(targetDate.toISOString());
  }

  async function saveTimerIso(isoString) {
    if (el.btnSaveTimer) el.btnSaveTimer.disabled = true;

    try {
      const data = await adminFetch('/api/admin/timer', {
        method: 'POST',
        body: { startTime: isoString }
      });

      state.config = data.config;
      showToast(`Competition Kickoff updated to: ${data.config.startTimeIST}`, 'success');
      await fetchAdminData();
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      if (el.btnSaveTimer) el.btnSaveTimer.disabled = false;
    }
  }

  // --- Dynamic Challenge Lock / Unlock ---
  function renderChallengesTable() {
    if (!el.challengesTableBody) return;

    el.challengesTableBody.innerHTML = '';

    if (state.challenges.length === 0) {
      el.challengesTableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 2rem; color: var(--text-muted);">No challenges loaded.</td></tr>`;
      return;
    }

    state.challenges.forEach(c => {
      const tr = document.createElement('tr');
      const isLocked = Boolean(c.isLocked);
      const diffClass = `diff-${(c.difficulty || 'easy').toLowerCase()}`;

      tr.innerHTML = `
        <td><span class="challenge-id-badge">${escapeHtml(c.id)}</span></td>
        <td><span style="font-size: 0.85rem; color: var(--text-secondary);">${escapeHtml(c.category)}</span></td>
        <td><strong style="color: #fff;">${escapeHtml(c.title)}</strong></td>
        <td><span class="diff-badge ${diffClass}">${escapeHtml(c.difficulty)}</span></td>
        <td><span class="mono" style="color: var(--accent-green); font-weight: 600;">${c.points} PTS</span></td>
        <td><span class="mono">${c.solveCount || 0} solves</span></td>
        <td>
          <span class="status-pill ${isLocked ? 'locked' : 'unlocked'}" id="status-pill-${c.id}">
            ${isLocked ? '🔒 LOCKED' : '🔓 UNLOCKED'}
          </span>
        </td>
        <td style="text-align: right;">
          <button 
            type="button" 
            class="btn ${isLocked ? 'btn-green' : 'btn-danger'} btn-sm" 
            id="toggle-btn-${c.id}"
          >
            ${isLocked ? '🔓 Unlock Question' : '🔒 Lock Question'}
          </button>
        </td>
      `;

      const toggleBtn = tr.querySelector(`#toggle-btn-${c.id}`);
      toggleBtn.addEventListener('click', () => handleToggleLock(c.id, !isLocked));

      el.challengesTableBody.appendChild(tr);
    });
  }

  async function handleToggleLock(challengeId, newLockState) {
    const btn = document.getElementById(`toggle-btn-${challengeId}`);
    if (btn) btn.disabled = true;

    try {
      const data = await adminFetch('/api/admin/challenge-lock', {
        method: 'POST',
        body: { challengeId, isLocked: newLockState }
      });

      const ch = state.challenges.find(item => item.id === challengeId);
      if (ch) {
        ch.isLocked = newLockState;
      }

      showToast(data.message, 'success');
      renderChallengesTable();
      updateMetricRatio();
    } catch (err) {
      showToast(err.message, 'error');
      if (btn) btn.disabled = false;
    }
  }

  async function handleBulkLock(isLocked) {
    const actionText = isLocked ? 'lock ALL questions' : 'unlock ALL questions';
    if (!confirm(`Are you sure you want to ${actionText}?`)) {
      return;
    }

    try {
      const data = await adminFetch('/api/admin/challenge-lock-all', {
        method: 'POST',
        body: { isLocked }
      });

      state.challenges.forEach(c => {
        c.isLocked = isLocked;
      });

      showToast(data.message, 'success');
      renderChallengesTable();
      updateMetricRatio();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  function updateMetricRatio() {
    const lockedCount = state.challenges.filter(c => c.isLocked).length;
    const unlockedCount = state.challenges.length - lockedCount;
    if (el.metricChallengesRatio) {
      el.metricChallengesRatio.textContent = `${unlockedCount} 🔓 / ${lockedCount} 🔒 (${state.challenges.length})`;
    }
  }

  // --- Leaderboard & Sheet Export ---
  function renderLeaderboard(query = '') {
    if (!el.leaderboardTableBody) return;

    el.leaderboardTableBody.innerHTML = '';

    let list = state.leaderboard;
    if (query) {
      list = list.filter(row => 
        (row.username || '').toLowerCase().includes(query) ||
        (row.email || '').toLowerCase().includes(query)
      );
    }

    if (list.length === 0) {
      el.leaderboardTableBody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; padding: 2.5rem; color: var(--text-muted);">
            No participant solves recorded yet. Standings will appear as teams submit flags.
          </td>
        </tr>
      `;
      return;
    }

    list.forEach(row => {
      const tr = document.createElement('tr');
      let rankBadge = `#${row.rank}`;
      if (row.rank === 1) rankBadge = '🥇 #1';
      else if (row.rank === 2) rankBadge = '🥈 #2';
      else if (row.rank === 3) rankBadge = '🥉 #3';

      tr.innerHTML = `
        <td><span class="mono" style="font-weight: 700; color: #fff;">${rankBadge}</span></td>
        <td><strong style="color: #fff;">${escapeHtml(row.username)}</strong></td>
        <td><span class="mono" style="color: var(--text-secondary); font-size: 0.82rem;">${escapeHtml(row.email)}</span></td>
        <td><span class="mono" style="color: var(--accent-cyan);">${row.solvedCount || 0}</span></td>
        <td><span class="mono" style="color: var(--accent-green); font-weight: 700;">${row.totalPoints || 0} PTS</span></td>
        <td><span class="mono" style="font-size: 0.82rem; color: var(--text-muted);">${escapeHtml(row.lastSolveTimeIST || 'None')}</span></td>
        <td><span class="mono" style="font-size: 0.82rem; color: var(--text-muted);">${escapeHtml(row.registeredAtIST || 'N/A')}</span></td>
      `;

      el.leaderboardTableBody.appendChild(tr);
    });
  }

  async function handleExportSheet() {
    el.btnExportSheet.disabled = true;
    el.btnExportSheet.textContent = 'Generating Sheet...';

    try {
      const res = await fetch('/api/admin/export-leaderboard', {
        headers: {
          'Authorization': `Bearer ${state.token}`
        },
        credentials: 'same-origin'
      });

      if (!res.ok) {
        throw new Error(`Export failed (${res.status})`);
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
      a.href = url;
      a.download = `Krypteia_CTF_Leaderboard_${timestamp}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      showToast('📥 Leaderboard spreadsheet downloaded successfully!', 'success');
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      el.btnExportSheet.disabled = false;
      el.btnExportSheet.textContent = '📥 Download Sheet (Excel / CSV)';
    }
  }

  // --- Danger Zone: Reset Leaderboard ---
  async function handleResetData() {
    const confirmation = prompt('⚠️ DESTRUCTIVE ACTION:\nThis will permanently clear all participant accounts, flag submissions, and leaderboard solves.\nType "RESET" to confirm:');
    if (confirmation !== 'RESET') {
      return;
    }

    try {
      const data = await adminFetch('/api/admin/reset-leaderboard', { method: 'POST' });
      showToast(data.message, 'success');
      await fetchAdminData();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  // --- Toast System ---
  function showToast(message, type = 'info') {
    if (!el.toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `admin-toast ${type}`;
    toast.textContent = message;

    el.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.25s ease';
      setTimeout(() => toast.remove(), 250);
    }, 4000);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Self-start on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
