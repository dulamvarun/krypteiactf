/**
 * KRYPTEIA CTF — Live Excel Leaderboard Client
 * Subscribes to real-time Excel updates via Server-Sent Events (SSE)
 * with automatic polling fallback.
 */

(function () {
  'use strict';

  // DOM Elements
  const podiumContainer = document.getElementById('podium-container');
  const leaderboardBody = document.getElementById('leaderboard-body');
  const teamCountEl = document.getElementById('team-count');
  const syncStatusText = document.getElementById('sync-status-text');
  const syncIndicatorDot = document.getElementById('sync-dot');
  const lastSyncTimeEl = document.getElementById('last-sync-time');
  const searchInput = document.getElementById('search-input');
  const refreshBtn = document.getElementById('refresh-btn');

  // State
  let currentTeams = [];
  let lastUpdatedTime = null;
  let previousScores = new Map();
  let eventSource = null;
  let isSSEConnected = false;
  let pollInterval = null;

  /**
   * Format numbers with commas (e.g. 1,450)
   */
  function formatPoints(pts) {
    if (typeof pts !== 'number') {
      const n = parseFloat(pts);
      if (isNaN(n)) return '0';
      return Math.round(n).toLocaleString('en-US');
    }
    return Math.round(pts).toLocaleString('en-US');
  }

  /**
   * Escape HTML to prevent injection
   */
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Update the relative sync time display
   */
  function updateSyncTimeLabel() {
    if (!lastUpdatedTime) return;
    const date = new Date(lastUpdatedTime);
    const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    if (lastSyncTimeEl) {
      lastSyncTimeEl.textContent = `Synced: ${timeStr}`;
    }
  }

  /**
   * Render Top 3 Highlight Cards
   */
  function renderPodium(teams) {
    if (!podiumContainer) return;

    if (!teams || teams.length === 0) {
      podiumContainer.innerHTML = '';
      return;
    }

    const topThree = teams.slice(0, 3);
    const medals = [
      { rank: 1, label: '🥇 1st Place', tier: 'Gold Tier', css: 'rank-1' },
      { rank: 2, label: '🥈 2nd Place', tier: 'Silver Tier', css: 'rank-2' },
      { rank: 3, label: '🥉 3rd Place', tier: 'Bronze Tier', css: 'rank-3' }
    ];

    const cardsHtml = topThree.map((team, idx) => {
      const m = medals[idx];
      return `
        <article class="podium-card ${m.css}">
          <div class="podium-top">
            <span class="medal-badge">${m.label}</span>
            <span class="rank-tier-tag">${m.tier}</span>
          </div>
          <div class="podium-team" title="${escapeHtml(team.teamName)}">${escapeHtml(team.teamName)}</div>
          <div class="podium-score">
            <span class="score-num">${formatPoints(team.points)}</span>
            <span class="score-unit">PTS</span>
          </div>
        </article>
      `;
    }).join('');

    podiumContainer.innerHTML = cardsHtml;
  }

  /**
   * Render the Two-Column Leaderboard Table
   */
  function renderTable(teams) {
    if (!leaderboardBody) return;

    const query = (searchInput ? searchInput.value : '').trim().toLowerCase();
    const filtered = query
      ? teams.filter(t => t.teamName.toLowerCase().includes(query))
      : teams;

    if (teamCountEl) {
      teamCountEl.textContent = `${teams.length} ${teams.length === 1 ? 'Team' : 'Teams'}`;
    }

    if (filtered.length === 0) {
      leaderboardBody.innerHTML = `
        <tr>
          <td colspan="2" class="state-box">
            ${query ? 'No matching teams found for "' + escapeHtml(query) + '"' : 'No teams found in leaderboard.xlsx'}
          </td>
        </tr>
      `;
      return;
    }

    const rowsHtml = filtered.map((team) => {
      let rankRowClass = '';
      let rankBadgeContent = `#${team.rank}`;

      if (team.rank === 1) {
        rankRowClass = 'row-rank-1';
        rankBadgeContent = '🥇 1';
      } else if (team.rank === 2) {
        rankRowClass = 'row-rank-2';
        rankBadgeContent = '🥈 2';
      } else if (team.rank === 3) {
        rankRowClass = 'row-rank-3';
        rankBadgeContent = '🥉 3';
      }

      // Check for score change to add flash animation
      const prev = previousScores.get(team.teamName);
      const hasChanged = prev !== undefined && prev !== team.points;
      const flashClass = hasChanged ? 'flash-update' : '';

      return `
        <tr class="${rankRowClass} ${flashClass}" data-team="${escapeHtml(team.teamName)}">
          <td class="col-team">
            <div class="team-cell">
              <span class="rank-badge">${rankBadgeContent}</span>
              <span class="team-title">${escapeHtml(team.teamName)}</span>
            </div>
          </td>
          <td class="col-points">
            <span class="points-val">${formatPoints(team.points)}</span>
            <span class="points-pts">PTS</span>
          </td>
        </tr>
      `;
    }).join('');

    leaderboardBody.innerHTML = rowsHtml;

    // Cache current scores for future change detection
    previousScores.clear();
    for (const t of teams) {
      previousScores.set(t.teamName, t.points);
    }
  }

  /**
   * Apply data payload from server
   */
  function applyLeaderboardData(data) {
    if (!data || !Array.isArray(data.teams)) return;

    currentTeams = data.teams;
    lastUpdatedTime = data.lastUpdated || new Date().toISOString();

    renderPodium(currentTeams);
    renderTable(currentTeams);
    updateSyncTimeLabel();

    if (syncStatusText) {
      syncStatusText.textContent = 'Excel Connected';
    }
    if (syncIndicatorDot) {
      syncIndicatorDot.style.backgroundColor = 'var(--neon-green)';
    }
  }

  /**
   * Fetch leaderboard via HTTP REST
   */
  async function fetchLeaderboard() {
    try {
      const res = await fetch('/api/leaderboard/sheet?_t=' + Date.now());
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const json = await res.json();
      applyLeaderboardData(json);
    } catch (err) {
      console.warn('[Leaderboard] Polling fetch error:', err.message);
      if (syncStatusText && !isSSEConnected) {
        syncStatusText.textContent = 'Syncing...';
      }
    }
  }

  /**
   * Establish Server-Sent Events (SSE) Stream
   */
  function initSSE() {
    if (!window.EventSource) {
      console.warn('[Leaderboard] SSE not supported, falling back to polling.');
      startPolling();
      return;
    }

    try {
      if (eventSource) {
        eventSource.close();
      }

      eventSource = new EventSource('/api/leaderboard/stream');

      eventSource.addEventListener('leaderboard_update', (event) => {
        try {
          const data = JSON.parse(event.data);
          isSSEConnected = true;
          applyLeaderboardData(data);
        } catch (err) {
          console.error('[Leaderboard] SSE parse error:', err);
        }
      });

      eventSource.onopen = () => {
        isSSEConnected = true;
        if (syncStatusText) syncStatusText.textContent = 'Excel Connected';
        if (syncIndicatorDot) syncIndicatorDot.style.backgroundColor = 'var(--neon-green)';
      };

      eventSource.onerror = () => {
        isSSEConnected = false;
        if (syncStatusText) syncStatusText.textContent = 'Reconnecting...';
        if (syncIndicatorDot) syncIndicatorDot.style.backgroundColor = 'var(--bronze-glow)';
      };
    } catch (err) {
      console.error('[Leaderboard] SSE setup error:', err);
      startPolling();
    }
  }

  /**
   * Fallback polling every 2.5 seconds
   */
  function startPolling() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(fetchLeaderboard, 2500);
  }

  // Event Listeners
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      renderTable(currentTeams);
    });
  }

  if (refreshBtn) {
    refreshBtn.addEventListener('click', async () => {
      refreshBtn.style.opacity = '0.5';
      await fetchLeaderboard();
      setTimeout(() => {
        refreshBtn.style.opacity = '1';
      }, 300);
    });
  }

  // Periodic display update for timestamp
  setInterval(updateSyncTimeLabel, 10000);

  // Initialize
  fetchLeaderboard();
  initSSE();
  startPolling(); // Keep light polling running as safety guarantee alongside SSE
})();
