// Krypteia CTF Application Logic
// St. Peter's Engineering College Cyber Security Technical Club

(function () {
  'use strict';

  // Application State
  const state = {
    currentUser: null,
    config: null,
    challenges: [],
    selectedCategory: 'all',
    statusFilter: 'all',
    searchQuery: '',
    currentModalChallengeId: null,
    leaderboardData: [],
    activeTab: 'challenges',
    timerInterval: null
  };

  // DOM Elements cache
  const elements = {};

  // Initialize App
  async function init() {
    cacheDomElements();
    setupEventListeners();
    handleHashChange();

    try {
      // Load config & user session
      await Promise.all([loadConfig(), loadUserSession()]);
      await loadChallenges();
      startCountdownTimer();
      startLivePolling();
    } catch (err) {
      console.error('Initialization error:', err);
      showToast('Error loading competition data', 'error');
    }
  }

  function cacheDomElements() {
    elements.navLinks = document.querySelectorAll('.nav-link');
    elements.authBtn = document.getElementById('auth-btn');
    elements.userPill = document.getElementById('user-pill');
    elements.userBadgeName = document.getElementById('user-badge-name');
    elements.userBadgeScore = document.getElementById('user-badge-score');
    
    // Views
    elements.challengesView = document.getElementById('challenges-view');
    elements.leaderboardView = document.getElementById('leaderboard-view');
    elements.rulesView = document.getElementById('rules-view');

    // Dashboard Banner
    elements.compTitle = document.getElementById('comp-title');
    elements.compStatusBadge = document.getElementById('comp-status-badge');
    elements.countdownTimer = document.getElementById('countdown-timer');
    elements.metricScore = document.getElementById('metric-score');
    elements.metricSolves = document.getElementById('metric-solves');
    elements.metricRank = document.getElementById('metric-rank');
    elements.metricTotal = document.getElementById('metric-total');

    // Filters & Grid
    elements.categoryPillsContainer = document.getElementById('category-pills');
    elements.searchInput = document.getElementById('search-input');
    elements.challengesGrid = document.getElementById('challenges-grid');
    elements.countAll = document.getElementById('count-all');
    elements.countUnsolved = document.getElementById('count-unsolved');
    elements.countSolved = document.getElementById('count-solved');
    elements.modalSolveBanner = document.getElementById('modal-solve-banner');

    // Pre-Event Standby Elements
    elements.preEventCard = document.getElementById('pre-event-card');
    elements.activeChallengesArea = document.getElementById('active-challenges-area');
    elements.preDays = document.getElementById('pre-days');
    elements.preHours = document.getElementById('pre-hours');
    elements.preMinutes = document.getElementById('pre-minutes');
    elements.preSeconds = document.getElementById('pre-seconds');
    elements.preStartTimeIst = document.getElementById('pre-start-time-ist');
    elements.preAuthNotice = document.getElementById('pre-auth-notice');
    elements.preAuthBtn = document.getElementById('pre-auth-btn');
    elements.modalLockedBanner = document.getElementById('modal-locked-banner');

    // Challenge Detail Modal
    elements.challengeModal = document.getElementById('challenge-modal');
    elements.modalCloseBtn = document.getElementById('modal-close-btn');
    elements.modalCategory = document.getElementById('modal-category');
    elements.modalDifficulty = document.getElementById('modal-difficulty');
    elements.modalPoints = document.getElementById('modal-points');
    elements.modalSolvesCount = document.getElementById('modal-solves-count');
    elements.modalSolvedStatus = document.getElementById('modal-solved-status');
    elements.modalTitle = document.getElementById('modal-title');
    elements.modalDescription = document.getElementById('modal-description');
    elements.modalAttachmentsSection = document.getElementById('modal-attachments-section');
    elements.modalAttachmentsList = document.getElementById('modal-attachments-list');
    elements.modalHintsSection = document.getElementById('modal-hints-section');
    elements.modalHintsList = document.getElementById('modal-hints-list');
    elements.flagForm = document.getElementById('flag-form');
    elements.flagInput = document.getElementById('flag-input');
    elements.flagSubmitBtn = document.getElementById('flag-submit-btn');
    elements.flagFeedback = document.getElementById('flag-feedback');
    elements.btnPrevChallenge = document.getElementById('btn-prev-challenge');
    elements.btnNextChallenge = document.getElementById('btn-next-challenge');

    // Auth Modal
    elements.authModal = document.getElementById('auth-modal');
    elements.authModalClose = document.getElementById('auth-modal-close');
    elements.loginTabBtn = document.getElementById('login-tab-btn');
    elements.registerTabBtn = document.getElementById('register-tab-btn');
    elements.loginForm = document.getElementById('login-form');
    elements.registerForm = document.getElementById('register-form');
    elements.authFeedback = document.getElementById('auth-feedback');

    // User Profile Modal
    elements.profileModal = document.getElementById('profile-modal');
    elements.profileModalClose = document.getElementById('profile-modal-close');
    elements.profileUsername = document.getElementById('profile-username');
    elements.profileEmail = document.getElementById('profile-email');
    elements.profileRank = document.getElementById('profile-rank');
    elements.profileScore = document.getElementById('profile-score');
    elements.profileSolvesCount = document.getElementById('profile-solves-count');
    elements.profileSolvesList = document.getElementById('profile-solves-list');
    elements.profileLogoutBtn = document.getElementById('profile-logout-btn');

    // Leaderboard
    elements.podiumContainer = document.getElementById('podium-container');
    elements.leaderboardTableBody = document.getElementById('leaderboard-tbody');
    elements.lbSearchInput = document.getElementById('lb-search-input');
    elements.lbRefreshBtn = document.getElementById('lb-refresh-btn');

    // Toast Container
    elements.toastContainer = document.getElementById('toast-container');
  }

  function setupEventListeners() {
    window.addEventListener('hashchange', handleHashChange);

    // Status filter clicks
    document.querySelectorAll('.status-pill').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const target = e.currentTarget;
        const status = target.getAttribute('data-status');
        if (status) {
          state.statusFilter = status;
          document.querySelectorAll('.status-pill').forEach(p => p.classList.remove('active'));
          target.classList.add('active');
          renderChallenges();
        }
      });
    });

    // Search challenges
    if (elements.searchInput) {
      elements.searchInput.addEventListener('input', (e) => {
        state.searchQuery = e.target.value.toLowerCase().trim();
        renderChallenges();
      });
    }

    // Pre-event register / login button
    if (elements.preAuthBtn) {
      elements.preAuthBtn.addEventListener('click', () => {
        openAuthModal('register');
      });
    }

    // Modal close events
    if (elements.modalCloseBtn) {
      elements.modalCloseBtn.addEventListener('click', closeChallengeModal);
    }
    if (elements.challengeModal) {
      elements.challengeModal.addEventListener('click', (e) => {
        if (e.target === elements.challengeModal) closeChallengeModal();
      });
    }

    // Auth modal events
    if (elements.authBtn) {
      elements.authBtn.addEventListener('click', openAuthModal);
    }
    if (elements.authModalClose) {
      elements.authModalClose.addEventListener('click', closeAuthModal);
    }
    if (elements.authModal) {
      elements.authModal.addEventListener('click', (e) => {
        if (e.target === elements.authModal) closeAuthModal();
      });
    }

    // Auth tab toggles
    if (elements.loginTabBtn) {
      elements.loginTabBtn.addEventListener('click', () => switchAuthTab('login'));
    }
    if (elements.registerTabBtn) {
      elements.registerTabBtn.addEventListener('click', () => switchAuthTab('register'));
    }

    // Auth form submissions
    if (elements.loginForm) {
      elements.loginForm.addEventListener('submit', handleLoginSubmit);
    }
    if (elements.registerForm) {
      elements.registerForm.addEventListener('submit', handleRegisterSubmit);
    }

    // Profile modal
    if (elements.userPill) {
      elements.userPill.addEventListener('click', openProfileModal);
    }
    if (elements.profileModalClose) {
      elements.profileModalClose.addEventListener('click', closeProfileModal);
    }
    if (elements.profileModal) {
      elements.profileModal.addEventListener('click', (e) => {
        if (e.target === elements.profileModal) closeProfileModal();
      });
    }
    if (elements.profileLogoutBtn) {
      elements.profileLogoutBtn.addEventListener('click', handleLogout);
    }

    // Flag Submission
    if (elements.flagForm) {
      elements.flagForm.addEventListener('submit', handleFlagSubmit);
    }

    // Challenge prev/next cycling
    if (elements.btnPrevChallenge) {
      elements.btnPrevChallenge.addEventListener('click', navigatePreviousChallenge);
    }
    if (elements.btnNextChallenge) {
      elements.btnNextChallenge.addEventListener('click', navigateNextChallenge);
    }

    // Leaderboard controls
    if (elements.lbRefreshBtn) {
      elements.lbRefreshBtn.addEventListener('click', async () => {
        elements.lbRefreshBtn.disabled = true;
        await loadLeaderboard();
        elements.lbRefreshBtn.disabled = false;
        showToast('Leaderboard refreshed', 'info');
      });
    }
    if (elements.lbSearchInput) {
      elements.lbSearchInput.addEventListener('input', (e) => {
        renderLeaderboard(e.target.value.toLowerCase().trim());
      });
    }

    // Global keyboard shortcuts (ESC to close modals)
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeChallengeModal();
        closeAuthModal();
        closeProfileModal();
      }
    });
  }

  // Routing via hash
  function handleHashChange() {
    const hash = window.location.hash.replace('#', '') || 'challenges';
    state.activeTab = hash;

    // Update navigation active states
    elements.navLinks.forEach(link => {
      const linkTab = link.getAttribute('data-tab');
      if (linkTab === hash) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    // Toggle views
    if (elements.challengesView) elements.challengesView.style.display = (hash === 'challenges') ? 'block' : 'none';
    if (elements.leaderboardView) elements.leaderboardView.style.display = (hash === 'leaderboard') ? 'block' : 'none';
    if (elements.rulesView) elements.rulesView.style.display = (hash === 'rules') ? 'block' : 'none';

    // Lazy load or refresh data based on tab
    if (hash === 'leaderboard') {
      loadLeaderboard();
    } else if (hash === 'challenges') {
      loadChallenges();
    } else if (hash === 'rules') {
      loadRules();
    }
  }

  // Config loader
  async function loadConfig() {
    try {
      const cfg = await API.getConfig();
      state.config = cfg;
      if (elements.compTitle) elements.compTitle.textContent = cfg.name || 'KRYPTEIA CTF';
      
      const isStarted = cfg.isStarted !== false;

      if (elements.compStatusBadge) {
        if (!isStarted) {
          elements.compStatusBadge.className = 'comp-badge upcoming';
          elements.compStatusBadge.innerHTML = `<span class="pulse-dot amber"></span> SCHEDULED (IST)`;
        } else if (cfg.isEnded) {
          elements.compStatusBadge.className = 'comp-badge ended';
          elements.compStatusBadge.textContent = 'ENDED';
        } else {
          elements.compStatusBadge.className = 'comp-badge live';
          elements.compStatusBadge.innerHTML = `<span class="pulse-dot"></span> LIVE`;
        }
      }

      if (elements.metricTotal) elements.metricTotal.textContent = cfg.totalChallenges || 8;

      // Toggle Pre-Event Standby Card vs Active Challenges Area
      if (elements.preEventCard && elements.activeChallengesArea) {
        if (!isStarted) {
          elements.preEventCard.style.display = 'block';
          elements.activeChallengesArea.style.display = 'none';
          if (elements.preStartTimeIst) elements.preStartTimeIst.textContent = cfg.startTimeIST || 'Scheduled';
          if (state.currentUser && elements.preAuthNotice) {
            elements.preAuthNotice.textContent = `Cadet "${state.currentUser.username}" is registered & authenticated. Ready for competition launch!`;
          }
          if (state.currentUser && elements.preAuthBtn) {
            elements.preAuthBtn.style.display = 'none';
          } else if (elements.preAuthBtn) {
            elements.preAuthBtn.style.display = 'inline-flex';
          }
        } else {
          elements.preEventCard.style.display = 'none';
          elements.activeChallengesArea.style.display = 'block';
        }
      }
    } catch (e) {
      console.warn('Config fetch fallback:', e);
    }
  }

  // Session loader
  async function loadUserSession() {
    try {
      const res = await API.getMe();
      if (res.user) {
        state.currentUser = res.user;
        updateUserUI();
      } else {
        state.currentUser = null;
        updateUserUI();
      }
    } catch (e) {
      state.currentUser = null;
      updateUserUI();
    }
  }

  function updateUserUI() {
    if (state.currentUser) {
      if (elements.authBtn) elements.authBtn.style.display = 'none';
      if (elements.userPill) elements.userPill.style.display = 'flex';
      if (elements.userBadgeName) elements.userBadgeName.textContent = state.currentUser.username;
      if (elements.userBadgeScore) elements.userBadgeScore.textContent = `${state.currentUser.totalPoints || 0} PTS`;

      if (elements.metricScore) elements.metricScore.textContent = `${state.currentUser.totalPoints || 0} PTS`;
      if (elements.metricSolves) elements.metricSolves.textContent = `${state.currentUser.solvedCount || 0}`;
      if (elements.metricRank) elements.metricRank.textContent = `#${state.currentUser.rank || 1}`;

      if (elements.preAuthNotice) {
        elements.preAuthNotice.textContent = `Cadet "${state.currentUser.username}" is registered & authenticated. Ready for competition launch!`;
      }
      if (elements.preAuthBtn) {
        elements.preAuthBtn.style.display = 'none';
      }
    } else {
      if (elements.authBtn) elements.authBtn.style.display = 'inline-flex';
      if (elements.userPill) elements.userPill.style.display = 'none';

      if (elements.metricScore) elements.metricScore.textContent = `0 PTS`;
      if (elements.metricSolves) elements.metricSolves.textContent = `0`;
      if (elements.metricRank) elements.metricRank.textContent = `-`;

      if (elements.preAuthNotice) {
        elements.preAuthNotice.textContent = 'You can register your account and log in now while waiting.';
      }
      if (elements.preAuthBtn) {
        elements.preAuthBtn.style.display = 'inline-flex';
      }
    }
  }

  // Countdown Timer (Handles both Pre-Event countdown and Live Remaining timer)
  function startCountdownTimer() {
    if (state.timerInterval) clearInterval(state.timerInterval);

    function update() {
      if (!state.config) return;

      const now = new Date().getTime();
      const isStarted = state.config.isStarted !== false;

      // Case 1: Event has not started yet -> Countdown to IST Kickoff
      if (!isStarted && state.config.startTime) {
        const start = new Date(state.config.startTime).getTime();
        const diff = start - now;

        if (diff <= 0) {
          // Event officially launched!
          state.config.isStarted = true;
          loadConfig();
          loadChallenges();
          showToast('🚀 KRYPTEIA CTF IS NOW LIVE! Arena Unlocked.', 'success');
          return;
        }

        const days = Math.floor(diff / (1000 * 60 * 60 * 24));
        const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diff % (1000 * 60)) / 1000);

        if (elements.preDays) elements.preDays.textContent = String(days).padStart(2, '0');
        if (elements.preHours) elements.preHours.textContent = String(hours).padStart(2, '0');
        if (elements.preMinutes) elements.preMinutes.textContent = String(minutes).padStart(2, '0');
        if (elements.preSeconds) elements.preSeconds.textContent = String(seconds).padStart(2, '0');

        const totalHours = days * 24 + hours;
        const fmt = `${String(totalHours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
        if (elements.countdownTimer) elements.countdownTimer.textContent = fmt;
        return;
      }

      // Case 2: Event is Live -> Countdown until end
      if (!state.config.endTime) {
        if (elements.countdownTimer) elements.countdownTimer.textContent = '21:00:00';
        return;
      }

      const end = new Date(state.config.endTime).getTime();
      const diff = end - now;

      if (diff <= 0) {
        if (elements.countdownTimer) elements.countdownTimer.textContent = 'COMPETITION ENDED';
        if (elements.compStatusBadge) elements.compStatusBadge.textContent = 'ENDED';
        return;
      }

      const hours = Math.floor(diff / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((diff % (1000 * 60)) / 1000);

      const fmt = `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
      if (elements.countdownTimer) elements.countdownTimer.textContent = fmt;
    }

    update();
    state.timerInterval = setInterval(update, 1000);
  }

  // Live dynamic polling to keep standings, solve counts, and ranks updated
  let livePollingInterval = null;
  function startLivePolling() {
    if (livePollingInterval) clearInterval(livePollingInterval);

    livePollingInterval = setInterval(async () => {
      if (document.hidden) return;

      try {
        if (state.activeTab === 'leaderboard') {
          await loadLeaderboard();
        } else if (state.activeTab === 'challenges') {
          // Poll config to detect timer changes from admin
          if (Math.random() < 0.3) {
            await loadConfig();
          }

          const res = await API.getChallenges();
          if (res && res.challenges) {
            let hasChanges = false;
            res.challenges.forEach(freshCh => {
              const current = state.challenges.find(c => c.id === freshCh.id);
              if (current) {
                if (current.solveCount !== freshCh.solveCount || current.isSolved !== freshCh.isSolved || current.isLocked !== freshCh.isLocked) {
                  current.solveCount = freshCh.solveCount;
                  current.isSolved = freshCh.isSolved;
                  current.isLocked = freshCh.isLocked;
                  hasChanges = true;
                }
              }
            });

            if (hasChanges) {
              renderChallenges();
              if (state.currentModalChallengeId && elements.modalSolvesCount) {
                const modalCh = state.challenges.find(c => c.id === state.currentModalChallengeId);
                if (modalCh) {
                  elements.modalSolvesCount.textContent = `${modalCh.solveCount || 0} solves`;
                }
              }
            }
          }
        }

        // Keep current participant stats & rank in sync
        if (state.currentUser) {
          const me = await API.getMe();
          if (me && me.user) {
            state.currentUser.totalPoints = me.user.totalPoints;
            state.currentUser.solvedCount = me.user.solvedCount;
            state.currentUser.rank = me.user.rank;
            updateUserUI();
          }
        }
      } catch (err) {
        // Background polling errors silent
      }
    }, 4000);
  }

  // Load Challenges
  async function loadChallenges() {
    try {
      const res = await API.getChallenges();
      state.challenges = res.challenges || [];
      renderCategoryFilters();
      renderChallenges();

      // Update solve count in banner
      if (state.currentUser && elements.metricSolves) {
        elements.metricSolves.textContent = `${res.solvedCount || 0}`;
      }
    } catch (err) {
      console.error('Failed to load challenges:', err);
    }
  }

  // Render category filters
  function renderCategoryFilters() {
    if (!elements.categoryPillsContainer) return;

    // Extract categories
    const categories = ['all'];
    const counts = { all: state.challenges.length };

    state.challenges.forEach(c => {
      counts[c.category] = (counts[c.category] || 0) + 1;
      if (!categories.includes(c.category)) {
        categories.push(c.category);
      }
    });

    elements.categoryPillsContainer.innerHTML = '';

    categories.forEach(cat => {
      const pill = document.createElement('button');
      pill.type = 'button';
      pill.className = `cat-pill ${state.selectedCategory === cat ? 'active' : ''}`;
      pill.innerHTML = `
        <span>${cat === 'all' ? 'All Categories' : cat}</span>
        <span class="cat-count">${counts[cat] || 0}</span>
      `;
      pill.addEventListener('click', () => {
        state.selectedCategory = cat;
        renderCategoryFilters();
        renderChallenges();
      });
      elements.categoryPillsContainer.appendChild(pill);
    });
  }

  // Render Challenge Cards
  function renderChallenges() {
    if (!elements.challengesGrid) return;

    // Update status counts on filter buttons
    const totalCount = state.challenges.length;
    const solvedCount = state.challenges.filter(c => c.isSolved).length;
    const unsolvedCount = totalCount - solvedCount;
    if (elements.countAll) elements.countAll.textContent = totalCount;
    if (elements.countSolved) elements.countSolved.textContent = solvedCount;
    if (elements.countUnsolved) elements.countUnsolved.textContent = unsolvedCount;

    let filtered = state.challenges;

    // Filter by status (all / unsolved / solved)
    if (state.statusFilter === 'solved') {
      filtered = filtered.filter(c => c.isSolved);
    } else if (state.statusFilter === 'unsolved') {
      filtered = filtered.filter(c => !c.isSolved);
    }

    // Filter by category
    if (state.selectedCategory !== 'all') {
      filtered = filtered.filter(c => c.category === state.selectedCategory);
    }

    // Filter by search query
    if (state.searchQuery) {
      filtered = filtered.filter(c => 
        c.title.toLowerCase().includes(state.searchQuery) ||
        c.category.toLowerCase().includes(state.searchQuery) ||
        c.description.toLowerCase().includes(state.searchQuery)
      );
    }

    if (filtered.length === 0) {
      elements.challengesGrid.innerHTML = `
        <div class="empty-state" style="grid-column: 1 / -1;">
          <div class="empty-state-icon">🔍</div>
          <h3>No challenges found</h3>
          <p>Try adjusting your category filter, status toggle, or search query.</p>
        </div>
      `;
      return;
    }

    elements.challengesGrid.innerHTML = '';

    filtered.forEach(c => {
      const card = document.createElement('div');
      const isLocked = Boolean(c.isLocked);
      card.className = `challenge-card ${c.isSolved ? 'solved' : 'unsolved'} ${isLocked ? 'locked' : ''}`;
      card.setAttribute('data-id', c.id);

      const diffClass = `diff-${c.difficulty.toLowerCase()}`;

      // Clean preview text
      const cleanDesc = c.description
        .replace(/```[\s\S]*?```/g, '[Code snippet]')
        .replace(/`([^`]+)`/g, '$1')
        .substring(0, 110) + '...';

      let statusBadgeHtml = '';
      if (isLocked) {
        statusBadgeHtml = `<span class="card-status-pill pill-locked">🔒 LOCKED</span>`;
      } else if (c.isSolved) {
        statusBadgeHtml = `<span class="card-status-pill pill-solved">✓ SOLVED</span>`;
      } else {
        statusBadgeHtml = `<span class="card-status-pill pill-unsolved">○ UNSOLVED</span>`;
      }

      card.innerHTML = `
        <div class="card-top-row">
          <span class="card-category-pill">${escapeHtml(c.category)}</span>
          <div class="card-badges-group">
            ${statusBadgeHtml}
            <span class="card-points-badge ${c.isSolved ? 'points-solved' : ''}">
              ${c.isSolved ? `✓ ${c.points} PTS` : `${c.points} PTS`}
            </span>
          </div>
        </div>
        <div class="card-main-content">
          <h3 class="card-title ${c.isSolved ? 'title-solved' : ''}">
            ${c.isSolved ? '<span class="title-check">✓</span> ' : ''}${isLocked ? '<span style="color:#fc8181; margin-right:4px;">🔒</span>' : ''}${escapeHtml(c.title)}
          </h3>
          <p class="card-preview-text">${isLocked ? '<em style="color:var(--text-muted); font-size:0.83rem;">🔒 Question locked by administrators</em>' : escapeHtml(cleanDesc)}</p>
        </div>
        <div class="card-bottom-row">
          <span class="difficulty-pill ${diffClass}">${escapeHtml(c.difficulty)}</span>
          <div class="card-status-indicator ${c.isSolved ? 'solved-text' : (isLocked ? 'locked-text' : 'unsolved-text')}">
            ${isLocked ? '🔒 LOCKED' : (c.isSolved ? `✓ SOLVED (${c.solveCount || 0} solves)` : `○ ${c.solveCount || 0} solves`)}
          </div>
        </div>
      `;

      card.addEventListener('click', () => {
        if (isLocked) {
          showToast(`🔒 "${c.title}" is locked by administrators. It will unlock when the competition organizers make it active.`, 'error');
          return;
        }
        openChallengeModal(c.id);
      });
      elements.challengesGrid.appendChild(card);
    });
  }

  // Open Challenge Modal
  function openChallengeModal(challengeId) {
    const c = state.challenges.find(item => item.id === challengeId);
    if (!c) return;

    // Locked questions cannot be opened
    if (c.isLocked) {
      showToast(`🔒 "${c.title}" is locked by administrators and cannot be opened.`, 'error');
      return;
    }

    state.currentModalChallengeId = challengeId;

    elements.modalTitle.textContent = c.title;
    elements.modalCategory.textContent = c.category;
    elements.modalPoints.textContent = `${c.points} PTS`;
    
    // Difficulty pill
    elements.modalDifficulty.textContent = c.difficulty;
    elements.modalDifficulty.className = `difficulty-pill diff-${c.difficulty.toLowerCase()}`;

    // Dynamic solve count badge
    if (elements.modalSolvesCount) {
      elements.modalSolvesCount.textContent = `${c.solveCount || 0} solves`;
    }

    // Solved status pill in header
    if (c.isSolved) {
      elements.modalSolvedStatus.style.display = 'inline-flex';
      elements.modalSolvedStatus.className = 'card-status-pill pill-solved';
      elements.modalSolvedStatus.innerHTML = '✓ SOLVED';
    } else {
      elements.modalSolvedStatus.style.display = 'inline-flex';
      elements.modalSolvedStatus.className = 'card-status-pill pill-unsolved';
      elements.modalSolvedStatus.innerHTML = '○ UNSOLVED';
    }

    // Modal prominent status banner
    if (elements.modalSolveBanner) {
      if (c.isSolved) {
        elements.modalSolveBanner.className = 'modal-solve-banner solved';
        elements.modalSolveBanner.innerHTML = `<span>✓</span> <span><strong>SOLVED:</strong> You captured this flag and earned ${c.points} points!</span>`;
        elements.modalSolveBanner.style.display = 'flex';
      } else {
        elements.modalSolveBanner.className = 'modal-solve-banner unsolved';
        elements.modalSolveBanner.innerHTML = `<span>○</span> <span><strong>UNSOLVED:</strong> Find the flag and submit below to claim ${c.points} points.</span>`;
        elements.modalSolveBanner.style.display = 'flex';
      }
    }

    // Render formatted markdown description
    elements.modalDescription.innerHTML = formatMarkdown(c.description);

    // Attachments
    if (c.attachments && c.attachments.length > 0) {
      elements.modalAttachmentsSection.style.display = 'flex';
      elements.modalAttachmentsList.innerHTML = '';
      c.attachments.forEach(att => {
        const chip = document.createElement('a');
        chip.href = att.url;
        chip.download = att.name;
        chip.className = 'attachment-chip';
        chip.innerHTML = `
          <span>📥 Download <strong>${escapeHtml(att.name)}</strong></span>
          <span class="attachment-size">(${att.size})</span>
        `;
        elements.modalAttachmentsList.appendChild(chip);
      });
    } else {
      elements.modalAttachmentsSection.style.display = 'none';
    }

    // Hints
    if (c.hints && c.hints.length > 0) {
      elements.modalHintsSection.style.display = 'flex';
      elements.modalHintsList.innerHTML = '';
      c.hints.forEach((hint, idx) => {
        const details = document.createElement('details');
        details.className = 'hint-details';
        details.innerHTML = `
          <summary class="hint-summary">💡 Reveal Hint ${idx + 1}</summary>
          <div class="hint-content">${formatMarkdown(hint)}</div>
        `;
        elements.modalHintsList.appendChild(details);
      });
    } else {
      elements.modalHintsSection.style.display = 'none';
    }

    // Flag input & lock states
    elements.flagInput.value = '';
    elements.flagFeedback.style.display = 'none';

    if (elements.modalLockedBanner) elements.modalLockedBanner.style.display = 'none';
    if (c.isSolved) {
      elements.flagInput.disabled = true;
      elements.flagInput.placeholder = 'Challenge already solved by your account';
      elements.flagSubmitBtn.disabled = true;
      elements.flagSubmitBtn.textContent = 'Already Solved';
    } else if (!state.currentUser) {
      elements.flagInput.disabled = true;
      elements.flagInput.placeholder = 'Log in to submit flags and claim points';
      elements.flagSubmitBtn.disabled = true;
      elements.flagSubmitBtn.textContent = 'Login Required';
    } else {
      elements.flagInput.disabled = false;
      elements.flagInput.placeholder = 'KRYPTEIA{...}';
      elements.flagSubmitBtn.disabled = false;
      elements.flagSubmitBtn.textContent = 'Submit Flag';
    }

    elements.challengeModal.classList.add('open');
    elements.challengeModal.setAttribute('aria-hidden', 'false');
  }

  function closeChallengeModal() {
    if (!elements.challengeModal) return;
    elements.challengeModal.classList.remove('open');
    elements.challengeModal.setAttribute('aria-hidden', 'true');
    state.currentModalChallengeId = null;
  }

  // Navigate between unlocked challenges inside modal
  function navigatePreviousChallenge() {
    const unlocked = state.challenges.filter(c => !c.isLocked);
    if (!state.currentModalChallengeId || unlocked.length === 0) return;
    const currentIndex = unlocked.findIndex(c => c.id === state.currentModalChallengeId);
    if (currentIndex === -1) return;
    const prevIndex = (currentIndex - 1 + unlocked.length) % unlocked.length;
    openChallengeModal(unlocked[prevIndex].id);
  }

  function navigateNextChallenge() {
    const unlocked = state.challenges.filter(c => !c.isLocked);
    if (!state.currentModalChallengeId || unlocked.length === 0) return;
    const currentIndex = unlocked.findIndex(c => c.id === state.currentModalChallengeId);
    if (currentIndex === -1) return;
    const nextIndex = (currentIndex + 1) % unlocked.length;
    openChallengeModal(unlocked[nextIndex].id);
  }

  // Flag Submission Handler
  async function handleFlagSubmit(e) {
    e.preventDefault();
    if (!state.currentUser) {
      openAuthModal();
      return;
    }

    const challengeId = state.currentModalChallengeId;
    let flag = elements.flagInput.value.trim();

    // Auto-normalize common space quirks (e.g., "KRYPT EIA{...}" -> "KRYPTEIA{...}")
    flag = flag.replace(/^KRYPT[\s_]+EIA/i, 'KRYPTEIA')
               .replace(/^([A-Za-z0-9_-]+)\s*\{/, '$1{')
               .replace(/^([A-Za-z0-9_-]+\{)\s*(.*?)\s*(\})$/, '$1$2$3');
    elements.flagInput.value = flag;

    if (!flag) {
      showFeedback('Please enter a flag', 'error');
      return;
    }

    elements.flagSubmitBtn.disabled = true;
    elements.flagSubmitBtn.textContent = 'Verifying...';

    try {
      const res = await API.submitFlag(challengeId, flag);

      if (res.success) {
        showFeedback(res.message, 'success');
        showToast(`+${res.pointsAwarded} PTS! Challenge Solved!`, 'success');

        // Update local challenge state
        const target = state.challenges.find(c => c.id === challengeId);
        if (target) {
          target.isSolved = true;
          target.solveCount = (target.solveCount || 0) + 1;
        }

        // Update user state
        if (state.currentUser) {
          state.currentUser.totalPoints = res.newTotalPoints;
          state.currentUser.solvedCount = res.solvedCount;
          state.currentUser.rank = res.rank;
          updateUserUI();
        }

        renderChallenges();
        if (elements.modalSolvesCount && target) {
          elements.modalSolvesCount.textContent = `${target.solveCount} solves`;
        }

        // Lock form on solve
        elements.flagInput.disabled = true;
        elements.flagSubmitBtn.textContent = 'Solved!';
        elements.modalSolvedStatus.style.display = 'inline-flex';
        elements.modalSolvedStatus.className = 'comp-badge live';
        elements.modalSolvedStatus.innerHTML = '✓ SOLVED';

        // Refresh authoritative leaderboard and challenge list dynamically
        loadLeaderboard();
        loadChallenges();
      } else if (res.alreadySolved) {
        showFeedback(res.message, 'info');
      }
    } catch (err) {
      showFeedback(err.message || 'Incorrect flag. Try again!', 'error');
    } finally {
      const currentCh = state.challenges.find(c => c.id === challengeId);
      if (!currentCh || !currentCh.isSolved) {
        elements.flagSubmitBtn.disabled = false;
        elements.flagSubmitBtn.textContent = 'Submit Flag';
      }
    }
  }

  function showFeedback(msg, type) {
    elements.flagFeedback.style.display = 'flex';
    elements.flagFeedback.className = `feedback-banner ${type}`;
    elements.flagFeedback.innerHTML = `
      <span>${type === 'success' ? '🏆' : type === 'error' ? '❌' : 'ℹ️'}</span>
      <span>${escapeHtml(msg)}</span>
    `;
  }

  // =====================================================================
  // LEADERBOARD
  // =====================================================================
  async function loadLeaderboard() {
    try {
      const res = await API.getLeaderboard();
      state.leaderboardData = res.leaderboard || [];
      renderLeaderboard(elements.lbSearchInput ? elements.lbSearchInput.value.toLowerCase().trim() : '');
    } catch (e) {
      console.error('Failed to load leaderboard:', e);
    }
  }

  function renderLeaderboard(filterText = '') {
    if (!elements.leaderboardTableBody) return;

    let data = state.leaderboardData;
    if (filterText) {
      data = data.filter(entry => entry.username.toLowerCase().includes(filterText));
    }

    // Top 3 Podium
    if (elements.podiumContainer) {
      const top3 = state.leaderboardData.slice(0, 3);
      elements.podiumContainer.innerHTML = '';

      if (top3.length === 0) {
        elements.podiumContainer.style.display = 'none';
      } else {
        elements.podiumContainer.style.display = 'grid';
        const podiumTiers = ['gold', 'silver', 'bronze'];

        top3.forEach((item, idx) => {
          const tier = podiumTiers[idx] || 'bronze';
          const card = document.createElement('div');
          card.className = `podium-card ${tier}`;
          card.innerHTML = `
            <div class="podium-rank-badge">#${item.rank}</div>
            <div class="podium-username">${escapeHtml(item.username)} ${item.isCurrentParticipant ? '<span class="you-tag">YOU</span>' : ''}</div>
            <div class="podium-score">${item.totalPoints} PTS</div>
            <div class="podium-meta">${item.solvedCount} solves · ${formatTimestamp(item.lastSolveTime)}</div>
          `;
          elements.podiumContainer.appendChild(card);
        });
      }
    }

    // Leaderboard Table
    if (data.length === 0) {
      elements.leaderboardTableBody.innerHTML = `
        <tr>
          <td colspan="5" class="empty-state">
            <div class="empty-state-icon">🏆</div>
            <div style="font-size: 1.1rem; font-weight: 600;">Leaderboard is clear</div>
            <div style="margin-top: 0.35rem; color: var(--text-muted); font-size: 0.9rem;">
              Rankings update dynamically in real time as participants register and solve challenges.
            </div>
          </td>
        </tr>
      `;
      return;
    }

    elements.leaderboardTableBody.innerHTML = '';

    data.forEach(item => {
      const row = document.createElement('tr');
      if (item.isCurrentParticipant) {
        row.className = 'current-user-row';
      }

      row.innerHTML = `
        <td class="rank-cell">#${item.rank}</td>
        <td class="username-cell">
          <span>${escapeHtml(item.username)}</span>
          ${item.isCurrentParticipant ? '<span class="you-tag">YOU</span>' : ''}
        </td>
        <td class="score-cell">${item.totalPoints} PTS</td>
        <td class="solves-cell">${item.solvedCount} solves</td>
        <td class="time-cell">${formatTimestamp(item.lastSolveTime)}</td>
      `;
      elements.leaderboardTableBody.appendChild(row);
    });
  }

  // =====================================================================
  // RULES
  // =====================================================================
  async function loadRules() {
    try {
      const res = await API.getRules();
      const rulesGrid = document.getElementById('rules-grid');
      if (!rulesGrid) return;

      rulesGrid.innerHTML = '';
      res.rules.forEach(r => {
        const card = document.createElement('div');
        card.className = 'rule-card';
        card.innerHTML = `
          <div class="rule-number">RULE // 0${r.id}</div>
          <h3 class="rule-title">${escapeHtml(r.title)}</h3>
          <p class="rule-description">${escapeHtml(r.description)}</p>
        `;
        rulesGrid.appendChild(card);
      });
    } catch (e) {
      console.warn('Failed to load rules:', e);
    }
  }

  // =====================================================================
  // AUTHENTICATION MODAL & LOGIC
  // =====================================================================
  function openAuthModal() {
    if (!elements.authModal) return;
    switchAuthTab('login');
    elements.authFeedback.style.display = 'none';
    elements.authModal.classList.add('open');
    elements.authModal.setAttribute('aria-hidden', 'false');
  }

  function closeAuthModal() {
    if (!elements.authModal) return;
    elements.authModal.classList.remove('open');
    elements.authModal.setAttribute('aria-hidden', 'true');
  }

  function switchAuthTab(tab) {
    if (tab === 'login') {
      elements.loginTabBtn.classList.add('active');
      elements.registerTabBtn.classList.remove('active');
      elements.loginForm.style.display = 'block';
      elements.registerForm.style.display = 'none';
    } else {
      elements.loginTabBtn.classList.remove('active');
      elements.registerTabBtn.classList.add('active');
      elements.loginForm.style.display = 'none';
      elements.registerForm.style.display = 'block';
    }
    elements.authFeedback.style.display = 'none';
  }

  async function handleLoginSubmit(e) {
    e.preventDefault();
    const id = document.getElementById('login-identifier').value.trim();
    const pwd = document.getElementById('login-password').value;

    if (!id || !pwd) {
      showAuthFeedback('Please enter both identifier and password', 'error');
      return;
    }

    try {
      const res = await API.login(id, pwd);
      state.currentUser = res.user;
      updateUserUI();
      closeAuthModal();
      showToast(`Welcome back, ${res.user.username}!`, 'success');
      await loadChallenges();
      if (state.activeTab === 'leaderboard') await loadLeaderboard();
    } catch (err) {
      showAuthFeedback(err.message || 'Login failed. Invalid credentials.', 'error');
    }
  }

  async function handleRegisterSubmit(e) {
    e.preventDefault();
    const username = document.getElementById('reg-username').value.trim();
    const email = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-password').value;

    if (!username || !email || !password) {
      showAuthFeedback('All registration fields are required', 'error');
      return;
    }

    try {
      const res = await API.register(username, email, password);
      state.currentUser = res.user;
      updateUserUI();
      closeAuthModal();
      showToast(`Account created! Welcome to Krypteia CTF, ${username}!`, 'success');
      await loadChallenges();
      if (state.activeTab === 'leaderboard') await loadLeaderboard();
    } catch (err) {
      showAuthFeedback(err.message || 'Registration failed.', 'error');
    }
  }

  function showAuthFeedback(msg, type) {
    elements.authFeedback.style.display = 'flex';
    elements.authFeedback.className = `feedback-banner ${type}`;
    elements.authFeedback.innerHTML = `<span>${type === 'error' ? '❌' : '✓'}</span><span>${escapeHtml(msg)}</span>`;
  }

  async function handleLogout() {
    try {
      await API.logout();
      state.currentUser = null;
      updateUserUI();
      closeProfileModal();
      showToast('Logged out successfully', 'info');
      await loadChallenges();
      if (state.activeTab === 'leaderboard') await loadLeaderboard();
    } catch (e) {
      console.error('Logout error:', e);
    }
  }

  // User Profile Modal
  function openProfileModal() {
    if (!state.currentUser || !elements.profileModal) return;

    elements.profileUsername.textContent = state.currentUser.username;
    elements.profileEmail.textContent = state.currentUser.email || 'Participant';
    elements.profileRank.textContent = `#${state.currentUser.rank || 1}`;
    elements.profileScore.textContent = `${state.currentUser.totalPoints || 0} PTS`;
    elements.profileSolvesCount.textContent = `${state.currentUser.solvedCount || 0} Solves`;

    // Render solve history
    elements.profileSolvesList.innerHTML = '';
    const solvedChallenges = state.challenges.filter(c => c.isSolved);

    if (solvedChallenges.length === 0) {
      elements.profileSolvesList.innerHTML = `
        <div style="color: var(--text-muted); font-size: 0.88rem; text-align: center; padding: 1rem;">
          No challenges solved yet. Jump into the challenge grid and capture flags!
        </div>
      `;
    } else {
      solvedChallenges.forEach(c => {
        const item = document.createElement('div');
        item.style.cssText = 'display: flex; justify-content: space-between; padding: 0.6rem 0; border-bottom: 1px solid var(--border-dim); font-size: 0.88rem;';
        item.innerHTML = `
          <span>${escapeHtml(c.title)} (${escapeHtml(c.category)})</span>
          <span style="color: var(--accent-green); font-family: var(--font-mono); font-weight: 700;">+${c.points} PTS</span>
        `;
        elements.profileSolvesList.appendChild(item);
      });
    }

    elements.profileModal.classList.add('open');
    elements.profileModal.setAttribute('aria-hidden', 'false');
  }

  function closeProfileModal() {
    if (!elements.profileModal) return;
    elements.profileModal.classList.remove('open');
    elements.profileModal.setAttribute('aria-hidden', 'true');
  }

  // Toasts
  function showToast(message, type = 'info') {
    if (!elements.toastContainer) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    const icon = type === 'success' ? '⚡' : type === 'error' ? '⚠️' : 'ℹ️';
    toast.innerHTML = `<span>${icon}</span><span>${escapeHtml(message)}</span>`;

    elements.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.25s ease';
      setTimeout(() => toast.remove(), 250);
    }, 3500);
  }

  // Format timestamp helper
  function formatTimestamp(isoStr) {
    if (!isoStr) return 'No solves yet';
    try {
      const date = new Date(isoStr);
      const diffSec = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
      const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      if (diffSec < 60) return `${timeStr} (${diffSec}s ago)`;
      if (diffSec < 3600) return `${timeStr} (${Math.floor(diffSec / 60)}m ago)`;
      if (diffSec < 86400) return `${timeStr} (${Math.floor(diffSec / 3600)}h ago)`;
      return date.toLocaleDateString() + ' ' + timeStr;
    } catch (e) {
      return isoStr;
    }
  }

  // Markdown renderer for rich descriptions and hints
  function formatMarkdown(text) {
    if (!text) return '';
    let html = escapeHtml(text);

    // Code blocks
    html = html.replace(/```([\s\S]*?)```/g, (match, p1) => {
      return `<pre><code>${p1.trim()}</code></pre>`;
    });

    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Bold text
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

    // URLs to links
    html = html.replace(/(https?:\/\/[^\s]+)/g, '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>');

    // Line breaks to paragraphs
    const paragraphs = html.split('\n\n').filter(p => p.trim());
    return paragraphs.map(p => {
      if (p.startsWith('<pre>')) return p;
      return `<p>${p.replace(/\n/g, '<br>')}</p>`;
    }).join('');
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

  // Bootstrap when DOM is loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
