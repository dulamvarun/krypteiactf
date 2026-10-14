const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const db = require('./database');
const { getPublicChallenges, validateFlag, CHALLENGES } = require('./challenges');

const app = express();
const PORT = process.env.PORT || 3000;

// Security Hardening: Hide server fingerprints
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// Body parsers and cookie middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Static file serving with lightweight client-side caching
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));
app.use('/attachments', express.static(path.join(__dirname, 'public', 'attachments'), {
  maxAge: '2h'
}));

// Custom Auth Middleware: checks cookie or Bearer token
function authMiddleware(req, res, next) {
  let token = req.cookies['krypteia_session'];

  if (!token && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      token = parts[1];
    }
  }

  if (token) {
    const user = db.getUserBySession(token);
    if (user) {
      req.user = user;
      req.sessionToken = token;
    }
  }
  next();
}

app.use(authMiddleware);

// --- Challenge Interactive Diagnostic Routes ---
// 1. For Challenge web-01 (Header / debug inspection)
app.get('/api/diagnostics/vault-status', (req, res) => {
  const roleHeader = req.headers['x-krypteia-role'];
  const debugQuery = req.query.debug;

  if (roleHeader === 'SecurityAdmin' || debugQuery === 'admin_override') {
    return res.json({
      status: 'authorized',
      access_level: 'Administrator',
      message: 'Access granted to internal security telemetry.',
      flag: 'KRYPTEIA{h34d3r_sp00f1ng_m4st3r_99}',
      timestamp: new Date().toISOString()
    });
  }

  res.status(403).json({
    status: 'forbidden',
    error: 'Access Denied',
    message: 'Missing or invalid security authorization. Expected header "X-Krypteia-Role: SecurityAdmin" or active debug parameter.'
  });
});

// 2. For Challenge web-02 (Cookie manipulation)
app.get('/api/diagnostics/cookie-vault', (req, res) => {
  const cookieRole = req.cookies['krypteia_role'];

  if (cookieRole === 'cyber_commander') {
    return res.json({
      status: 'unlocked',
      role: 'cyber_commander',
      message: 'Authentication bypass successful. Vault unlocked.',
      flag: 'KRYPTEIA{c00k13_m4n1pul4t10n_succ3ss}',
      timestamp: new Date().toISOString()
    });
  }

  res.status(401).json({
    status: 'locked',
    error: 'Unauthorized Role',
    message: 'Access restricted. Cookie "krypteia_role" must be present and set to "cyber_commander".'
  });
});

// --- Public Competition Metadata ---
app.get('/api/config', (req, res) => {
  const config = db.getCompetitionConfig();
  res.json({
    ...config,
    totalChallenges: CHALLENGES.length
  });
});

// --- Authentication Routes ---
app.post('/api/auth/register', (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    const user = db.createUser(username, email, password);
    const token = db.createSession(user.id);

    // Set secure HTTP-only cookie
    res.cookie('krypteia_session', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    const stats = db.getUserStats(user.id);

    res.status(201).json({
      message: 'Registration successful! Welcome to KRYPTEIA CTF.',
      token,
      user: stats
    });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Registration failed' });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) {
      return res.status(400).json({ error: 'Username/email and password are required' });
    }

    const user = db.authenticateUser(identifier, password);
    const token = db.createSession(user.id);

    res.cookie('krypteia_session', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    const stats = db.getUserStats(user.id);

    res.json({
      message: 'Authentication successful. Welcome back!',
      token,
      user: stats
    });
  } catch (err) {
    res.status(401).json({ error: err.message || 'Authentication failed' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  if (req.sessionToken) {
    db.deleteSession(req.sessionToken);
  }
  res.clearCookie('krypteia_session');
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.user) {
    return res.json({ user: null });
  }

  const stats = db.getUserStats(req.user.id);
  res.json({ user: stats });
});

// --- Challenges API ---
app.get('/api/challenges', (req, res) => {
  const userId = req.user ? req.user.id : null;
  const solves = userId ? db.getUserSolves(userId) : [];
  const solvedSet = new Set(solves.map(s => s.challenge_id));
  const solveCounts = db.getChallengeSolveCounts();
  const challengeLocks = db.getChallengeLocks();

  // Strip all secret answers before sending to client!
  const publicChallenges = getPublicChallenges(solvedSet, solveCounts, challengeLocks);

  res.json({
    challenges: publicChallenges,
    totalCount: publicChallenges.length,
    solvedCount: solvedSet.size
  });
});

// --- Flag Submission and Scoring ---
app.post('/api/submit-flag', (req, res) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required. Please log in to submit flags.'
    });
  }

  const { challengeId, flag } = req.body;

  if (!challengeId || !flag) {
    return res.status(400).json({
      success: false,
      error: 'Challenge ID and flag are required.'
    });
  }

  // Rate limiting per user
  const rateLimit = db.checkRateLimit(req.user.id);
  if (rateLimit.limited) {
    return res.status(429).json({
      success: false,
      error: `Too many submissions. Please wait ${rateLimit.waitSeconds} second(s) before trying again.`
    });
  }

  // Competition status validation (using IST-aware start time)
  const compConfig = db.getCompetitionConfig();
  if (!compConfig.isStarted) {
    return res.status(403).json({
      success: false,
      error: `Competition has not started yet. Event scheduled kickoff: ${compConfig.startTimeIST || compConfig.startTime}.`
    });
  }
  if (compConfig.isEnded) {
    return res.status(403).json({
      success: false,
      error: 'Competition has concluded. Flag submissions are now closed.'
    });
  }

  // Check if challenge is locked by administrator
  if (db.isChallengeLocked(challengeId)) {
    return res.status(403).json({
      success: false,
      error: 'This challenge is currently locked by administrators. Submissions are temporarily closed.'
    });
  }

  // Validate submitted flag against private answer
  const validation = validateFlag(challengeId, flag);
  if (!validation.found) {
    return res.status(404).json({
      success: false,
      error: 'Challenge not found.'
    });
  }

  // Record submission history log
  db.recordSubmission(req.user.id, challengeId, flag, validation.isCorrect);

  if (!validation.isCorrect) {
    return res.status(400).json({
      success: false,
      error: 'Incorrect flag! Inspect your methodology and try again.'
    });
  }

  // Flag is correct: attempt to record solve atomically
  const solveResult = db.recordSolve(req.user.id, challengeId, validation.points);

  if (solveResult.alreadySolved) {
    return res.json({
      success: false,
      alreadySolved: true,
      message: 'Challenge already solved! You have already claimed points for this challenge.'
    });
  }

  // Newly solved! Fetch updated participant stats
  const updatedStats = db.getUserStats(req.user.id);

  res.json({
    success: true,
    message: `[+] Correct Flag! ${validation.points} points awarded for "${validation.title}".`,
    pointsAwarded: validation.points,
    challengeId,
    newTotalPoints: updatedStats.totalPoints,
    solvedCount: updatedStats.solvedCount,
    rank: updatedStats.rank
  });
});

// --- Authoritative Leaderboard ---
app.get('/api/leaderboard', (req, res) => {
  const currentUserId = req.user ? req.user.id : null;
  const leaderboard = db.getLeaderboard(currentUserId);
  res.json({
    leaderboard,
    totalParticipants: leaderboard.length,
    generatedAt: new Date().toISOString()
  });
});

// --- Competition Rules ---
app.get('/api/rules', (req, res) => {
  const config = db.getCompetitionConfig();
  res.json({
    title: 'KRYPTEIA CTF — Official Rules & Code of Conduct',
    institution: "St. Peter's Engineering College, Hyderabad",
    rules: [
      {
        id: 1,
        title: 'Authentic Individual Accounts',
        description: 'Participants must use their own registered individual accounts. Sharing accounts, impersonation, or submitting flags on behalf of other players is strictly forbidden.'
      },
      {
        id: 2,
        title: 'Flag Format & Official Submission',
        description: 'All flags adhere to the standard format: KRYPTEIA{...} unless explicitly stated otherwise in the challenge description. Flags must be submitted through this official portal input field.'
      },
      {
        id: 3,
        title: 'Authoritative Unique Scoring',
        description: 'Points are awarded only once per valid solve. Duplicate correct submissions for the same challenge will not award additional points. Tie-breaks are determined strictly by the earliest last solve timestamp.'
      },
      {
        id: 4,
        title: 'No Answer Sharing or Collusion',
        description: 'Do not distribute flags, solution scripts, or spoilers during the live competition period. Collaboration between opposing participants will lead to immediate disqualification.'
      },
      {
        id: 5,
        title: 'Permitted Targets Only',
        description: 'Only challenge files, diagnostic endpoints, and designated target URLs provided in the challenge briefs may be tested. Do not launch DoS/DDoS attacks, automated high-rate fuzzing, or attacks against the scoring portal infrastructure or college servers.'
      },
      {
        id: 6,
        title: 'Spirit of Cybersecurity Learning',
        description: 'Krypteia CTF is created by the Cyber Security Technical Club at St. Peter\'s Engineering College to foster hands-on hacking, analytical thinking, and ethical security practice. Play fair and enjoy the challenge!'
      }
    ],
    config
  });
});

// --- Administrator Middleware & Routes ---
function adminAuthMiddleware(req, res, next) {
  let token = req.cookies['krypteia_admin_session'];
  if (!token && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      token = parts[1];
    }
  }

  if (token && db.validateAdminSession(token)) {
    req.adminToken = token;
    return next();
  }

  return res.status(401).json({
    success: false,
    error: 'Administrator authentication required.'
  });
}

// 1. Admin Login (Credentials: id - pappu, pass - Bt@1801)
app.post('/api/admin/login', (req, res) => {
  const { id, username, password } = req.body;
  const adminId = (id || username || '').trim();

  if (adminId.toLowerCase() === 'pappu' && password === 'Bt@1801') {
    const token = db.createAdminSession();
    res.cookie('krypteia_admin_session', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });
    return res.json({
      success: true,
      token,
      message: 'Admin authentication successful. Welcome, Commander Pappu.',
      admin: { id: 'pappu', role: 'admin' }
    });
  }

  return res.status(401).json({
    success: false,
    error: 'Invalid administrator credentials. Access Denied.'
  });
});

// 2. Admin Logout
app.post('/api/admin/logout', (req, res) => {
  let token = req.cookies['krypteia_admin_session'];
  if (!token && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      token = parts[1];
    }
  }
  if (token) {
    db.deleteAdminSession(token);
  }
  res.clearCookie('krypteia_admin_session');
  res.json({ success: true, message: 'Logged out from administrator portal.' });
});

// 3. Admin Status & Overview
app.get('/api/admin/status', (req, res) => {
  let token = req.cookies['krypteia_admin_session'];
  if (!token && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      token = parts[1];
    }
  }

  const authenticated = Boolean(token && db.validateAdminSession(token));
  if (!authenticated) {
    return res.json({ authenticated: false });
  }

  const config = db.getCompetitionConfig();
  const locks = db.getChallengeLocks();
  const solveCounts = db.getChallengeSolveCounts();

  const challengeList = CHALLENGES.map(c => ({
    id: c.id,
    title: c.title,
    category: c.category,
    difficulty: c.difficulty,
    points: c.points,
    solveCount: solveCounts[c.id] || 0,
    isLocked: Boolean(locks[c.id])
  }));

  const leaderboard = db.getDetailedLeaderboardForExport();

  res.json({
    authenticated: true,
    admin: { id: 'pappu', role: 'admin' },
    config,
    challenges: challengeList,
    totalUsers: leaderboard.length,
    totalSolves: Object.values(solveCounts).reduce((a, b) => a + b, 0),
    leaderboard
  });
});

// 4. Set Event Timer (IST)
app.post('/api/admin/timer', adminAuthMiddleware, (req, res) => {
  const { startTime, endTime, status } = req.body;
  if (!startTime) {
    return res.status(400).json({ error: 'startTime is required' });
  }

  const startDate = new Date(startTime);
  if (isNaN(startDate.getTime())) {
    return res.status(400).json({ error: 'Invalid startTime format' });
  }

  let endDateIso = null;
  if (endTime) {
    const endDate = new Date(endTime);
    if (!isNaN(endDate.getTime())) {
      endDateIso = endDate.toISOString();
    }
  }

  const updatedConfig = db.setCompetitionTimer(startDate.toISOString(), endDateIso, status);
  res.json({
    success: true,
    message: 'Competition timer updated successfully',
    config: updatedConfig
  });
});

// 5. Lock / Unlock Individual Challenge
app.post('/api/admin/challenge-lock', adminAuthMiddleware, (req, res) => {
  const { challengeId, isLocked } = req.body;
  if (!challengeId) {
    return res.status(400).json({ error: 'challengeId is required' });
  }

  db.setChallengeLock(challengeId, Boolean(isLocked));
  res.json({
    success: true,
    challengeId,
    isLocked: Boolean(isLocked),
    message: `Challenge "${challengeId}" is now ${isLocked ? 'locked 🔒' : 'unlocked 🔓'}.`
  });
});

// 6. Bulk Lock / Unlock All Challenges
app.post('/api/admin/challenge-lock-all', adminAuthMiddleware, (req, res) => {
  const { isLocked } = req.body;
  const allIds = CHALLENGES.map(c => c.id);
  const locks = db.setAllChallengeLocks(allIds, Boolean(isLocked));
  res.json({
    success: true,
    isLocked: Boolean(isLocked),
    locks,
    message: `All challenges are now ${isLocked ? 'locked 🔒' : 'unlocked 🔓'}.`
  });
});

// 7. Download Leaderboard in Sheet format (CSV with UTF-8 BOM)
app.get('/api/admin/export-leaderboard', adminAuthMiddleware, (req, res) => {
  const csvData = db.generateLeaderboardCSV();
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `Krypteia_CTF_Leaderboard_${timestamp}.csv`;

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(csvData);
});

// 8. Clear / Reset Leaderboard and Participants
app.post('/api/admin/reset-leaderboard', adminAuthMiddleware, (req, res) => {
  const result = db.clearAllParticipants();
  res.json({
    success: true,
    message: 'Leaderboard and participant accounts cleared successfully.'
  });
});

// Admin Portal Web Route
app.get(['/admin', '/admin.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Fallback to index.html for SPA routing
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start listening
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`  KRYPTEIA CTF PORTAL is live on http://localhost:${PORT}`);
    console.log(`  Institution: St. Peter's Engineering College`);
    console.log(`====================================================`);
  });
}

module.exports = app;
