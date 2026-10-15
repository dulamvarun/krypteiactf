const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const db = require('./database');
const { getPublicChallenges, validateFlag, CHALLENGES } = require('./challenges');
const excelLeaderboard = require('./excel-leaderboard');

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

// Static file serving with no-cache for dynamic app assets (HTML, JS, CSS)
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html') || filePath.endsWith('.js') || filePath.endsWith('.css')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));
app.use('/attachments', express.static(path.join(__dirname, 'public', 'attachments'), {
  maxAge: '2h'
}));

// Custom Auth Middleware: checks Authorization header, custom headers, cookies, and body tokens
function authMiddleware(req, res, next) {
  const candidates = [];

  // 1. Authorization header: "Bearer <token>"
  if (req.headers && req.headers.authorization) {
    const authHeader = String(req.headers.authorization).trim();
    const match = authHeader.match(/^Bearer\s+(\S+)$/i);
    if (match && match[1]) {
      candidates.push(match[1]);
    }
  }

  // 2. Custom header tokens
  if (req.headers && req.headers['x-session-token']) {
    candidates.push(String(req.headers['x-session-token']).trim());
  }
  if (req.headers && req.headers['x-auth-token']) {
    candidates.push(String(req.headers['x-auth-token']).trim());
  }

  // 3. Cookie token
  if (req.cookies && req.cookies['krypteia_session']) {
    candidates.push(String(req.cookies['krypteia_session']).trim());
  }

  // 4. Request body token fallback (especially for JSON POST requests)
  if (req.body && typeof req.body === 'object') {
    if (req.body.token) candidates.push(String(req.body.token).trim());
    if (req.body.sessionToken) candidates.push(String(req.body.sessionToken).trim());
  }

  // 5. Query token fallback
  if (req.query && req.query.token) {
    candidates.push(String(req.query.token).trim());
  }

  // Try candidate tokens until a valid user is resolved
  for (const raw of candidates) {
    if (!raw) continue;
    const cleanToken = raw.replace(/^["']|["']$/g, '').trim();
    if (!cleanToken) continue;
    const user = db.getUserBySession(cleanToken);
    if (user) {
      req.user = user;
      req.sessionToken = cleanToken;
      break;
    }
  }
  next();
}

app.use(authMiddleware);

// --- Real-Time Server-Sent Events (SSE) Live Synchronization ---
const sseClients = new Set();

function notifyParticipants(eventType, data = {}) {
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.res.write(payload);
    } catch (err) {
      sseClients.delete(client);
    }
  }
}

app.get('/api/events/live-sync', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  if (typeof res.flushHeaders === 'function') {
    res.flushHeaders();
  }

  const client = { id: Date.now() + Math.random(), res };
  sseClients.add(client);

  // Send handshake message
  res.write(`event: connected\ndata: ${JSON.stringify({ ok: true, timestamp: Date.now() })}\n\n`);

  // Heartbeat ping every 15 seconds
  const heartbeat = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch (e) {
      clearInterval(heartbeat);
      sseClients.delete(client);
    }
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(client);
  });
});

// --- Challenge Interactive Diagnostic Routes ---
// 1. For Challenge web-01 (Header / debug inspection)
app.get('/api/diagnostics/vault-status', (req, res) => {
  const roleHeader = req.headers['x-krypteia-role'];
  const debugQuery = req.query.debug;

  if (roleHeader === 'SecurityAdmin' || debugQuery === 'admin_override') {
    const ch = db.getChallengeById('web-01');
    const flag = ch ? db.decryptFlag(ch.flag_encrypted) : null;
    return res.json({
      status: 'authorized',
      access_level: 'Administrator',
      message: 'Access granted to internal security telemetry.',
      flag: flag || null,
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
    const ch = db.getChallengeById('web-02');
    const flag = ch ? db.decryptFlag(ch.flag_encrypted) : null;
    return res.json({
      status: 'unlocked',
      role: 'cyber_commander',
      message: 'Authentication bypass successful. Vault unlocked.',
      flag: flag || null,
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
    totalChallenges: db.getChallengeCount()
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

    // Set secure HTTP-only cookie with explicit path: '/' and 30-day duration
    res.cookie('krypteia_session', token, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });
    res.setHeader('X-Session-Token', token);

    const stats = db.getUserStats(user.id);

    notifyParticipants('user_registered', {
      userId: user.id,
      username: user.username
    });

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
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });
    res.setHeader('X-Session-Token', token);

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
  res.clearCookie('krypteia_session', { path: '/' });
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.user) {
    return res.json({ user: null });
  }

  // Refresh cookie to keep session alive and synchronized with client
  if (req.sessionToken) {
    res.cookie('krypteia_session', req.sessionToken, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });
    res.setHeader('X-Session-Token', req.sessionToken);
  }

  const stats = db.getUserStats(req.user.id);
  res.json({ user: stats, token: req.sessionToken });
});

// --- Challenges API ---
app.get('/api/challenges', (req, res) => {
  const userId = req.user ? req.user.id : null;
  const solves = userId ? db.getUserSolves(userId) : [];
  const solvedSet = new Set(solves.map(s => s.challenge_id));
  const solveCounts = db.getChallengeSolveCounts();

  // Strip all secret answers before sending to client!
  const publicChallenges = getPublicChallenges(solvedSet, solveCounts);

  res.json({
    challenges: publicChallenges,
    totalCount: publicChallenges.length,
    solvedCount: solvedSet.size
  });
});

app.post('/api/submit-flag', (req, res) => {
  // Direct safety fallback check if req.user wasn't resolved by middleware
  if (!req.user) {
    const fallbackToken = (req.body && (req.body.token || req.body.sessionToken)) ||
                          (req.headers && (req.headers['x-session-token'] || req.headers['x-auth-token'])) ||
                          (req.cookies && req.cookies['krypteia_session']);
    if (fallbackToken) {
      const clean = String(fallbackToken).replace(/^["']|["']$/g, '').trim();
      const user = db.getUserBySession(clean);
      if (user) {
        req.user = user;
        req.sessionToken = clean;
      }
    }
  }

  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required. Please log in to submit flags.'
    });
  }

  // Refresh cookie on active flag submission
  if (req.sessionToken) {
    res.cookie('krypteia_session', req.sessionToken, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000
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
  const solveCounts = db.getChallengeSolveCounts();

  // Broadcast live solve event to participants
  notifyParticipants('challenge_solved', {
    challengeId,
    solveCount: solveCounts[challengeId] || 1
  });

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
  const excelData = excelLeaderboard.getLeaderboardData();
  res.json({
    leaderboard,
    totalParticipants: leaderboard.length,
    excelLeaderboard: excelData.teams,
    generatedAt: new Date().toISOString()
  });
});

// --- Excel Sheet-Driven Leaderboard (Dedicated Endpoints) ---
app.get('/api/leaderboard/sheet', (req, res) => {
  const data = excelLeaderboard.getLeaderboardData();
  res.json({
    success: true,
    ...data
  });
});

app.get('/api/leaderboard/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  if (typeof res.flushHeaders === 'function') {
    res.flushHeaders();
  }

  // Immediately send initial payload
  const initial = excelLeaderboard.getLeaderboardData();
  res.write(`event: leaderboard_update\ndata: ${JSON.stringify(initial)}\n\n`);

  // Listener when Excel file on disk changes
  const onLeaderboardChange = (data) => {
    try {
      res.write(`event: leaderboard_update\ndata: ${JSON.stringify(data)}\n\n`);
    } catch (_) {
      excelLeaderboard.removeListener(onLeaderboardChange);
    }
  };

  excelLeaderboard.addListener(onLeaderboardChange);

  // Keep-alive heartbeat every 15s
  const heartbeat = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch (_) {
      clearInterval(heartbeat);
      excelLeaderboard.removeListener(onLeaderboardChange);
    }
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    excelLeaderboard.removeListener(onLeaderboardChange);
  });
});

app.get('/api/leaderboard/download', (req, res) => {
  if (fs.existsSync(excelLeaderboard.EXCEL_FILE_PATH)) {
    res.download(excelLeaderboard.EXCEL_FILE_PATH, 'leaderboard.xlsx');
  } else {
    res.status(404).json({ error: 'Spreadsheet not found' });
  }
});

app.post('/api/leaderboard/upload', express.raw({ type: ['application/octet-stream', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.ms-excel'], limit: '15mb' }), (req, res) => {
  try {
    if (!req.body || !req.body.length) {
      return res.status(400).json({ error: 'No Excel file data received' });
    }
    const updated = excelLeaderboard.updateExcelFile(req.body);
    res.json({
      success: true,
      message: 'Excel spreadsheet updated and leaderboard re-synced',
      ...updated
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process Excel upload: ' + err.message });
  }
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
function resolveAdminToken(req) {
  const candidates = [];

  // 1. Authorization header Bearer token (highest priority for programmatic API calls)
  if (req.headers && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0].toLowerCase() === 'bearer' && parts[1]) {
      candidates.push(parts[1].trim());
    }
  }

  // 2. HTTP-only session cookie
  if (req.cookies && req.cookies['krypteia_admin_session']) {
    candidates.push(String(req.cookies['krypteia_admin_session']).trim());
  }

  // 3. Fallback header or query param
  if (req.headers && req.headers['x-admin-token']) {
    candidates.push(String(req.headers['x-admin-token']).trim());
  }
  if (req.query && req.query.admin_token) {
    candidates.push(String(req.query.admin_token).trim());
  }

  // Find first candidate token that is currently valid in the database
  for (const t of candidates) {
    if (t && db.validateAdminSession(t)) {
      return t;
    }
  }

  return null;
}

function adminAuthMiddleware(req, res, next) {
  const token = resolveAdminToken(req);

  if (token) {
    req.adminToken = token;
    // Resync cookie so browser session remains fresh and never out of sync with localStorage
    res.cookie('krypteia_admin_session', token, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
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
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000
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
  const token = resolveAdminToken(req);
  if (token) {
    db.deleteAdminSession(token);
  }
  res.clearCookie('krypteia_admin_session', { path: '/' });
  res.json({ success: true, message: 'Logged out from administrator portal.' });
});

// 3. Admin Status & Overview
app.get('/api/admin/status', (req, res) => {
  const token = resolveAdminToken(req);
  if (!token) {
    return res.json({ authenticated: false });
  }

  // Refresh cookie to keep session alive and synchronized with client
  res.cookie('krypteia_admin_session', token, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  const config = db.getCompetitionConfig();
  const solveCounts = db.getChallengeSolveCounts();
  const challengeList = db.getAdminChallenges();
  const leaderboard = db.getDetailedLeaderboardForExport();

  res.json({
    authenticated: true,
    token,
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
  notifyParticipants('timer_updated', { config: updatedConfig });
  res.json({
    success: true,
    message: 'Competition timer updated successfully',
    config: updatedConfig
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
  notifyParticipants('leaderboard_reset', {});
  res.json({
    success: true,
    message: 'Leaderboard and participant accounts cleared successfully.'
  });
});

// 8b. Delete Individual Participant / User
app.delete('/api/admin/users/:id', adminAuthMiddleware, (req, res) => {
  try {
    const result = db.deleteUser(req.params.id);
    notifyParticipants('user_deleted', {
      userId: req.params.id,
      username: result.user ? result.user.username : 'User'
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- Dynamic Challenge & Flag Management APIs ---

// 9. Create New Challenge (Stores flag as salted HMAC + AES-256 encrypted)
app.post('/api/admin/challenges', adminAuthMiddleware, (req, res) => {
  try {
    const created = db.createChallenge(req.body);
    notifyParticipants('challenge_created', {
      challengeId: created.id,
      title: created.title,
      category: created.category
    });
    res.json({
      success: true,
      message: `Challenge "${created.title}" (${created.id}) created successfully with secure salted HMAC flag storage!`,
      challenge: created
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 10. Update Challenge
app.put('/api/admin/challenges/:id', adminAuthMiddleware, (req, res) => {
  try {
    const updated = db.updateChallenge(req.params.id, req.body);
    notifyParticipants('challenge_updated', {
      challengeId: updated.id,
      title: updated.title
    });
    res.json({
      success: true,
      message: `Challenge "${updated.title}" (${updated.id}) updated successfully!`,
      challenge: updated
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 11. Delete Challenge
app.delete('/api/admin/challenges/:id', adminAuthMiddleware, (req, res) => {
  try {
    db.deleteChallenge(req.params.id);
    notifyParticipants('challenge_deleted', {
      challengeId: req.params.id
    });
    res.json({
      success: true,
      message: `Challenge "${req.params.id}" has been deleted successfully.`
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 12. Sandbox Test Flag Validation
app.post('/api/admin/test-flag', adminAuthMiddleware, (req, res) => {
  const { challengeId, flag } = req.body;
  if (!challengeId || !flag) {
    return res.status(400).json({ error: 'challengeId and flag are required' });
  }
  const result = db.testFlagValidation(challengeId, flag);
  res.json({
    success: true,
    ...result
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
  excelLeaderboard.initExcelWatcher();
  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`  KRYPTEIA CTF PORTAL is live on http://localhost:${PORT}`);
    console.log(`  Excel Leaderboard synced from leaderboard.xlsx`);
    console.log(`  Institution: St. Peter's Engineering College`);
    console.log(`====================================================`);
  });
} else {
  excelLeaderboard.initExcelWatcher();
}

module.exports = app;
