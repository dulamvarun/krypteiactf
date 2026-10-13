const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'krypteia_ctf.db');
const db = new Database(dbPath);

// Enable WAL mode for high concurrency
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    is_demo INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS solves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    challenge_id TEXT NOT NULL,
    points INTEGER NOT NULL,
    solved_at TEXT NOT NULL,
    UNIQUE(user_id, challenge_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    challenge_id TEXT NOT NULL,
    flag_submitted TEXT NOT NULL,
    is_correct INTEGER NOT NULL,
    submitted_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS competition_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

// Password hashing helpers using native crypto
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 12000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  const check = crypto.pbkdf2Sync(password, salt, 12000, 64, 'sha512').toString('hex');
  return check === hash;
}

// User registration
function createUser(username, email, password, isDemo = 0) {
  const cleanUsername = username.trim();
  const cleanEmail = email.trim().toLowerCase();
  
  if (!cleanUsername || cleanUsername.length < 3 || cleanUsername.length > 30) {
    throw new Error('Username must be between 3 and 30 characters');
  }
  if (!/^[a-zA-Z0-9_\-\.]+$/.test(cleanUsername)) {
    throw new Error('Username can only contain letters, numbers, underscores, dashes, and periods');
  }
  if (!cleanEmail || !cleanEmail.includes('@') || !cleanEmail.includes('.')) {
    throw new Error('Please enter a valid email address');
  }
  if (!password || password.length < 6) {
    throw new Error('Password must be at least 6 characters long');
  }

  // Check unique constraints
  const existingUser = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(cleanUsername, cleanEmail);
  if (existingUser) {
    throw new Error('Username or email is already registered');
  }

  const { salt, hash } = hashPassword(password);
  const now = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO users (username, email, password_hash, salt, is_demo, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const info = stmt.run(cleanUsername, cleanEmail, hash, salt, isDemo, now);
  return {
    id: info.lastInsertRowid,
    username: cleanUsername,
    email: cleanEmail,
    created_at: now
  };
}

// User authentication
function authenticateUser(identifier, password) {
  const cleanId = (identifier || '').trim();
  if (!cleanId || !password) {
    throw new Error('Identifier and password are required');
  }

  const user = db.prepare(`
    SELECT * FROM users WHERE username = ? OR email = ?
  `).get(cleanId, cleanId.toLowerCase());

  if (!user) {
    throw new Error('Invalid username or password');
  }

  const isValid = verifyPassword(password, user.salt, user.password_hash);
  if (!isValid) {
    throw new Error('Invalid username or password');
  }

  return {
    id: user.id,
    username: user.username,
    email: user.email,
    created_at: user.created_at
  };
}

// Session handling
function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // 7 days

  db.prepare(`
    INSERT INTO sessions (token, user_id, created_at, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(token, userId, now.toISOString(), expiresAt.toISOString());

  return token;
}

function getUserBySession(token) {
  if (!token) return null;

  const now = new Date().toISOString();
  const session = db.prepare(`
    SELECT s.user_id, u.id, u.username, u.email, u.created_at
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token = ? AND s.expires_at > ?
  `).get(token, now);

  if (!session) return null;

  return {
    id: session.id,
    username: session.username,
    email: session.email,
    created_at: session.created_at
  };
}

function deleteSession(token) {
  if (!token) return;
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

// Solve operations (ATOMIC & CONCURRENCY-SAFE)
function recordSolve(userId, challengeId, points) {
  const now = new Date().toISOString();

  const insertSolveTx = db.transaction(() => {
    // Check if already solved
    const existing = db.prepare(`
      SELECT id FROM solves WHERE user_id = ? AND challenge_id = ?
    `).get(userId, challengeId);

    if (existing) {
      return { alreadySolved: true };
    }

    // Insert solve
    db.prepare(`
      INSERT INTO solves (user_id, challenge_id, points, solved_at)
      VALUES (?, ?, ?, ?)
    `).run(userId, challengeId, points, now);

    return { success: true, points, solved_at: now };
  });

  return insertSolveTx();
}

// Record submission attempt
function recordSubmission(userId, challengeId, flagSubmitted, isCorrect) {
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO submissions (user_id, challenge_id, flag_submitted, is_correct, submitted_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(userId, challengeId, flagSubmitted.substring(0, 100), isCorrect ? 1 : 0, now);
}

// Get user solved challenge IDs
function getUserSolves(userId) {
  if (!userId) return [];
  const rows = db.prepare(`
    SELECT challenge_id, points, solved_at FROM solves WHERE user_id = ? ORDER BY solved_at DESC
  `).all(userId);
  return rows;
}

// Get solve count per challenge
function getChallengeSolveCounts() {
  const rows = db.prepare(`
    SELECT challenge_id, COUNT(*) as count FROM solves GROUP BY challenge_id
  `).all();
  const map = {};
  rows.forEach(r => {
    map[r.challenge_id] = r.count;
  });
  return map;
}

// Get full authoritative leaderboard
function getLeaderboard(currentUserId = null) {
  const rows = db.prepare(`
    SELECT 
      u.id as user_id,
      u.username,
      COALESCE(SUM(s.points), 0) as total_points,
      COUNT(s.id) as solved_count,
      MAX(s.solved_at) as last_solve_time
    FROM users u
    LEFT JOIN solves s ON u.id = s.user_id
    GROUP BY u.id, u.username
    ORDER BY total_points DESC,
             CASE WHEN last_solve_time IS NULL THEN 1 ELSE 0 END ASC,
             last_solve_time ASC,
             u.id ASC
  `).all();

  return rows.map((row, idx) => ({
    rank: idx + 1,
    userId: row.user_id,
    username: row.username,
    totalPoints: row.total_points,
    solvedCount: row.solved_count,
    lastSolveTime: row.last_solve_time,
    isCurrentParticipant: currentUserId ? row.user_id === currentUserId : false
  }));
}

// Get participant dashboard stats
function getUserStats(userId) {
  if (!userId) return null;

  const user = db.prepare('SELECT id, username, email FROM users WHERE id = ?').get(userId);
  if (!user) return null;

  const solves = db.prepare(`
    SELECT challenge_id, points, solved_at FROM solves WHERE user_id = ?
  `).all(userId);

  const totalPoints = solves.reduce((sum, s) => sum + s.points, 0);

  // Calculate current rank
  const leaderboard = getLeaderboard();
  const entry = leaderboard.find(l => l.userId === userId);
  const rank = entry ? entry.rank : leaderboard.length + 1;

  return {
    id: user.id,
    username: user.username,
    email: user.email,
    rank,
    totalPoints,
    solvedCount: solves.length,
    solves: solves.map(s => s.challenge_id)
  };
}

// Rate limiting support
const submissionRateMap = new Map(); // userId -> [timestamps]

function checkRateLimit(userId) {
  const now = Date.now();
  const windowMs = 5000; // 5 seconds
  const maxAttempts = 3;  // max 3 submissions per 5 seconds

  let timestamps = submissionRateMap.get(userId) || [];
  timestamps = timestamps.filter(t => now - t < windowMs);

  if (timestamps.length >= maxAttempts) {
    const oldest = timestamps[0];
    const waitSeconds = Math.ceil((windowMs - (now - oldest)) / 1000);
    return { limited: true, waitSeconds: Math.max(1, waitSeconds) };
  }

  timestamps.push(now);
  submissionRateMap.set(userId, timestamps);
  return { limited: false };
}

// Seed initial demo data if database is fresh
function seedDemoDataIfNeeded() {
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  if (userCount > 0) return;

  console.log('Seeding initial competition participants...');

  // 1. Set competition metadata
  const startTime = new Date(Date.now() - 3 * 3600 * 1000).toISOString(); // started 3 hours ago
  const endTime = new Date(Date.now() + 21 * 3600 * 1000).toISOString();  // ends in 21 hours
  const insertConfig = db.prepare('INSERT OR REPLACE INTO competition_config (key, value) VALUES (?, ?)');
  insertConfig.run('competition_name', 'KRYPTEIA CTF 2026');
  insertConfig.run('institution', "St. Peter's Engineering College");
  insertConfig.run('club', 'Krypteia — The Cyber Security Technical Club');
  insertConfig.run('status', 'Live');
  insertConfig.run('start_time', startTime);
  insertConfig.run('end_time', endTime);

  // 2. Seed realistic college participants
  const demoUsers = [
    { username: 'CipherViper', email: 'cipher@spec.ac.in', solves: ['gen-01', 'crypto-01', 'web-01', 'forensics-01'], offsetMin: 140 },
    { username: 'NullByte_Spec', email: 'nullbyte@spec.ac.in', solves: ['gen-01', 'crypto-01', 'osint-01'], offsetMin: 110 },
    { username: 'ZeroDayGhost', email: 'zeroday@spec.ac.in', solves: ['gen-01', 'web-01'], offsetMin: 90 },
    { username: 'ByteBandit', email: 'bandit@spec.ac.in', solves: ['gen-01'], offsetMin: 45 }
  ];

  const pointsMap = {
    'gen-01': 50,
    'crypto-01': 100,
    'web-01': 150,
    'forensics-01': 200,
    'netsec-01': 200,
    'osint-01': 150,
    'crypto-02': 250,
    'web-02': 175
  };

  const nowMs = Date.now();

  for (const d of demoUsers) {
    const user = createUser(d.username, d.email, 'Krypteia#2026', 1);
    let solveTimeMs = nowMs - d.offsetMin * 60 * 1000;

    for (const chId of d.solves) {
      const pts = pointsMap[chId] || 100;
      const solvedAt = new Date(solveTimeMs).toISOString();
      db.prepare(`
        INSERT INTO solves (user_id, challenge_id, points, solved_at)
        VALUES (?, ?, ?, ?)
      `).run(user.id, chId, pts, solvedAt);
      solveTimeMs += 12 * 60 * 1000; // subsequent solve 12 mins later
    }
  }

  console.log('Seeded demo participants successfully.');
}

seedDemoDataIfNeeded();

function getCompetitionConfig() {
  const rows = db.prepare('SELECT key, value FROM competition_config').all();
  const config = {
    name: 'KRYPTEIA CTF 2026',
    club: 'Krypteia — The Cyber Security Technical Club',
    institution: "St. Peter's Engineering College",
    status: 'Live',
    startTime: new Date(Date.now() - 3 * 3600 * 1000).toISOString(),
    endTime: new Date(Date.now() + 21 * 3600 * 1000).toISOString()
  };

  rows.forEach(r => {
    if (r.key === 'competition_name') config.name = r.value;
    if (r.key === 'club') config.club = r.value;
    if (r.key === 'institution') config.institution = r.value;
    if (r.key === 'status') config.status = r.value;
    if (r.key === 'start_time') config.startTime = r.value;
    if (r.key === 'end_time') config.endTime = r.value;
  });

  return config;
}

module.exports = {
  db,
  createUser,
  authenticateUser,
  createSession,
  getUserBySession,
  deleteSession,
  recordSolve,
  recordSubmission,
  getUserSolves,
  getChallengeSolveCounts,
  getLeaderboard,
  getUserStats,
  checkRateLimit,
  getCompetitionConfig
};
