const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

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

// -------------------------------------------------------------
// Engine 1: SQLite Engine (via better-sqlite3)
// -------------------------------------------------------------
let sqliteDb = null;
let useSqlite = false;

try {
  if (process.env.FORCE_MEMORY_DB) {
    throw new Error('Forced memory store for testing');
  }
  const Database = require('better-sqlite3');
  let dataDir;
  let dbPath;

  // If in Vercel or read-only serverless environment, use /tmp
  if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) {
    dataDir = path.join(os.tmpdir(), 'krypteia_data');
    try {
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }
      dbPath = path.join(dataDir, 'krypteia_ctf.db');
      sqliteDb = new Database(dbPath);
    } catch (e) {
      // In-memory sqlite fallback if /tmp fails
      sqliteDb = new Database(':memory:');
    }
  } else {
    dataDir = path.join(__dirname, 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    dbPath = path.join(dataDir, 'krypteia_ctf.db');
    sqliteDb = new Database(dbPath);
  }

  // WAL mode (ignore error on memory db)
  try {
    sqliteDb.pragma('journal_mode = WAL');
  } catch (_) {}
  sqliteDb.pragma('foreign_keys = ON');

  // Initialize schema
  sqliteDb.exec(`
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

    CREATE TABLE IF NOT EXISTS challenge_locks (
      challenge_id TEXT PRIMARY KEY,
      is_locked INTEGER DEFAULT 0,
      updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS admin_sessions (
      token TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
  `);

  useSqlite = true;
} catch (err) {
  console.warn('better-sqlite3 unavailable or failed to initialize (' + err.message + '). Using pure-JS resilient in-memory engine.');
  useSqlite = false;
  sqliteDb = null;
}

// -------------------------------------------------------------
// Engine 2: Pure-JS In-Memory Resilient Engine (Zero native dependencies, 100% Vercel Serverless safe)
// -------------------------------------------------------------
const memoryStore = {
  users: [],
  sessions: [],
  adminSessions: [],
  solves: [],
  submissions: [],
  challengeLocks: {},
  config: {
    competition_name: 'KRYPTEIA CTF 2026',
    club: 'Krypteia — The Cyber Security Technical Club',
    institution: "St. Peter's Engineering College",
    status: 'Live',
    start_time: new Date(Date.now() - 3 * 3600 * 1000).toISOString(),
    end_time: new Date(Date.now() + 21 * 3600 * 1000).toISOString()
  },
  nextUserId: 1,
  nextSolveId: 1,
  nextSubId: 1
};

// -------------------------------------------------------------
// Unified Database Interface Implementation
// -------------------------------------------------------------

function validateUserInput(username, email, password) {
  const cleanUsername = (username || '').trim();
  const cleanEmail = (email || '').trim().toLowerCase();

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
  return { cleanUsername, cleanEmail };
}

function createUser(username, email, password, isDemo = 0) {
  const { cleanUsername, cleanEmail } = validateUserInput(username, email, password);

  if (useSqlite) {
    const existingUser = sqliteDb.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(cleanUsername, cleanEmail);
    if (existingUser) {
      throw new Error('Username or email is already registered');
    }

    const { salt, hash } = hashPassword(password);
    const now = new Date().toISOString();

    const stmt = sqliteDb.prepare(`
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
  } else {
    const exists = memoryStore.users.some(u => 
      u.username.toLowerCase() === cleanUsername.toLowerCase() || 
      u.email.toLowerCase() === cleanEmail.toLowerCase()
    );
    if (exists) {
      throw new Error('Username or email is already registered');
    }

    const { salt, hash } = hashPassword(password);
    const now = new Date().toISOString();
    const newUser = {
      id: memoryStore.nextUserId++,
      username: cleanUsername,
      email: cleanEmail,
      password_hash: hash,
      salt: salt,
      is_demo: isDemo ? 1 : 0,
      created_at: now
    };
    memoryStore.users.push(newUser);
    return {
      id: newUser.id,
      username: newUser.username,
      email: newUser.email,
      created_at: newUser.created_at
    };
  }
}

function authenticateUser(identifier, password) {
  const cleanId = (identifier || '').trim();
  if (!cleanId || !password) {
    throw new Error('Identifier and password are required');
  }

  if (useSqlite) {
    const user = sqliteDb.prepare(`
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
  } else {
    const cleanLower = cleanId.toLowerCase();
    const user = memoryStore.users.find(u => 
      u.username.toLowerCase() === cleanLower || 
      u.email.toLowerCase() === cleanLower
    );

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
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // 7 days

  if (useSqlite) {
    sqliteDb.prepare(`
      INSERT INTO sessions (token, user_id, created_at, expires_at)
      VALUES (?, ?, ?, ?)
    `).run(token, userId, now.toISOString(), expiresAt.toISOString());
  } else {
    memoryStore.sessions.push({
      token,
      user_id: userId,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString()
    });
  }

  return token;
}

function getUserBySession(token) {
  if (!token) return null;
  const now = new Date().toISOString();

  if (useSqlite) {
    const session = sqliteDb.prepare(`
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
  } else {
    const session = memoryStore.sessions.find(s => s.token === token && s.expires_at > now);
    if (!session) return null;

    const user = memoryStore.users.find(u => u.id === session.user_id);
    if (!user) return null;

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      created_at: user.created_at
    };
  }
}

function deleteSession(token) {
  if (!token) return;
  if (useSqlite) {
    sqliteDb.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  } else {
    const idx = memoryStore.sessions.findIndex(s => s.token === token);
    if (idx !== -1) memoryStore.sessions.splice(idx, 1);
  }
}

function recordSolve(userId, challengeId, points) {
  const now = new Date().toISOString();

  if (useSqlite) {
    const insertSolveTx = sqliteDb.transaction(() => {
      const existing = sqliteDb.prepare(`
        SELECT id FROM solves WHERE user_id = ? AND challenge_id = ?
      `).get(userId, challengeId);

      if (existing) {
        return { alreadySolved: true };
      }

      sqliteDb.prepare(`
        INSERT INTO solves (user_id, challenge_id, points, solved_at)
        VALUES (?, ?, ?, ?)
      `).run(userId, challengeId, points, now);

      return { success: true, points, solved_at: now };
    });

    return insertSolveTx();
  } else {
    const existing = memoryStore.solves.find(s => s.user_id === userId && s.challenge_id === challengeId);
    if (existing) {
      return { alreadySolved: true };
    }

    memoryStore.solves.push({
      id: memoryStore.nextSolveId++,
      user_id: userId,
      challenge_id: challengeId,
      points,
      solved_at: now
    });

    return { success: true, points, solved_at: now };
  }
}

function recordSubmission(userId, challengeId, flagSubmitted, isCorrect) {
  const now = new Date().toISOString();
  const subFlag = (flagSubmitted || '').substring(0, 100);

  if (useSqlite) {
    sqliteDb.prepare(`
      INSERT INTO submissions (user_id, challenge_id, flag_submitted, is_correct, submitted_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(userId, challengeId, subFlag, isCorrect ? 1 : 0, now);
  } else {
    memoryStore.submissions.push({
      id: memoryStore.nextSubId++,
      user_id: userId,
      challenge_id: challengeId,
      flag_submitted: subFlag,
      is_correct: isCorrect ? 1 : 0,
      submitted_at: now
    });
  }
}

function getUserSolves(userId) {
  if (!userId) return [];
  if (useSqlite) {
    return sqliteDb.prepare(`
      SELECT challenge_id, points, solved_at FROM solves WHERE user_id = ? ORDER BY solved_at DESC
    `).all(userId);
  } else {
    return memoryStore.solves
      .filter(s => s.user_id === userId)
      .sort((a, b) => (b.solved_at > a.solved_at ? 1 : -1))
      .map(s => ({ challenge_id: s.challenge_id, points: s.points, solved_at: s.solved_at }));
  }
}

function getChallengeSolveCounts() {
  const map = {};
  if (useSqlite) {
    const rows = sqliteDb.prepare(`
      SELECT challenge_id, COUNT(*) as count FROM solves GROUP BY challenge_id
    `).all();
    rows.forEach(r => { map[r.challenge_id] = r.count; });
  } else {
    memoryStore.solves.forEach(s => {
      map[s.challenge_id] = (map[s.challenge_id] || 0) + 1;
    });
  }
  return map;
}

function getLeaderboard(currentUserId = null) {
  if (useSqlite) {
    const rows = sqliteDb.prepare(`
      SELECT 
        u.id as user_id,
        u.username,
        u.created_at,
        COALESCE(SUM(s.points), 0) as total_points,
        COUNT(s.id) as solved_count,
        MAX(s.solved_at) as last_solve_time
      FROM users u
      LEFT JOIN solves s ON u.id = s.user_id
      GROUP BY u.id, u.username, u.created_at
      ORDER BY total_points DESC,
               CASE WHEN last_solve_time IS NULL THEN 1 ELSE 0 END ASC,
               last_solve_time ASC,
               u.created_at ASC,
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
  } else {
    // Group solves by user
    const userScores = memoryStore.users.map(u => {
      const userSolves = memoryStore.solves.filter(s => s.user_id === u.id);
      const totalPoints = userSolves.reduce((sum, s) => sum + s.points, 0);
      let lastSolveTime = null;
      if (userSolves.length > 0) {
        lastSolveTime = userSolves.reduce((max, s) => (s.solved_at > max ? s.solved_at : max), userSolves[0].solved_at);
      }
      return {
        user_id: u.id,
        username: u.username,
        created_at: u.created_at,
        total_points: totalPoints,
        solved_count: userSolves.length,
        last_solve_time: lastSolveTime
      };
    });

    userScores.sort((a, b) => {
      // 1. Points priority (higher points first)
      if (b.total_points !== a.total_points) {
        return b.total_points - a.total_points;
      }
      // 2. Earliest last solve time has priority
      if (a.last_solve_time && !b.last_solve_time) return -1;
      if (!a.last_solve_time && b.last_solve_time) return 1;
      if (a.last_solve_time && b.last_solve_time) {
        if (a.last_solve_time < b.last_solve_time) return -1;
        if (a.last_solve_time > b.last_solve_time) return 1;
      }
      // 3. For 0-solve users: earlier registration wins
      if (a.created_at && b.created_at && a.created_at !== b.created_at) {
        return a.created_at < b.created_at ? -1 : 1;
      }
      return a.user_id - b.user_id;
    });

    return userScores.map((row, idx) => ({
      rank: idx + 1,
      userId: row.user_id,
      username: row.username,
      totalPoints: row.total_points,
      solvedCount: row.solved_count,
      lastSolveTime: row.last_solve_time,
      isCurrentParticipant: currentUserId ? row.user_id === currentUserId : false
    }));
  }
}

function getUserStats(userId) {
  if (!userId) return null;

  if (useSqlite) {
    const user = sqliteDb.prepare('SELECT id, username, email FROM users WHERE id = ?').get(userId);
    if (!user) return null;

    const solves = sqliteDb.prepare(`
      SELECT challenge_id, points, solved_at FROM solves WHERE user_id = ?
    `).all(userId);

    const totalPoints = solves.reduce((sum, s) => sum + s.points, 0);
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
  } else {
    const user = memoryStore.users.find(u => u.id === userId);
    if (!user) return null;

    const solves = memoryStore.solves.filter(s => s.user_id === userId);
    const totalPoints = solves.reduce((sum, s) => sum + s.points, 0);
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
}

// Rate limiting support
const submissionRateMap = new Map();

function checkRateLimit(userId) {
  const now = Date.now();
  const windowMs = 5000;
  const maxAttempts = 3;

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

// Initialize competition configuration
function initCompetitionConfigIfNeeded() {
  const startTime = new Date(Date.now() - 3 * 3600 * 1000).toISOString();
  const endTime = new Date(Date.now() + 21 * 3600 * 1000).toISOString();

  if (useSqlite) {
    const configCount = sqliteDb.prepare('SELECT COUNT(*) as count FROM competition_config').get().count;
    if (configCount === 0) {
      const insertConfig = sqliteDb.prepare('INSERT OR REPLACE INTO competition_config (key, value) VALUES (?, ?)');
      insertConfig.run('competition_name', 'KRYPTEIA CTF 2026');
      insertConfig.run('institution', "St. Peter's Engineering College");
      insertConfig.run('club', 'Krypteia — The Cyber Security Technical Club');
      insertConfig.run('status', 'Live');
      insertConfig.run('start_time', startTime);
      insertConfig.run('end_time', endTime);
    }
  } else {
    if (!memoryStore.config) {
      memoryStore.config = {
        competition_name: 'KRYPTEIA CTF 2026',
        club: 'Krypteia — The Cyber Security Technical Club',
        institution: "St. Peter's Engineering College",
        status: 'Live',
        start_time: startTime,
        end_time: endTime
      };
    }
  }
}

// Clear all participants, solves, sessions, and submissions to start fresh
function clearAllParticipants() {
  if (useSqlite) {
    sqliteDb.transaction(() => {
      sqliteDb.exec(`
        DELETE FROM sessions;
        DELETE FROM solves;
        DELETE FROM submissions;
        DELETE FROM users;
      `);
      try {
        sqliteDb.exec(`DELETE FROM sqlite_sequence WHERE name IN ('users', 'solves', 'submissions');`);
      } catch (_) {}
    })();
    return { success: true, message: 'All participants, solves, sessions, and submissions cleared.' };
  } else {
    memoryStore.users = [];
    memoryStore.sessions = [];
    memoryStore.solves = [];
    memoryStore.submissions = [];
    memoryStore.nextUserId = 1;
    memoryStore.nextSolveId = 1;
    memoryStore.nextSubId = 1;
    return { success: true, message: 'All participants, solves, sessions, and submissions cleared from memory.' };
  }
}

// Seed initial competition demo participants only if SEED_DEMO_DATA is explicitly true
function seedDemoDataIfNeeded() {
  if (process.env.SEED_DEMO_DATA !== 'true') {
    return;
  }

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

  const demoUsers = [
    { username: 'CipherViper', email: 'cipher@spec.ac.in', solves: ['gen-01', 'crypto-01', 'web-01', 'forensics-01'], offsetMin: 140 },
    { username: 'NullByte_Spec', email: 'nullbyte@spec.ac.in', solves: ['gen-01', 'crypto-01', 'osint-01'], offsetMin: 110 },
    { username: 'ZeroDayGhost', email: 'zeroday@spec.ac.in', solves: ['gen-01', 'web-01'], offsetMin: 90 },
    { username: 'ByteBandit', email: 'bandit@spec.ac.in', solves: ['gen-01'], offsetMin: 45 }
  ];

  const nowMs = Date.now();

  if (useSqlite) {
    const userCount = sqliteDb.prepare('SELECT COUNT(*) as count FROM users').get().count;
    if (userCount > 0) return;

    for (const d of demoUsers) {
      const user = createUser(d.username, d.email, 'Krypteia#2026', 1);
      let solveTimeMs = nowMs - d.offsetMin * 60 * 1000;

      for (const chId of d.solves) {
        const pts = pointsMap[chId] || 100;
        const solvedAt = new Date(solveTimeMs).toISOString();
        sqliteDb.prepare(`
          INSERT INTO solves (user_id, challenge_id, points, solved_at)
          VALUES (?, ?, ?, ?)
        `).run(user.id, chId, pts, solvedAt);
        solveTimeMs += 12 * 60 * 1000;
      }
    }
  } else {
    if (memoryStore.users.length > 0) return;

    for (const d of demoUsers) {
      const user = createUser(d.username, d.email, 'Krypteia#2026', 1);
      let solveTimeMs = nowMs - d.offsetMin * 60 * 1000;

      for (const chId of d.solves) {
        const pts = pointsMap[chId] || 100;
        const solvedAt = new Date(solveTimeMs).toISOString();
        memoryStore.solves.push({
          id: memoryStore.nextSolveId++,
          user_id: user.id,
          challenge_id: chId,
          points: pts,
          solved_at: solvedAt
        });
        solveTimeMs += 12 * 60 * 1000;
      }
    }
  }
}

initCompetitionConfigIfNeeded();
seedDemoDataIfNeeded();

// IST (Indian Standard Time) formatting helper
function formatIST(dateInput) {
  if (!dateInput) return 'N/A';
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return 'N/A';
  return d.toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  }) + ' IST';
}

function getCompetitionConfig() {
  let rawConfig;
  if (useSqlite) {
    const rows = sqliteDb.prepare('SELECT key, value FROM competition_config').all();
    rawConfig = {
      name: 'KRYPTEIA CTF 2026',
      club: 'Krypteia — The Cyber Security Technical Club',
      institution: "St. Peter's Engineering College",
      status: 'Live',
      startTime: new Date(Date.now() - 3 * 3600 * 1000).toISOString(),
      endTime: new Date(Date.now() + 21 * 3600 * 1000).toISOString()
    };

    rows.forEach(r => {
      if (r.key === 'competition_name') rawConfig.name = r.value;
      if (r.key === 'club') rawConfig.club = r.value;
      if (r.key === 'institution') rawConfig.institution = r.value;
      if (r.key === 'status') rawConfig.status = r.value;
      if (r.key === 'start_time') rawConfig.startTime = r.value;
      if (r.key === 'end_time') rawConfig.endTime = r.value;
    });
  } else {
    rawConfig = {
      name: memoryStore.config.competition_name,
      club: memoryStore.config.club,
      institution: memoryStore.config.institution,
      status: memoryStore.config.status,
      startTime: memoryStore.config.start_time,
      endTime: memoryStore.config.end_time
    };
  }

  const now = new Date();
  const start = rawConfig.startTime ? new Date(rawConfig.startTime) : null;
  const end = rawConfig.endTime ? new Date(rawConfig.endTime) : null;

  let isStarted = true;
  let isEnded = false;
  let computedStatus = rawConfig.status || 'Live';

  if (start && !isNaN(start.getTime()) && now < start) {
    isStarted = false;
    computedStatus = 'Upcoming';
  } else if (end && !isNaN(end.getTime()) && now > end) {
    isStarted = true;
    isEnded = true;
    computedStatus = 'Ended';
  } else {
    isStarted = true;
    computedStatus = 'Live';
  }

  return {
    ...rawConfig,
    status: computedStatus,
    isStarted,
    isEnded,
    serverTime: now.toISOString(),
    startTimeIST: start ? formatIST(start) : 'N/A',
    endTimeIST: end ? formatIST(end) : 'N/A',
    serverTimeIST: formatIST(now)
  };
}

function setCompetitionTimer(startTimeIso, endTimeIso = null, status = null) {
  if (useSqlite) {
    sqliteDb.transaction(() => {
      const upsert = sqliteDb.prepare('INSERT OR REPLACE INTO competition_config (key, value) VALUES (?, ?)');
      if (startTimeIso) upsert.run('start_time', startTimeIso);
      if (endTimeIso) upsert.run('end_time', endTimeIso);
      if (status) upsert.run('status', status);
    })();
  } else {
    if (startTimeIso) memoryStore.config.start_time = startTimeIso;
    if (endTimeIso) memoryStore.config.end_time = endTimeIso;
    if (status) memoryStore.config.status = status;
  }
  return getCompetitionConfig();
}

// -------------------------------------------------------------
// Challenge Locks Management
// -------------------------------------------------------------
function getChallengeLocks() {
  const map = {};
  if (useSqlite) {
    const rows = sqliteDb.prepare('SELECT challenge_id, is_locked FROM challenge_locks').all();
    rows.forEach(r => {
      map[r.challenge_id] = Boolean(r.is_locked);
    });
  } else {
    Object.keys(memoryStore.challengeLocks || {}).forEach(k => {
      map[k] = Boolean(memoryStore.challengeLocks[k]);
    });
  }
  return map;
}

function isChallengeLocked(challengeId) {
  if (!challengeId) return false;
  if (useSqlite) {
    const row = sqliteDb.prepare('SELECT is_locked FROM challenge_locks WHERE challenge_id = ?').get(challengeId);
    return row ? Boolean(row.is_locked) : false;
  } else {
    return Boolean((memoryStore.challengeLocks || {})[challengeId]);
  }
}

function setChallengeLock(challengeId, isLocked) {
  const val = isLocked ? 1 : 0;
  const now = new Date().toISOString();
  if (useSqlite) {
    sqliteDb.prepare(`
      INSERT INTO challenge_locks (challenge_id, is_locked, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(challenge_id) DO UPDATE SET is_locked = excluded.is_locked, updated_at = excluded.updated_at
    `).run(challengeId, val, now);
  } else {
    if (!memoryStore.challengeLocks) memoryStore.challengeLocks = {};
    memoryStore.challengeLocks[challengeId] = Boolean(isLocked);
  }
  return { challengeId, isLocked: Boolean(isLocked) };
}

function setAllChallengeLocks(challengeIds, isLocked) {
  const val = isLocked ? 1 : 0;
  const now = new Date().toISOString();
  if (useSqlite) {
    sqliteDb.transaction(() => {
      const stmt = sqliteDb.prepare(`
        INSERT INTO challenge_locks (challenge_id, is_locked, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(challenge_id) DO UPDATE SET is_locked = excluded.is_locked, updated_at = excluded.updated_at
      `);
      challengeIds.forEach(id => {
        stmt.run(id, val, now);
      });
    })();
  } else {
    if (!memoryStore.challengeLocks) memoryStore.challengeLocks = {};
    challengeIds.forEach(id => {
      memoryStore.challengeLocks[id] = Boolean(isLocked);
    });
  }
  return getChallengeLocks();
}

// -------------------------------------------------------------
// Administrator Session Management
// -------------------------------------------------------------
function createAdminSession() {
  const token = crypto.randomBytes(32).toString('hex');
  const now = new Date();
  const expires = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours

  if (useSqlite) {
    sqliteDb.prepare('INSERT INTO admin_sessions (token, created_at, expires_at) VALUES (?, ?, ?)')
      .run(token, now.toISOString(), expires.toISOString());
  } else {
    if (!memoryStore.adminSessions) memoryStore.adminSessions = [];
    memoryStore.adminSessions.push({
      token,
      created_at: now.toISOString(),
      expires_at: expires.toISOString()
    });
  }
  return token;
}

function validateAdminSession(token) {
  if (!token) return false;
  const now = new Date().toISOString();
  if (useSqlite) {
    const row = sqliteDb.prepare('SELECT token FROM admin_sessions WHERE token = ? AND expires_at > ?').get(token, now);
    return Boolean(row);
  } else {
    const s = (memoryStore.adminSessions || []).find(item => item.token === token && item.expires_at > now);
    return Boolean(s);
  }
}

function deleteAdminSession(token) {
  if (!token) return;
  if (useSqlite) {
    sqliteDb.prepare('DELETE FROM admin_sessions WHERE token = ?').run(token);
  } else {
    memoryStore.adminSessions = (memoryStore.adminSessions || []).filter(s => s.token !== token);
  }
}

// -------------------------------------------------------------
// Detailed Leaderboard Export & Sheet Generation
// -------------------------------------------------------------
function getDetailedLeaderboardForExport() {
  const leaderboard = getLeaderboard();
  if (useSqlite) {
    const usersMap = {};
    sqliteDb.prepare('SELECT id, email, created_at FROM users').all().forEach(u => {
      usersMap[u.id] = u;
    });

    const solvesMap = {};
    sqliteDb.prepare('SELECT user_id, challenge_id FROM solves ORDER BY solved_at ASC').all().forEach(s => {
      if (!solvesMap[s.user_id]) solvesMap[s.user_id] = [];
      solvesMap[s.user_id].push(s.challenge_id);
    });

    return leaderboard.map(entry => {
      const user = usersMap[entry.userId] || {};
      const solvedList = (solvesMap[entry.userId] || []).join('; ');
      return {
        rank: entry.rank,
        username: entry.username,
        email: user.email || 'N/A',
        totalPoints: entry.totalPoints,
        solvedCount: entry.solvedCount,
        solvedChallenges: solvedList || 'None',
        lastSolveTimeIST: entry.lastSolveTime ? formatIST(entry.lastSolveTime) : 'N/A',
        registeredAtIST: user.created_at ? formatIST(user.created_at) : 'N/A'
      };
    });
  } else {
    return leaderboard.map(entry => {
      const user = memoryStore.users.find(u => u.id === entry.userId) || {};
      const solves = memoryStore.solves.filter(s => s.user_id === entry.userId);
      const solvedList = solves.map(s => s.challenge_id).join('; ');
      return {
        rank: entry.rank,
        username: entry.username,
        email: user.email || 'N/A',
        totalPoints: entry.totalPoints,
        solvedCount: entry.solvedCount,
        solvedChallenges: solvedList || 'None',
        lastSolveTimeIST: entry.lastSolveTime ? formatIST(entry.lastSolveTime) : 'N/A',
        registeredAtIST: user.created_at ? formatIST(user.created_at) : 'N/A'
      };
    });
  }
}

function generateLeaderboardCSV() {
  const data = getDetailedLeaderboardForExport();
  const headers = [
    'Rank',
    'Username / Team',
    'Email Address',
    'Total Points',
    'Challenges Solved Count',
    'Solved Challenge IDs',
    'Last Solve Time (IST)',
    'Registration Time (IST)'
  ];

  const escapeCSV = (val) => {
    if (val === null || val === undefined) return '""';
    const s = String(val).replace(/"/g, '""');
    return `"${s}"`;
  };

  const rows = [headers.map(escapeCSV).join(',')];

  data.forEach(item => {
    rows.push([
      item.rank,
      escapeCSV(item.username),
      escapeCSV(item.email),
      item.totalPoints,
      item.solvedCount,
      escapeCSV(item.solvedChallenges),
      escapeCSV(item.lastSolveTimeIST),
      escapeCSV(item.registeredAtIST)
    ].join(','));
  });

  // Prepend UTF-8 Byte Order Mark (BOM) so Excel opens UTF-8 properly without broken characters
  return '\uFEFF' + rows.join('\r\n');
}

module.exports = {
  db: sqliteDb,
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
  getCompetitionConfig,
  setCompetitionTimer,
  formatIST,
  getChallengeLocks,
  isChallengeLocked,
  setChallengeLock,
  setAllChallengeLocks,
  createAdminSession,
  validateAdminSession,
  deleteAdminSession,
  getDetailedLeaderboardForExport,
  generateLeaderboardCSV,
  clearAllParticipants,
  initCompetitionConfigIfNeeded
};
