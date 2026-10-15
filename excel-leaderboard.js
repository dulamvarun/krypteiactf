const fs = require('fs');
const path = require('path');
const xlsx = require('xlsx');

// Primary Excel sheet file path in project root
const EXCEL_FILE_PATH = path.join(__dirname, 'leaderboard.xlsx');

// Cached parsed leaderboard data
let cachedLeaderboard = {
  teams: [],
  lastUpdated: null,
  totalTeams: 0,
  topTeam: null
};

// Registered listeners for live updates (e.g., SSE connections)
const changeListeners = new Set();

/**
 * Creates default sample leaderboard.xlsx if file doesn't exist
 */
function ensureExcelFileExists() {
  if (!fs.existsSync(EXCEL_FILE_PATH)) {
    const wb = xlsx.utils.book_new();
    const defaultData = [
      ['Team Name', 'Points'],
      ['ByteBandits', 1450],
      ['NullPointers', 1320],
      ['CyberKnights', 1150],
      ['0xBitShift', 980],
      ['ShadowProtocol', 870],
      ['KernelPanic', 750],
      ['BinaryBeasts', 620],
      ['PhishBusters', 500],
      ['SYN_ACK_Attack', 420],
      ['CipherSquad', 350],
      ['DecryptionDuo', 280],
      ['PacketPioneers', 200]
    ];
    const ws = xlsx.utils.aoa_to_sheet(defaultData);
    xlsx.utils.book_append_sheet(wb, ws, 'Leaderboard');
    xlsx.writeFile(wb, EXCEL_FILE_PATH);
    console.log('[Excel Leaderboard] Created initial leaderboard.xlsx');
  }
}

/**
 * Normalizes column header names for flexible Excel format support
 */
function isTeamColumn(headerName) {
  if (!headerName || typeof headerName !== 'string') return false;
  const h = headerName.trim().toLowerCase().replace(/[\s_-]+/g, '');
  return ['teamname', 'team', 'name', 'participant', 'handle', 'user', 'teamtitle'].includes(h);
}

function isPointsColumn(headerName) {
  if (!headerName || typeof headerName !== 'string') return false;
  const h = headerName.trim().toLowerCase().replace(/[\s_-]+/g, '');
  return ['points', 'score', 'pts', 'totalpoints', 'marks', 'point'].includes(h);
}

/**
 * Reads and parses the Excel sheet, sorts by points descending, and highlights top 3
 */
function readExcelLeaderboard() {
  ensureExcelFileExists();

  try {
    const fileBuffer = fs.readFileSync(EXCEL_FILE_PATH);
    const workbook = xlsx.read(fileBuffer, { type: 'buffer' });

    if (!workbook.SheetNames || workbook.SheetNames.length === 0) {
      return cachedLeaderboard;
    }

    // Use first sheet
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    const rawRows = xlsx.utils.sheet_to_json(sheet, { defval: '' });

    if (!Array.isArray(rawRows) || rawRows.length === 0) {
      cachedLeaderboard = {
        teams: [],
        lastUpdated: new Date().toISOString(),
        totalTeams: 0,
        topTeam: null
      };
      return cachedLeaderboard;
    }

    // Inspect headers of first row to map column keys
    const firstRow = rawRows[0];
    const keys = Object.keys(firstRow);

    let teamKey = keys.find(k => isTeamColumn(k));
    let pointsKey = keys.find(k => isPointsColumn(k));

    // Fallbacks if headers didn't match standard names: assume Col 1 is Team, Col 2 is Points
    if (!teamKey && keys.length > 0) teamKey = keys[0];
    if (!pointsKey && keys.length > 1) pointsKey = keys[1];

    const teamList = [];

    for (const row of rawRows) {
      const rawName = row[teamKey];
      const rawPoints = row[pointsKey];

      if (rawName === undefined || rawName === null) continue;
      const teamName = String(rawName).trim();
      if (!teamName || teamName.toLowerCase() === 'team name' || teamName.toLowerCase() === 'team') {
        continue;
      }

      // Parse numerical points cleanly (strip commas, spaces, etc.)
      let points = 0;
      if (typeof rawPoints === 'number') {
        points = rawPoints;
      } else if (typeof rawPoints === 'string') {
        const cleanPoints = rawPoints.replace(/[^0-9.-]/g, '');
        points = parseFloat(cleanPoints) || 0;
      }

      teamList.push({
        teamName,
        points: Math.round(points)
      });
    }

    // Sort by points descending (highest to lowest); tie-break alphabetically by team name
    teamList.sort((a, b) => {
      if (b.points !== a.points) {
        return b.points - a.points;
      }
      return a.teamName.localeCompare(b.teamName);
    });

    // Assign ranks and top-3 highlights
    const rankedTeams = teamList.map((team, idx) => {
      const rank = idx + 1;
      return {
        rank,
        teamName: team.teamName,
        points: team.points,
        isTop3: rank <= 3,
        isFirst: rank === 1,
        isSecond: rank === 2,
        isThird: rank === 3
      };
    });

    const fileStat = fs.statSync(EXCEL_FILE_PATH);

    cachedLeaderboard = {
      teams: rankedTeams,
      lastUpdated: fileStat.mtime.toISOString(),
      totalTeams: rankedTeams.length,
      topTeam: rankedTeams.length > 0 ? rankedTeams[0] : null
    };

    return cachedLeaderboard;
  } catch (err) {
    console.error('[Excel Leaderboard] Error reading spreadsheet:', err.message);
    return cachedLeaderboard;
  }
}

/**
 * Broadcasts update to all registered SSE connections
 */
function notifyListeners() {
  const data = cachedLeaderboard;
  for (const listener of changeListeners) {
    try {
      listener(data);
    } catch (_) {
      changeListeners.delete(listener);
    }
  }
}

/**
 * Initializes automatic file watcher on leaderboard.xlsx
 */
let debounceTimer = null;

function initExcelWatcher() {
  ensureExcelFileExists();
  // Initial load
  readExcelLeaderboard();

  // Watch for changes using fs.watch
  try {
    fs.watch(EXCEL_FILE_PATH, (eventType) => {
      if (eventType === 'change' || eventType === 'rename') {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          // Retry with slight delay if file is locked during save
          setTimeout(() => {
            readExcelLeaderboard();
            notifyListeners();
            console.log(`[Excel Leaderboard] Excel sheet updated! Synced ${cachedLeaderboard.totalTeams} teams.`);
          }, 250);
        }, 150);
      }
    });
  } catch (err) {
    console.warn('[Excel Leaderboard] fs.watch notice:', err.message);
  }

  // Polling fallback every 2 seconds to ensure changes made by external programs are never missed
  fs.watchFile(EXCEL_FILE_PATH, { interval: 1500 }, (curr, prev) => {
    if (curr.mtimeMs !== prev.mtimeMs) {
      readExcelLeaderboard();
      notifyListeners();
    }
  });

  console.log('[Excel Leaderboard] Auto-watcher active on leaderboard.xlsx');
}

/**
 * Allows uploading / replacing leaderboard.xlsx programmatically or via API
 */
function updateExcelFile(buffer) {
  fs.writeFileSync(EXCEL_FILE_PATH, buffer);
  readExcelLeaderboard();
  notifyListeners();
  return cachedLeaderboard;
}

module.exports = {
  EXCEL_FILE_PATH,
  initExcelWatcher,
  readExcelLeaderboard,
  getLeaderboardData: () => cachedLeaderboard,
  updateExcelFile,
  addListener: (fn) => changeListeners.add(fn),
  removeListener: (fn) => changeListeners.delete(fn)
};
