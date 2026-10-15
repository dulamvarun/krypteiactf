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
      ['Rank', 'Team Name', 'Points'],
      [1, 'Hash-Cracks', 1100],
      [2, 'F Society', 950],
      [3, 'Elite Minds', 900],
      [4, 'Black Hat', 750],
      [5, 'Karunya', 550],
      [5, 'GriftiT', 550],
      [7, 'Space', 500],
      [7, 'Ctrl-Z', 500],
      [7, 'Data Dynamics', 500],
      [10, 'Vikings', 475],
      [11, 'Mogers', 300],
      [11, 'Data Dynamic', 300],
      [13, 'Raiders', 0]
    ];
    const ws = xlsx.utils.aoa_to_sheet(defaultData);
    xlsx.utils.book_append_sheet(wb, ws, 'Leaderboard');
    xlsx.writeFile(wb, EXCEL_FILE_PATH);
    console.log('[Excel Leaderboard] Created initial leaderboard.xlsx with Krypteia teams');
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

function isRankColumn(headerName) {
  if (!headerName || typeof headerName !== 'string') return false;
  const h = headerName.trim().toLowerCase().replace(/[\s_#-]+/g, '');
  return ['rank', 'pos', 'position', 'rk', 'place', 'no'].includes(h);
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

    let rankKey = keys.find(k => isRankColumn(k));
    let teamKey = keys.find(k => isTeamColumn(k));
    let pointsKey = keys.find(k => isPointsColumn(k));

    // Fallbacks if headers didn't match standard names: assume Col 1 is Team, Col 2 is Points
    if (!teamKey && keys.length > 0) teamKey = keys[0];
    if (!pointsKey && keys.length > 1) pointsKey = keys[1];

    const teamList = [];

    rawRows.forEach((row, originalIndex) => {
      const rawName = row[teamKey];
      const rawPoints = row[pointsKey];

      if (rawName === undefined || rawName === null) return;
      const teamName = String(rawName).trim();
      if (!teamName || teamName.toLowerCase() === 'team name' || teamName.toLowerCase() === 'team') {
        return;
      }

      // Parse numerical points cleanly (strip commas, spaces, etc.)
      let points = 0;
      if (typeof rawPoints === 'number') {
        points = rawPoints;
      } else if (typeof rawPoints === 'string') {
        const cleanPoints = rawPoints.replace(/[^0-9.-]/g, '');
        points = parseFloat(cleanPoints) || 0;
      }

      // Explicit rank from sheet if available
      let explicitRank = null;
      if (rankKey && row[rankKey] !== undefined && row[rankKey] !== '') {
        const parsed = parseInt(String(row[rankKey]).replace(/[^0-9]/g, ''), 10);
        if (!isNaN(parsed) && parsed > 0) explicitRank = parsed;
      }

      teamList.push({
        teamName,
        points: Math.round(points),
        explicitRank,
        originalIndex
      });
    });

    // Sort by points descending (highest to lowest); maintain original sheet order for ties
    teamList.sort((a, b) => {
      if (b.points !== a.points) {
        return b.points - a.points;
      }
      return a.originalIndex - b.originalIndex;
    });

    // Standard competition ranking (1224 style) or explicit rank from sheet
    let currentRank = 1;
    const rankedTeams = teamList.map((team, idx) => {
      if (team.explicitRank) {
        currentRank = team.explicitRank;
      } else if (idx > 0 && team.points < teamList[idx - 1].points) {
        currentRank = idx + 1;
      }
      const rank = team.explicitRank || currentRank;
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
