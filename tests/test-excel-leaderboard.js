const assert = require('assert');
const fs = require('fs');
const path = require('path');
const xlsx = require('xlsx');
const http = require('http');

const excelLeaderboard = require('../excel-leaderboard');
const serverApp = require('../server');

const TEST_EXCEL_PATH = excelLeaderboard.EXCEL_FILE_PATH;

async function runTests() {
  console.log('--- Starting CTF Leaderboard & Excel Integration Tests ---');

  // Test 1: Verify Excel reading & descending point sort
  console.log('\n[Test 1] Verifying Excel parsing and descending sort order...');
  const initialData = excelLeaderboard.readExcelLeaderboard();
  assert(Array.isArray(initialData.teams), 'Teams must be an array');
  assert(initialData.teams.length >= 3, 'Must have at least 3 sample teams');

  for (let i = 0; i < initialData.teams.length - 1; i++) {
    const current = initialData.teams[i];
    const next = initialData.teams[i + 1];
    assert(
      current.points >= next.points,
      `Sort violation: Team ${current.teamName} (${current.points}) should be >= Team ${next.teamName} (${next.points})`
    );
  }
  console.log('✓ Teams are correctly sorted from highest points to lowest.');

  // Test 2: Verify Top 3 Highlighting flags
  console.log('\n[Test 2] Verifying Top 3 highlighting...');
  const top1 = initialData.teams[0];
  const top2 = initialData.teams[1];
  const top3 = initialData.teams[2];
  const rank4 = initialData.teams[3];

  assert(top1.rank === 1 && top1.isFirst === true && top1.isTop3 === true, '1st place flags failed');
  assert(top2.rank === 2 && top2.isSecond === true && top2.isTop3 === true, '2nd place flags failed');
  assert(top3.rank === 3 && top3.isThird === true && top3.isTop3 === true, '3rd place flags failed');
  if (rank4) {
    assert(rank4.rank === 4 && rank4.isTop3 === false, '4th place should not be marked isTop3');
  }
  console.log(`✓ Top 3 successfully flagged: 1st=${top1.teamName} (${top1.points}), 2nd=${top2.teamName} (${top2.points}), 3rd=${top3.teamName} (${top3.points}).`);

  // Test 3: Verify Column Constraint (Team Name & Points)
  console.log('\n[Test 3] Verifying strict Two-Column data structure (Team Name and Points)...');
  initialData.teams.forEach((team) => {
    assert(typeof team.teamName === 'string' && team.teamName.length > 0, 'teamName must be a valid string');
    assert(typeof team.points === 'number' && !isNaN(team.points), 'points must be a valid number');
  });
  console.log('✓ All records adhere strictly to Team Name and Points.');

  // Test 4: Verify Dynamic Update upon Excel File Modification
  console.log('\n[Test 4] Verifying automatic update when Excel sheet changes on disk...');
  const originalBuffer = fs.readFileSync(TEST_EXCEL_PATH);

  // Create an updated workbook where a new team "ApexPredators" takes 1st place with 9999 pts
  const testWb = xlsx.read(originalBuffer, { type: 'buffer' });
  const sheetName = testWb.SheetNames[0];
  const sheet = testWb.Sheets[sheetName];
  const sheetData = xlsx.utils.sheet_to_json(sheet);
  
  sheetData.push({ 'Team Name': 'ApexPredators_Test', 'Points': 9999 });
  const updatedSheet = xlsx.utils.json_to_sheet(sheetData);
  testWb.Sheets[sheetName] = updatedSheet;
  const newBuffer = xlsx.write(testWb, { type: 'buffer', bookType: 'xlsx' });

  // Write new buffer to Excel file
  fs.writeFileSync(TEST_EXCEL_PATH, newBuffer);

  // Read updated sheet
  const updatedData = excelLeaderboard.readExcelLeaderboard();
  assert.strictEqual(updatedData.teams[0].teamName, 'ApexPredators_Test', 'New team should take 1st place');
  assert.strictEqual(updatedData.teams[0].points, 9999, 'New team score should be 9999');
  assert.strictEqual(updatedData.teams[0].rank, 1, 'New team rank should be 1');
  console.log('✓ Dynamic update verified: ApexPredators_Test immediately ranked #1 with 9999 pts.');

  // Restore original Excel file
  fs.writeFileSync(TEST_EXCEL_PATH, originalBuffer);
  const restoredData = excelLeaderboard.readExcelLeaderboard();
  assert.notStrictEqual(restoredData.teams[0].teamName, 'ApexPredators_Test', 'Original data should be restored');
  console.log('✓ Original Excel workbook cleanly restored.');

  // Test 5: Verify HTTP API Endpoints
  console.log('\n[Test 5] Verifying HTTP Endpoints via Express Server...');
  const testPort = 3991;
  const server = http.createServer(serverApp);
  await new Promise((resolve) => server.listen(testPort, resolve));

  async function httpGet(path) {
    return new Promise((resolve, reject) => {
      http.get(`http://localhost:${testPort}${path}`, (res) => {
        let raw = '';
        res.on('data', chunk => raw += chunk);
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: raw }));
      }).on('error', reject);
    });
  }

  // 5a. Test /api/leaderboard/sheet
  const sheetRes = await httpGet('/api/leaderboard/sheet');
  assert.strictEqual(sheetRes.status, 200, 'GET /api/leaderboard/sheet should return 200');
  const sheetJson = JSON.parse(sheetRes.body);
  assert.strictEqual(sheetJson.success, true);
  assert(Array.isArray(sheetJson.teams));
  assert(sheetJson.teams.length > 0);
  console.log(`✓ /api/leaderboard/sheet returned 200 OK with ${sheetJson.teams.length} teams.`);

  // 5b. Test /api/leaderboard/download
  const downloadRes = await httpGet('/api/leaderboard/download');
  assert.strictEqual(downloadRes.status, 200, 'GET /api/leaderboard/download should return 200');
  console.log('✓ /api/leaderboard/download returned 200 OK with attachment.');

  // 5c. Test root / HTML page
  const indexRes = await httpGet('/');
  assert.strictEqual(indexRes.status, 200, 'GET / should return 200');
  assert(indexRes.body.includes('KRYPTEIA'), 'HTML must include KRYPTEIA');
  assert(indexRes.body.includes('Team Name'), 'HTML must include Team Name column');
  assert(indexRes.body.includes('Points'), 'HTML must include Points column');
  assert(indexRes.body.includes('leaderboard.js'), 'HTML must link to leaderboard.js');
  console.log('✓ GET / successfully serves the minimal dark CTF leaderboard website.');

  server.close();
  console.log('\n======================================================');
  console.log('   ALL 5 TESTS PASSED SUCCESSFULLY!');
  console.log('======================================================\n');
}

runTests().catch((err) => {
  console.error('\n❌ Test Failure:', err);
  process.exit(1);
});
