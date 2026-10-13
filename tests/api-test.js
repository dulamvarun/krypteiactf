const assert = require('assert');
const app = require('../server');
const db = require('../database');
const { CHALLENGES } = require('../challenges');

// In-memory or local test server
const http = require('http');

let server;
let baseUrl;

async function request(path, options = {}) {
  const url = `${baseUrl}${path}`;
  const headers = options.headers || {};
  if (options.body && typeof options.body === 'object') {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }

  const res = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body: options.body
  });

  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {}

  return { status: res.status, headers: res.headers, text, json };
}

async function runTests() {
  console.log('--- Starting Krypteia CTF Test Suite ---');

  server = http.createServer(app);
  await new Promise(resolve => server.listen(0, resolve));
  const port = server.address().port;
  baseUrl = `http://localhost:${port}`;
  console.log(`Test server running on ${baseUrl}`);

  try {
    // Test 1: Config endpoint
    console.log('[1] Testing /api/config');
    const configRes = await request('/api/config');
    assert.strictEqual(configRes.status, 200);
    assert.strictEqual(configRes.json.status, 'Live');
    assert.strictEqual(configRes.json.totalChallenges, CHALLENGES.length);
    console.log('  ✓ Config returns competition metadata');

    // Test 2: Public challenges API does not leak flags
    console.log('[2] Testing /api/challenges flag security');
    const chRes = await request('/api/challenges');
    assert.strictEqual(chRes.status, 200);
    assert.ok(chRes.json.challenges.length >= 6);
    for (const c of chRes.json.challenges) {
      assert.strictEqual(c.flag, undefined, `CRITICAL LEAK: Flag exposed in challenge ${c.id}`);
      assert.ok(c.id && c.title && c.category && c.points);
    }
    console.log('  ✓ Challenges endpoint does NOT expose any flags');

    // Test 3: User Registration
    console.log('[3] Testing /api/auth/register');
    const testUsername = `cadet_${Date.now()}`;
    const testEmail = `${testUsername}@spec.ac.in`;
    const regRes = await request('/api/auth/register', {
      method: 'POST',
      body: { username: testUsername, email: testEmail, password: 'SecurePassword123!' }
    });
    assert.strictEqual(regRes.status, 201);
    assert.ok(regRes.json.token);
    assert.strictEqual(regRes.json.user.username, testUsername);
    const authToken = regRes.json.token;
    console.log('  ✓ Registration successful, token issued');

    // Test 4: Auth me check
    console.log('[4] Testing /api/auth/me');
    const meRes = await request('/api/auth/me', {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    assert.strictEqual(meRes.status, 200);
    assert.strictEqual(meRes.json.user.username, testUsername);
    assert.strictEqual(meRes.json.user.totalPoints, 0);
    assert.strictEqual(meRes.json.user.solvedCount, 0);
    console.log('  ✓ User profile and stats verified');

    // Test 5: Interactive challenge web-01 endpoint
    console.log('[5] Testing interactive challenge web-01 (/api/diagnostics/vault-status)');
    const unauthVault = await request('/api/diagnostics/vault-status');
    assert.strictEqual(unauthVault.status, 403);
    const authVault = await request('/api/diagnostics/vault-status', {
      headers: { 'X-Krypteia-Role': 'SecurityAdmin' }
    });
    assert.strictEqual(authVault.status, 200);
    assert.strictEqual(authVault.json.flag, 'KRYPTEIA{h34d3r_sp00f1ng_m4st3r_99}');
    console.log('  ✓ Interactive Vault API correctly responds to header authentication');

    // Test 6: Flag submission - Incorrect flag
    console.log('[6] Testing flag submission with incorrect flag');
    const badSub = await request('/api/submit-flag', {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
      body: { challengeId: 'gen-01', flag: 'KRYPTEIA{wrong_flag_here}' }
    });
    assert.strictEqual(badSub.status, 400);
    assert.strictEqual(badSub.json.success, false);
    console.log('  ✓ Incorrect flag rejected with error message');

    // Test 7: Flag submission - Correct flag
    console.log('[7] Testing flag submission with correct flag');
    const goodSub = await request('/api/submit-flag', {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
      body: { challengeId: 'gen-01', flag: 'KRYPTEIA{w3lc0m3_t0_krypt31a_2026}' }
    });
    assert.strictEqual(goodSub.status, 200);
    assert.strictEqual(goodSub.json.success, true);
    assert.strictEqual(goodSub.json.pointsAwarded, 50);
    assert.strictEqual(goodSub.json.newTotalPoints, 50);
    assert.strictEqual(goodSub.json.solvedCount, 1);
    console.log('  ✓ Correct flag awarded 50 points and incremented solves');

    // Test 8: Flag submission - Duplicate solve prevention
    console.log('[8] Testing duplicate flag submission prevention');
    const dupSub = await request('/api/submit-flag', {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
      body: { challengeId: 'gen-01', flag: 'KRYPTEIA{w3lc0m3_t0_krypt31a_2026}' }
    });
    assert.strictEqual(dupSub.status, 200);
    assert.strictEqual(dupSub.json.success, false);
    assert.strictEqual(dupSub.json.alreadySolved, true);
    console.log('  ✓ Duplicate flag solve safely rejected without duplicate points');

    // Test 9: Solve a second challenge (wait 5.1s to respect rate limiter)
    console.log('[9] Testing second challenge solve (web-01) - waiting for rate limit window...');
    await new Promise(r => setTimeout(r, 5200));
    const secondSub = await request('/api/submit-flag', {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
      body: { challengeId: 'web-01', flag: 'KRYPTEIA{h34d3r_sp00f1ng_m4st3r_99}' }
    });
    assert.strictEqual(secondSub.status, 200);
    assert.strictEqual(secondSub.json.success, true);
    assert.strictEqual(secondSub.json.pointsAwarded, 150);
    assert.strictEqual(secondSub.json.newTotalPoints, 200); // 50 + 150
    assert.strictEqual(secondSub.json.solvedCount, 2);
    console.log('  ✓ Second challenge awarded 150 points, total now 200');

    // Test 10: Leaderboard reflects updated score and ranking
    console.log('[10] Testing leaderboard sorting and current user rank');
    const lbRes = await request('/api/leaderboard', {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    assert.strictEqual(lbRes.status, 200);
    const lb = lbRes.json.leaderboard;
    assert.ok(lb.length >= 2);
    // Find our test user in leaderboard
    const myEntry = lb.find(e => e.username === testUsername);
    assert.ok(myEntry);
    assert.strictEqual(myEntry.totalPoints, 200);
    assert.strictEqual(myEntry.solvedCount, 2);
    assert.strictEqual(myEntry.isCurrentParticipant, true);
    console.log(`  ✓ Leaderboard accurately shows test user at Rank #${myEntry.rank} with 200 points`);

    // Test 11: Rules endpoint
    console.log('[11] Testing /api/rules');
    const rulesRes = await request('/api/rules');
    assert.strictEqual(rulesRes.status, 200);
    assert.ok(rulesRes.json.rules.length >= 5);
    console.log('  ✓ Rules returned correctly');

    console.log('\n>>> ALL BACKEND API TESTS PASSED SUCCESSFULLY! <<<');
  } finally {
    server.close();
  }
}

runTests().catch(err => {
  console.error('Test suite failed:', err);
  if (server) server.close();
  process.exit(1);
});
