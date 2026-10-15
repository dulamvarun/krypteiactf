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
    // Reset test state to clean baseline
    db.clearAllParticipants();
    db.setAllChallengeLocks(db.getAllChallengeIds(), false);

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
    assert.ok(authVault.json.flag && authVault.json.flag.startsWith('KRYPTEIA{'));
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

    // Retrieve flags dynamically from secure database for test assertions
    const flagGen01 = db.decryptFlag(db.getChallengeById('gen-01').flag_encrypted);
    const flagCrypto01 = db.decryptFlag(db.getChallengeById('crypto-01').flag_encrypted);
    const flagWeb01 = db.decryptFlag(db.getChallengeById('web-01').flag_encrypted);

    // Test 7: Flag submission - Correct flag
    console.log('[7] Testing flag submission with correct flag');
    const goodSub = await request('/api/submit-flag', {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
      body: { challengeId: 'gen-01', flag: flagGen01 }
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
      body: { challengeId: 'gen-01', flag: flagGen01 }
    });
    assert.strictEqual(dupSub.status, 200);
    assert.strictEqual(dupSub.json.success, false);
    assert.strictEqual(dupSub.json.alreadySolved, true);
    console.log('  ✓ Duplicate flag solve safely rejected without duplicate points');

    // Test 9: Flag submission with extra space (e.g. KRYPT EIA{...} from Caesar cipher decoders)
    console.log('[9] Testing flag submission with extra space: KRYPT EIA{...}');
    await new Promise(r => setTimeout(r, 5200));
    const spaceFlag = flagCrypto01.replace('KRYPTEIA', 'KRYPT EIA');
    const spaceSub = await request('/api/submit-flag', {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
      body: { challengeId: 'crypto-01', flag: spaceFlag }
    });
    assert.strictEqual(spaceSub.status, 200);
    assert.strictEqual(spaceSub.json.success, true);
    assert.strictEqual(spaceSub.json.pointsAwarded, 100);
    assert.strictEqual(spaceSub.json.newTotalPoints, 150); // 50 + 100
    assert.strictEqual(spaceSub.json.solvedCount, 2);
    console.log('  ✓ Flag with extra space (KRYPT EIA{...}) accepted and awarded 100 points');

    // Test 10: Solve a third challenge (web-01)
    console.log('[10] Testing third challenge solve (web-01) - waiting for rate limit window...');
    await new Promise(r => setTimeout(r, 5200));
    const thirdSub = await request('/api/submit-flag', {
      method: 'POST',
      headers: { Authorization: `Bearer ${authToken}` },
      body: { challengeId: 'web-01', flag: flagWeb01 }
    });
    assert.strictEqual(thirdSub.status, 200);
    assert.strictEqual(thirdSub.json.success, true);
    assert.strictEqual(thirdSub.json.pointsAwarded, 150);
    assert.strictEqual(thirdSub.json.newTotalPoints, 300); // 50 + 100 + 150
    assert.strictEqual(thirdSub.json.solvedCount, 3);
    console.log('  ✓ Third challenge awarded 150 points, total now 300');

    // Test 10: Leaderboard reflects updated score and ranking
    console.log('[10] Testing leaderboard sorting and current user rank');
    const lbRes = await request('/api/leaderboard', {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    assert.strictEqual(lbRes.status, 200);
    const lb = lbRes.json.leaderboard;
    assert.ok(lb.length >= 1);
    // Find our test user in leaderboard
    const myEntry = lb.find(e => e.username === testUsername);
    assert.ok(myEntry);
    assert.strictEqual(myEntry.totalPoints, 300);
    assert.strictEqual(myEntry.solvedCount, 3);
    assert.strictEqual(myEntry.isCurrentParticipant, true);
    console.log(`  ✓ Leaderboard accurately shows test user at Rank #${myEntry.rank} with 300 points`);

    // Test 11: Rules endpoint
    console.log('[11] Testing /api/rules');
    const rulesRes = await request('/api/rules');
    assert.strictEqual(rulesRes.status, 200);
    assert.ok(rulesRes.json.rules.length >= 5);
    console.log('  ✓ Rules returned correctly');

    // Test 12: Admin authentication and Challenge Management API
    console.log('[12] Testing Admin Login & Challenge Creation with Salted HMAC flag');
    const adminLoginRes = await request('/api/admin/login', {
      method: 'POST',
      body: { id: 'pappu', password: 'Bt@1801' }
    });
    assert.strictEqual(adminLoginRes.status, 200);
    assert.ok(adminLoginRes.json.token);
    const adminToken = adminLoginRes.json.token;
    const dynamicTestFlag = `KRYPTEIA{test_probe_${Date.now()}}`;

    // Create a new challenge dynamically
    const newChRes = await request('/api/admin/challenges', {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: {
        id: 'rev-01',
        title: 'Binary Disassembly Probe',
        category: 'Reverse Engineering',
        difficulty: 'Hard',
        points: 300,
        description: 'Disassemble the ELF binary to recover the secret access code.',
        hints: ['Look at strcmp in main function'],
        attachments: [],
        flag: dynamicTestFlag,
        isLocked: false
      }
    });
    assert.strictEqual(newChRes.status, 200);
    assert.strictEqual(newChRes.json.success, true);
    console.log('  ✓ Admin successfully created dynamic challenge with salted HMAC flag');

    // Test 13: Verify DB storage does NOT contain plaintext flag
    console.log('[13] Testing DB internal storage security (zero plaintext flags)');
    const chInDb = db.getChallengeById('rev-01');
    assert.ok(chInDb);
    assert.ok(chInDb.flag_hash);
    assert.ok(chInDb.flag_salt);
    assert.strictEqual(chInDb.flag, undefined);
    assert.notStrictEqual(chInDb.flag_hash, dynamicTestFlag);
    // Verify decrypted flag available to admin
    assert.strictEqual(db.decryptFlag(chInDb.flag_encrypted), dynamicTestFlag);
    console.log('  ✓ DB stores only salted HMAC and AES-256-GCM envelope; plaintext flag is nowhere in the DB table');

    // Test 14: Test flag sandbox API
    console.log('[14] Testing /api/admin/test-flag sandbox');
    const testFlagGood = await request('/api/admin/test-flag', {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: { challengeId: 'rev-01', flag: dynamicTestFlag }
    });
    assert.strictEqual(testFlagGood.json.isCorrect, true);

    const testFlagBad = await request('/api/admin/test-flag', {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: { challengeId: 'rev-01', flag: 'KRYPTEIA{wrong_guess}' }
    });
    assert.strictEqual(testFlagBad.json.isCorrect, false);
    console.log('  ✓ Admin flag test sandbox correctly verifies valid and invalid flags');

    // Test 15: Clean up created challenge
    console.log('[15] Testing admin challenge deletion');
    const delRes = await request('/api/admin/challenges/rev-01', {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(delRes.status, 200);
    assert.strictEqual(delRes.json.success, true);
    assert.strictEqual(db.getChallengeById('rev-01'), null);
    console.log('  ✓ Admin challenge deletion works cleanly');

    // Test 16: Real-time Server-Sent Events (SSE) Live Sync
    console.log('[16] Testing /api/events/live-sync real-time push streaming');
    const receivedEvents = [];
    let sseClientReq;

    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        if (sseClientReq) sseClientReq.destroy();
        reject(new Error('SSE connection timed out waiting for event'));
      }, 5000);

      sseClientReq = http.get(`${baseUrl}/api/events/live-sync`, (res) => {
        assert.strictEqual(res.statusCode, 200);
        assert.ok(res.headers['content-type'].includes('text/event-stream'));

        res.on('data', async (chunk) => {
          const str = chunk.toString();
          if (str.includes('event: connected')) {
            receivedEvents.push('connected');
            // Trigger an admin lock action to test broadcast delivery
            await request('/api/admin/challenge-lock', {
              method: 'POST',
              headers: { Authorization: `Bearer ${adminToken}` },
              body: { challengeId: 'crypto-01', isLocked: true }
            });
          }
          if (str.includes('event: challenge_lock_updated')) {
            receivedEvents.push('challenge_lock_updated');
            clearTimeout(timeout);
            // Revert lock back to unlocked
            await request('/api/admin/challenge-lock', {
              method: 'POST',
              headers: { Authorization: `Bearer ${adminToken}` },
              body: { challengeId: 'crypto-01', isLocked: false }
            });
            sseClientReq.destroy();
            resolve();
          }
        });
      });

      sseClientReq.on('error', (err) => {
        if (err.code !== 'ECONNRESET') reject(err);
      });
    });

    assert.ok(receivedEvents.includes('connected'), 'SSE did not send connected event');
    assert.ok(receivedEvents.includes('challenge_lock_updated'), 'SSE did not broadcast challenge_lock_updated event');
    console.log('  ✓ Server-Sent Events live stream broadcasts admin modifications in real-time');

    // Test 17: Admin Lock / Unlock synchronization & solve blocking
    console.log('[17] Testing Admin challenge lock synchronization & solve blocking');
    // Lock crypto-01
    const lockRes = await request('/api/admin/challenge-lock', {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: { challengeId: 'crypto-01', isLocked: true }
    });
    assert.strictEqual(lockRes.status, 200);
    assert.strictEqual(lockRes.json.isLocked, true);

    // Verify /api/challenges returns it locked with stripped description
    const challengesAfterLock = await request('/api/challenges');
    const lockedCh = challengesAfterLock.json.challenges.find(c => c.id === 'crypto-01');
    assert.ok(lockedCh, 'crypto-01 not found');
    assert.strictEqual(lockedCh.isLocked, true, 'crypto-01 should be locked in public API');
    assert.strictEqual(lockedCh.description, '', 'Locked challenge description must be stripped');

    // Attempt to submit flag to locked challenge -> 403 Forbidden
    const blockedSubmit = await request('/api/submit-flag', {
      method: 'POST',
      headers: { Cookie: `krypteia_session=${authToken}` },
      body: { challengeId: 'crypto-01', flag: 'KRYPTEIA{c4354r_sh1ft_c1ph3r_unl0ck3d}' }
    });
    assert.strictEqual(blockedSubmit.status, 403, 'Submitting to locked challenge must return 403');
    assert.ok(blockedSubmit.json.error.includes('when unlocked'), 'Expected unlock message');

    // Unlock crypto-01
    const unlockRes = await request('/api/admin/challenge-lock', {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: { challengeId: 'crypto-01', isLocked: false }
    });
    assert.strictEqual(unlockRes.status, 200);
    assert.strictEqual(unlockRes.json.isLocked, false);

    // Verify /api/challenges returns it unlocked with full description restored
    const challengesAfterUnlock = await request('/api/challenges');
    const unlockedCh = challengesAfterUnlock.json.challenges.find(c => c.id === 'crypto-01');
    assert.strictEqual(unlockedCh.isLocked, false, 'crypto-01 should be unlocked in public API');
    assert.ok(unlockedCh.description.length > 10, 'Unlocked challenge description must be present');
    console.log('  ✓ Admin question lock options sync and enforce solve blocks flawlessly');

    // Test 18: Leaderboard tie-break based on first submission when marks are equal
    console.log('[18] Testing Leaderboard tie-break based on first submission for identical marks');
    // Clear participants to have a clean leaderboard test
    db.clearAllParticipants();

    // Register User One
    const u1Res = await request('/api/auth/register', {
      method: 'POST',
      body: { username: 'FirstSubmitter', email: 'first@spec.ac.in', password: 'Password123!' }
    });
    const u1Token = u1Res.json.token;

    // Register User Two
    const u2Res = await request('/api/auth/register', {
      method: 'POST',
      body: { username: 'SecondSubmitter', email: 'second@spec.ac.in', password: 'Password123!' }
    });
    const u2Token = u2Res.json.token;

    // User One solves gen-01 first
    const u1Solve = await request('/api/submit-flag', {
      method: 'POST',
      headers: { Cookie: `krypteia_session=${u1Token}` },
      body: { challengeId: 'gen-01', flag: 'KRYPTEIA{w3lc0m3_t0_krypt31a_2026}' }
    });
    assert.strictEqual(u1Solve.status, 200);
    assert.strictEqual(u1Solve.json.success, true);

    // Wait 1.1s for rate limit window, then User Two solves gen-01
    await new Promise(r => setTimeout(r, 1100));
    const u2Solve = await request('/api/submit-flag', {
      method: 'POST',
      headers: { Cookie: `krypteia_session=${u2Token}` },
      body: { challengeId: 'gen-01', flag: 'KRYPTEIA{w3lc0m3_t0_krypt31a_2026}' }
    });
    assert.strictEqual(u2Solve.status, 200);
    assert.strictEqual(u2Solve.json.success, true);

    // Query leaderboard: both have 50 points, but User One submitted earlier!
    const lbTieRes = await request('/api/leaderboard');
    assert.strictEqual(lbTieRes.status, 200);
    const standings = lbTieRes.json.leaderboard;
    assert.strictEqual(standings.length, 2);
    assert.strictEqual(standings[0].username, 'FirstSubmitter', 'First submitter must be Rank #1 on equal marks');
    assert.strictEqual(standings[0].rank, 1);
    assert.strictEqual(standings[1].username, 'SecondSubmitter', 'Second submitter must be Rank #2 on equal marks');
    assert.strictEqual(standings[1].rank, 2);
    console.log('  ✓ Leaderboard ranking accurately gives top position to first submission when marks are equal');

    // Test 19: New user immediately added to leaderboard & Admin user deletion
    console.log('[19] Testing immediate addition to leaderboard upon registration and admin user deletion');
    const u3Res = await request('/api/auth/register', {
      method: 'POST',
      body: { username: 'NewCadet99', email: 'cadet99@spec.ac.in', password: 'Password123!' }
    });
    assert.strictEqual(u3Res.status, 201);
    const u3Id = u3Res.json.user.id;

    // Check leaderboard: NewCadet99 must be present on leaderboard immediately
    const lbWithNew = await request('/api/leaderboard');
    assert.ok(lbWithNew.json.leaderboard.some(u => u.username === 'NewCadet99'), 'Newly registered user must appear on leaderboard');

    // Admin deletes user
    const delUserRes = await request(`/api/admin/users/${u3Id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(delUserRes.status, 200);
    assert.strictEqual(delUserRes.json.success, true);

    // Verify user is removed from leaderboard
    const lbAfterDel = await request('/api/leaderboard');
    assert.ok(!lbAfterDel.json.leaderboard.some(u => u.username === 'NewCadet99'), 'Deleted user must be removed from leaderboard');
    console.log('  ✓ User instantly appears on leaderboard upon registration and admin can delete user cleanly');

    console.log('\n>>> ALL BACKEND API TESTS PASSED SUCCESSFULLY! <<<');
  } finally {
    db.clearAllParticipants();
    server.close();
  }
}

runTests().catch(err => {
  console.error('Test suite failed:', err);
  if (server) server.close();
  process.exit(1);
});
