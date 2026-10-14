const db = require('../database');

console.log('Clearing all participants, sessions, solves, and submissions...');
const result = db.clearAllParticipants();
console.log('✓ Success:', result.message);

const leaderboard = db.getLeaderboard();
console.log(`Current participant count on leaderboard: ${leaderboard.length}`);
console.log('KRYPTEIA CTF is now fresh and ready for participants.');
