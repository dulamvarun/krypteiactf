// Server-side private challenge definitions
// NOTE: Expected flags are NEVER returned to the client or public API responses!

const CHALLENGES = [
  {
    id: 'gen-01',
    title: 'Terminal Sanity Check',
    category: 'General Skills',
    difficulty: 'Easy',
    points: 50,
    description: `Welcome to KRYPTEIA CTF! In cybersecurity competitions, flags follow strict format rules. Analyze the encoded hex payload transmitted during the opening ceremony:

\`\`\`
4b525950544549417b77336c63306d335f74305f6b727970743331615f323032367d
\`\`\`

Decode the hexadecimal byte stream to reveal the introductory flag.`,
    hints: [
      'Each pair of hexadecimal digits (e.g., 4b, 52...) corresponds to one ASCII character in byte notation.',
      'You can use bash \`xxd -r -p\`, Python \`bytes.fromhex(...)\`, or an online tool like CyberChef.'
    ],
    flag: 'KRYPTEIA{w3lc0m3_t0_krypt31a_2026}',
    attachments: []
  },
  {
    id: 'crypto-01',
    title: "Caesar's Ciphertext Relay",
    category: 'Cryptography',
    difficulty: 'Easy',
    points: 100,
    description: `Our radio monitoring station at St. Peter's Engineering College intercepted a secret communication scrambled with a classical Caesar shift cipher:

\`\`\`
NUBSWHLD{f43v4u_vk1iw_f1sk3u_xqo0fn3g}
\`\`\`

The transmission logs indicate an encryption key shift of **+3**. Reverse the shift (-3) to recover the original flag.`,
    hints: [
      'Shift each alphabet character backward by 3 positions (N -> K, U -> R...).',
      'Numbers, braces, and underscores remain untouched.',
      'The flag format is KRYPTEIA{...} without spaces (both KRYPTEIA and KRYPT EIA are accepted).'
    ],
    flag: 'KRYPTEIA{c43s4r_sh1ft_c1ph3r_unl0ck3d}',
    attachments: []
  },
  {
    id: 'web-01',
    title: 'The Vault API Inspector',
    category: 'Web Security',
    difficulty: 'Medium',
    points: 150,
    description: `The club internal telemetry system exposes a diagnostic route at:
\`/api/diagnostics/vault-status\`

If you query it directly, it returns \`403 Forbidden: Missing security role\`. Security audits reveal that the backend verifies the presence of an administrative header:
\`X-Krypteia-Role: SecurityAdmin\`
or query parameter:
\`?debug=admin_override\`

Use your browser DevTools Console, curl, or fetch to query this endpoint with the correct authorization header or parameter to retrieve the secret flag.`,
    hints: [
      'Open your browser Console (F12) and run:\nfetch("/api/diagnostics/vault-status", { headers: { "X-Krypteia-Role": "SecurityAdmin" } }).then(r => r.json()).then(console.log)',
      'Alternatively, visit \`/api/diagnostics/vault-status?debug=admin_override\` directly in your browser.'
    ],
    flag: 'KRYPTEIA{h34d3r_sp00f1ng_m4st3r_99}',
    attachments: []
  },
  {
    id: 'forensics-01',
    title: 'Silent Carrier',
    category: 'Digital Forensics',
    difficulty: 'Medium',
    points: 200,
    description: `During a campus cyber drill, an unauthorized flash drive was discovered in the computer science laboratory. On it was an image specimen: **stego_specimen.png**.

Our digital forensics analysts believe that sensitive intelligence was hidden inside the file metadata or image structure. Download the attachment and extract the flag.`,
    hints: [
      'Check the PNG textual metadata chunks using ExifTool, hex editor, or string inspection.',
      'On terminal: run \`strings stego_specimen.png | grep KRYPTEIA\` or inspect in CyberChef.'
    ],
    flag: 'KRYPTEIA{m3t4d4t4_n3v3r_l13s_7812}',
    attachments: [
      {
        name: 'stego_specimen.png',
        url: '/attachments/stego_specimen.png',
        size: '16.5 KB',
        type: 'image/png'
      }
    ]
  },
  {
    id: 'netsec-01',
    title: 'Suspicious Packet Capture',
    category: 'Network Security',
    difficulty: 'Medium',
    points: 200,
    description: `A network tap on the St. Peter's campus perimeter firewall captured anomalous communication between host \`192.168.1.100\` and destination \`10.10.15.5\`.

Download the packet capture file **traffic_analysis.pcap**, analyze the intercepted TCP/HTTP payload, and reconstruct the exfiltrated flag.`,
    hints: [
      'Open traffic_analysis.pcap in Wireshark or CyberChef.',
      'Right-click any TCP packet and choose "Follow > TCP Stream" to inspect the plaintext HTTP payload.'
    ],
    flag: 'KRYPTEIA{p4ck3t_sn1ff3r_pr0t0c0l_337}',
    attachments: [
      {
        name: 'traffic_analysis.pcap',
        url: '/attachments/traffic_analysis.pcap',
        size: '354 B',
        type: 'application/vnd.tcpdump.pcap'
      }
    ]
  },
  {
    id: 'osint-01',
    title: 'The Campus Transceiver',
    category: 'OSINT',
    difficulty: 'Easy',
    points: 150,
    description: `An anonymous signal transmitter was spotted on the perimeter of **St. Peter's Engineering College, Maisammaguda, Hyderabad**.

The emergency transceiver registration code follows this canonical convention:
\`\`\`
KRYPTEIA{SPEC_HYD_{PINCODE}_{EST_YEAR}}
\`\`\`

Investigate public records for St. Peter's Engineering College to identify:
1. The 6-digit postal PIN Code for Maisammaguda campus.
2. The official founding/establishment year of the college.

Combine them in the exact format specified above.`,
    hints: [
      "St. Peter's Engineering College is situated at Maisammaguda, Medchal-Malkajgiri District, Hyderabad. The postal PIN code is 500100.",
      'Check official college publications or AICTE registration records for the establishment year (2007).'
    ],
    flag: 'KRYPTEIA{SPEC_HYD_500100_2007}',
    attachments: []
  },
  {
    id: 'crypto-02',
    title: 'XOR Protocol Stream',
    category: 'Cryptography',
    difficulty: 'Hard',
    points: 250,
    description: `We intercepted an encrypted telemetry stream protected by repetitive multi-byte XOR masking. According to the recovered incident documentation, the key is the ASCII string:
\`\`\`
KRYPT
\`\`\`

The raw hexadecimal representation of the intercepted payload is:
\`\`\`
00000000000e1b182b2c7b200633653b3a6a220b38262b6360260d3d63377b366a340b7266682d
\`\`\`

Decrypt the ciphertext byte stream using the repeating key \`KRYPT\` to obtain the flag.`,
    hints: [
      'In CyberChef: add "From Hex" operation, then add "XOR" operation with Key set to UTF-8 string "KRYPT".',
      'Or in Python: \nkey = b"KRYPT"\nct = bytes.fromhex("0000...")\nflag = bytes([b ^ key[i % len(key)] for i, b in enumerate(ct)])\nprint(flag.decode())'
    ],
    flag: 'KRYPTEIA{x0r_c1ph3r_str34m_d3c0d3d_941}',
    attachments: [
      {
        name: 'xor_stream.hex',
        url: '/attachments/xor_stream.hex',
        size: '79 B',
        type: 'text/plain'
      }
    ]
  },
  {
    id: 'web-02',
    title: "Cookie Monster's Session Token",
    category: 'Web Security',
    difficulty: 'Medium',
    points: 175,
    description: `A restricted diagnostic vault is accessible at:
\`/api/diagnostics/cookie-vault\`

The endpoint uses cookie-based state validation. If your request carries the cookie:
\`krypteia_role=cyber_commander\`
the access barrier unlocks and outputs the flag.

Use browser document.cookie manipulation or curl to present the required cookie.`,
    hints: [
      "Set the cookie in DevTools > Storage/Application > Cookies, or in console: document.cookie = 'krypteia_role=cyber_commander; path=/';",
      'Then visit /api/diagnostics/cookie-vault in your browser or run fetch("/api/diagnostics/cookie-vault").then(r => r.json()).then(console.log)'
    ],
    flag: 'KRYPTEIA{c00k13_m4n1pul4t10n_succ3ss}',
    attachments: []
  }
];

// Map for fast O(1) lookup
const CHALLENGE_MAP = new Map();
CHALLENGES.forEach(c => CHALLENGE_MAP.set(c.id, c));

/**
 * Returns public challenge data stripped of all private flags.
 * Also attaches whether the user solved it.
 */
function getPublicChallenges(userSolves = new Set(), solveCounts = {}) {
  return CHALLENGES.map(c => ({
    id: c.id,
    title: c.title,
    category: c.category,
    difficulty: c.difficulty,
    points: c.points,
    description: c.description,
    hints: c.hints,
    attachments: c.attachments,
    solveCount: solveCounts[c.id] || 0,
    isSolved: userSolves.has(c.id)
  }));
}

/**
 * Normalizes submitted flags to handle common formatting quirks:
 * - Space in prefix: "KRYPT EIA{...}" or "KRYPT_EIA{...}" -> "KRYPTEIA{...}"
 * - Spaces before brace: "KRYPTEIA {" -> "KRYPTEIA{"
 * - Spaces inside braces: "KRYPTEIA{ flag }" -> "KRYPTEIA{flag}"
 */
function normalizeFlag(flag) {
  if (!flag || typeof flag !== 'string') return '';
  let str = flag.trim();
  // Fix accidental split between KRYPT and EIA
  str = str.replace(/^KRYPT[\s_]+EIA/i, 'KRYPTEIA');
  // Fix spaces before opening brace
  str = str.replace(/^([A-Za-z0-9_-]+)\s*\{/, '$1{');
  // Trim spaces immediately inside braces
  str = str.replace(/^([A-Za-z0-9_-]+\{)\s*(.*?)\s*(\})$/, '$1$2$3');
  return str;
}

/**
 * Validates a submitted flag against the private server-side answer.
 * Tolerates minor whitespace errors (e.g. "KRYPT EIA{...}").
 */
function validateFlag(challengeId, submittedFlag) {
  const challenge = CHALLENGE_MAP.get(challengeId);
  if (!challenge) return { found: false };

  const rawSubmitted = (submittedFlag || '').trim();
  const rawExpected = challenge.flag.trim();

  // 1. Direct exact match
  if (rawSubmitted === rawExpected) {
    return {
      found: true,
      isCorrect: true,
      points: challenge.points,
      title: challenge.title
    };
  }

  // 2. Normalized match (handles "KRYPT EIA{...}", extra spaces, etc.)
  const normSubmitted = normalizeFlag(rawSubmitted);
  const normExpected = normalizeFlag(rawExpected);

  if (normSubmitted === normExpected) {
    return {
      found: true,
      isCorrect: true,
      points: challenge.points,
      title: challenge.title
    };
  }

  // 3. Case-insensitive prefix match with exact inner payload
  const matchSub = normSubmitted.match(/^([A-Za-z0-9_-]+)\{(.*)\}$/);
  const matchExp = normExpected.match(/^([A-Za-z0-9_-]+)\{(.*)\}$/);
  if (matchSub && matchExp) {
    if (matchSub[1].toUpperCase() === matchExp[1].toUpperCase() && matchSub[2] === matchExp[2]) {
      return {
        found: true,
        isCorrect: true,
        points: challenge.points,
        title: challenge.title
      };
    }
  }

  return {
    found: true,
    isCorrect: false,
    points: challenge.points,
    title: challenge.title
  };
}

module.exports = {
  CHALLENGES,
  CHALLENGE_MAP,
  getPublicChallenges,
  validateFlag
};
