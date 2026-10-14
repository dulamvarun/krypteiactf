// Server-side seed challenge definitions
// NOTE: Upon first launch, these challenges are automatically seeded into SQLite
// with cryptographic HMAC-SHA256 salted hashes + AES-256-GCM envelope encryption.
// Live validations and challenge state are handled dynamically by database.js.

const INITIAL_CHALLENGES = [
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
      'Raw machine telemetry is often transmitted as pairs of hexadecimal nibbles representing byte values.',
      'Consider how hexadecimal notation maps to ASCII character tables in computing fundamentals.'
    ],
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
      'Classical substitution ciphers maintain predictable frequency and offset patterns across the 26-letter Latin alphabet.',
      'Notice that non-alphabetical characters (like underscores, numbers, and braces) typically do not shift.'
    ],
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
      'Web services frequently evaluate authorization based on contextual metadata supplied in the HTTP request headers or query parameters.',
      'Explore how your browser developer tools or HTTP clients allow crafting requests with custom client headers.'
    ],
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
      'Image file formats contain non-visual data segments—such as header chunks, metadata tags, and appended raw strings.',
      'Examine the file structure for contiguous sequences of printable text that may be embedded within the binary stream.'
    ],
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
      'Network captures preserve packet headers and payloads across communication sessions.',
      'Reconstructing the conversation stream between the source and destination IP addresses often reveals unencrypted protocol exchanges.'
    ],
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
      'Postal Index Numbers (PIN codes) in the Maisammaguda / Medchal area can be verified through official postal directory lookups.',
      'Educational regulatory portals and official college history pages list the approved establishment milestone for engineering colleges in Hyderabad.'
    ],
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
      'XOR is a symmetric bitwise operation: applying the repeating key to the ciphertext reverses the transformation.',
      'Ensure the key cycles periodically across every byte of the hex-decoded byte stream.'
    ],
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
      'Stateful web authentication often checks client-managed storage tokens passed automatically in request headers.',
      'Inspect how cookies can be viewed, created, or modified within browser storage or via client-side scripts.'
    ],
    attachments: []
  },
  {
    id: 'forensics-02',
    title: 'Evidence in Pieces',
    category: 'Digital Forensics',
    difficulty: 'Easy',
    points: 150,
    description: `Our incident response team recovered an image from a compromised workstation. The file appears ordinary, but the analyst suspects that evidence has been left behind.

Your task is to inspect the provided evidence and recover the complete flag.

**Evidence 1 — Image Metadata**

The extracted metadata contains a suspicious comment:

\`KRYPTEIA{m3t4d4t4_\`

**Evidence 2 — Embedded Artifact**

A separate artifact extracted from the same image contains:

\`d03sn7_l13}\`

Determine the correct order of the fragments and submit the complete flag.`,
    hints: [
      'Forensic investigations often require piecing together disjointed artifacts found in image metadata and file payloads.',
      'Check the syntax of CTF flag conventions to reconstruct the fragments into a single coherent flag.'
    ],
    attachments: [
      {
        name: 'evidence_image.png',
        url: '/attachments/evidence_image.png',
        size: '17 KB',
        type: 'image/png'
      }
    ]
  }
];

// Map for fast initial seed lookup
const CHALLENGE_MAP = new Map();
INITIAL_CHALLENGES.forEach(c => CHALLENGE_MAP.set(c.id, c));

/**
 * Normalizes submitted flags to handle common formatting quirks:
 * - Space in prefix: "KRYPT EIA{...}" or "KRYPT_EIA{...}" -> "KRYPTEIA{...}"
 * - Spaces before brace: "KRYPTEIA {" -> "KRYPTEIA{"
 * - Spaces inside braces: "KRYPTEIA{ flag }" -> "KRYPTEIA{flag}"
 */
function normalizeFlag(flag) {
  if (!flag || typeof flag !== 'string') return '';
  let str = flag.trim();
  str = str.replace(/^KRYPT[\s_]+EIA/i, 'KRYPTEIA');
  str = str.replace(/^([A-Za-z0-9_-]+)\s*\{/, '$1{');
  str = str.replace(/^([A-Za-z0-9_-]+\{)\s*(.*?)\s*(\})$/, '$1$2$3');
  const braceIdx = str.indexOf('{');
  if (braceIdx > 0 && str.endsWith('}')) {
    const prefix = str.substring(0, braceIdx).toUpperCase();
    const inner = str.substring(braceIdx + 1, str.length - 1);
    str = `${prefix}{${inner}}`;
  }
  return str;
}

/**
 * Returns public challenge data stripped of all private flags.
 * Queries dynamic database store.
 */
function getPublicChallenges(userSolves = new Set(), solveCounts = {}, challengeLocks = {}) {
  const db = require('./database');
  return db.getAllPublicChallenges(userSolves, solveCounts, challengeLocks);
}

/**
 * Validates a submitted flag against the cryptographic salted HMAC in the database.
 */
function validateFlag(challengeId, submittedFlag) {
  const db = require('./database');
  return db.verifyFlag(challengeId, submittedFlag);
}

module.exports = {
  INITIAL_CHALLENGES,
  CHALLENGES: INITIAL_CHALLENGES,
  CHALLENGE_MAP,
  getPublicChallenges,
  validateFlag,
  normalizeFlag
};
