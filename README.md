# 🛡️ Krypteia CTF — College Cybersecurity Competition Portal

Official jeopardy-style cybersecurity competition platform built for **Krypteia — The Cyber Security Technical Club at St. Peter's Engineering College**.

![CTF Portal](https://img.shields.io/badge/Platform-Krypteia%20CTF-00ff66?style=flat-square)
![Institution](https://img.shields.io/badge/Institution-St.%20Peter's%20Engineering%20College-1a202c?style=flat-square)
![Node.js](https://img.shields.io/badge/Node.js-24%2B-green?style=flat-square)
![SQLite](https://img.shields.io/badge/Database-SQLite%20(WAL%20Mode)-blue?style=flat-square)

---

## ⚡ Overview

Krypteia CTF provides an approachable, student-friendly competition experience featuring a clean matte terminal aesthetic, live countdown timer, persistent participant accounts, and authoritative server-side scoring.

### 🌟 Key Features
- **Matte Dark Terminal Aesthetic**: Non-glaring dark mode (`#0e1210`) with muted sage/terminal green (`#48bb78`) accents. Zero unwanted glow or animations.
- **Clear Solved vs. Unsolved Differentiation**: Visual status banners, checkmark badges, green accent borders on solved challenges, and dedicated status filter pills (`All`, `○ Unsolved`, `✓ Solved`).
- **Zero Client Flag Leaks**: All private answer keys are verified strictly server-side. Public APIs never expose flags or hashes to browser DevTools.
- **Authoritative Scoring**: Backed by SQLite transactions (`UNIQUE(user_id, challenge_id)`). Re-submitting solved challenges awards zero duplicate points.
- **Standard CTF Tie-Breaking**: Ranked by highest score descending; ties broken by earliest solve timestamp.
- **Built-in Rate Limiting**: Protects flag submission endpoints against brute-force attacks.

---

## 🧩 Preconfigured Solvable Challenges

| Challenge | Domain | Difficulty | Points | Methodology |
| :--- | :--- | :--- | :--- | :--- |
| **Terminal Sanity Check** | General Skills | Easy | 50 | Hexadecimal byte stream ASCII decoding |
| **Caesar's Ciphertext Relay** | Cryptography | Easy | 100 | Classical Caesar shift (-3) cryptanalysis |
| **The Vault API Inspector** | Web Security | Medium | 150 | Diagnostic API header / parameter inspection |
| **Silent Carrier** | Digital Forensics | Medium | 200 | PNG metadata chunk extraction (`stego_specimen.png`) |
| **Suspicious Packet Capture** | Network Security | Medium | 200 | TCP/HTTP packet stream reconstruction (`traffic_analysis.pcap`) |
| **The Campus Transceiver** | OSINT | Easy | 150 | Campus PIN Code & founding year OSINT investigation |
| **XOR Protocol Stream** | Cryptography | Hard | 250 | Multi-byte repeating key (`KRYPT`) XOR stream decoding |
| **Cookie Monster's Session** | Web Security | Medium | 175 | Cookie-based session role manipulation |

---

## 🚀 Quick Start & Installation

### Prerequisites
- [Node.js](https://nodejs.org/) (v18 or higher)
- [npm](https://www.npmjs.com/)

### 1. Clone the repository
```bash
git clone https://github.com/dulamvarun/krypteiactf.git
cd krypteiactf
```

### 2. Install dependencies
```bash
npm install
```

### 3. Generate challenge attachments
```bash
node scripts/generate-assets.js
```

### 4. Run automated test suite
```bash
npm test
# or: node tests/api-test.js
```

### 5. Launch the competition portal
```bash
node server.js
```
Open **`http://localhost:3000`** in your browser.

---

## 📁 Repository Structure

```
├── server.js              # Express 5 server, security headers, rate limiting, and SPA routing
├── database.js            # SQLite database schema, PBKDF2 hashing, and scoring queries
├── challenges.js          # Private server-side challenge catalog and flag validator
├── scripts/
│   └── generate-assets.js # Generates downloadable challenge attachments (PCAP, PNG, XOR hex)
├── tests/
│   └── api-test.js        # Automated API test suite covering auth, scoring, and concurrency
├── public/                # Static Single Page Application frontend
│   ├── index.html         # Semantic HTML markup
│   ├── css/
│   │   └── style.css      # Matte dark terminal CSS styles
│   ├── js/
│   │   ├── api.js         # API client
│   │   └── app.js         # Client routing, modal navigation, timer, and filtering
│   └── attachments/       # Downloadable challenge files
└── .gitignore
```

---

## 📜 License & Acknowledgments
Built for **Krypteia — The Cyber Security Technical Club at St. Peter's Engineering College, Maisammaguda, Hyderabad**.
All rights reserved. For educational and cybersecurity training purposes.
