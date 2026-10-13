# 🛡️ Krypteia CTF — College Cybersecurity Competition Portal

Official CTF competition platform built for **Krypteia — The Cyber Security Technical Club at St. Peter's Engineering College**.

A complete, self-contained, lightweight Jeopardy-style cybersecurity competition website with persistent SQLite storage, real-time leaderboard scoring, and authentic solvable challenges across 6 cybersecurity disciplines.

---

## ⚡ Tech Stack & Architecture

- **Backend**: Node.js & Express 5 (HTTP-only sessions, rate limiting, security headers, atomic transactions)
- **Database**: SQLite with WAL mode (`better-sqlite3`)
- **Frontend**: Vanilla HTML5, Vanilla CSS, Vanilla JavaScript (zero bundle build step, lightweight, fast)
- **Design Aesthetic**: Muted matte terminal dark palette with zero-glare green accents, high contrast, responsive cards, and modal-based challenge workflow.

---

## 🚀 Getting Started

### Prerequisites
- Node.js (v18+)
- npm

### Installation & Launch

1. **Clone repository**:
   ```bash
   git clone https://github.com/dulamvarun/krypteiactf.git
   cd krypteiactf
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Generate challenge attachment assets** (PCAP capture, Stego PNG, XOR payload):
   ```bash
   node scripts/generate-assets.js
   ```

4. **Start the CTF Portal**:
   ```bash
   node server.js
   ```

5. **Access the portal in your browser**:
   ```
   http://localhost:3000
   ```

---

## 🧩 Challenge Catalog

| ID | Title | Category | Difficulty | Points | Topic |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `gen-01` | **Terminal Sanity Check** | General Skills | Easy | 50 | Hexadecimal byte decoding |
| `crypto-01` | **Caesar's Ciphertext Relay** | Cryptography | Easy | 100 | Classical Caesar shift cipher |
| `web-01` | **The Vault API Inspector** | Web Security | Medium | 150 | Diagnostic API header / parameter inspection |
| `forensics-01` | **Silent Carrier** | Digital Forensics | Medium | 200 | PNG metadata / chunk steganography |
| `netsec-01` | **Suspicious Packet Capture** | Network Security | Medium | 200 | PCAP network traffic TCP/HTTP analysis |
| `osint-01` | **The Campus Transceiver** | OSINT | Easy | 150 | Campus geolocation, PIN, and establishment year |
| `crypto-02` | **XOR Protocol Stream** | Cryptography | Hard | 250 | Multi-byte XOR cryptanalysis |
| `web-02` | **Cookie Monster's Session** | Web Security | Medium | 175 | Cookie manipulation & state validation |

*All challenge flags follow the format: `KRYPTEIA{...}` and are kept strictly server-side.*

---

## 🧪 Testing

Run the automated backend test suite:
```bash
node tests/api-test.js
```

---

## 📜 License
Developed for educational cybersecurity competitions at St. Peter's Engineering College by Krypteia Cyber Security Club.
