const fs = require('fs');
const path = require('path');
const db = require('../database');

function getChallengeFlag(id) {
  try {
    const ch = db.getChallengeById(id);
    if (ch && ch.flag_encrypted) {
      return db.decryptFlag(ch.flag_encrypted) || '';
    }
  } catch (_) {}
  return '';
}

const attachmentsDir = path.join(__dirname, '..', 'public', 'attachments');
if (!fs.existsSync(attachmentsDir)) {
  fs.mkdirSync(attachmentsDir, { recursive: true });
}

// 1. Generate traffic_analysis.pcap
function generatePcap() {
  const pcapPath = path.join(attachmentsDir, 'traffic_analysis.pcap');
  
  // PCAP Global Header: 24 bytes
  const globalHeader = Buffer.alloc(24);
  globalHeader.writeUInt32LE(0xa1b2c3d4, 0); // Magic number
  globalHeader.writeUInt16LE(2, 4);          // Major version
  globalHeader.writeUInt16LE(4, 6);          // Minor version
  globalHeader.writeInt32LE(0, 8);           // Thiszone (GMT)
  globalHeader.writeUInt32LE(0, 12);         // Sigfigs
  globalHeader.writeUInt32LE(65535, 16);     // Snaplen
  globalHeader.writeUInt32LE(1, 20);         // LinkType: 1 = Ethernet

  // Ethernet header (14 bytes)
  // Dst MAC: 00:11:22:33:44:55, Src MAC: aa:bb:cc:dd:ee:ff, EtherType: 0x0800 (IPv4)
  const ethHeader = Buffer.from([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x08, 0x00
  ]);

  // Payload: HTTP response containing flag dynamically from DB
  const netsecFlag = getChallengeFlag('netsec-01');
  const httpPayload = Buffer.from(
    'HTTP/1.1 200 OK\r\n' +
    'Server: Krypteia-SecVault/1.4\r\n' +
    'Date: Tue, 13 Oct 2026 15:30:00 GMT\r\n' +
    'Content-Type: application/json\r\n' +
    'Connection: close\r\n\r\n' +
    JSON.stringify({ service: 'Krypteia NetSec Diagnostic', intercepted_key: netsecFlag, status: 'exfiltrated' }) + '\n'
  );

  // IPv4 header (20 bytes)
  const ipHeader = Buffer.alloc(20);
  ipHeader.writeUInt8(0x45, 0); // Version 4, IHL 5
  ipHeader.writeUInt8(0x00, 1); // DSCP/ECN
  const totalLength = 20 + 20 + httpPayload.length;
  ipHeader.writeUInt16BE(totalLength, 2);
  ipHeader.writeUInt16BE(0x1337, 4); // ID
  ipHeader.writeUInt16BE(0x4000, 6); // Flags: Don't Fragment
  ipHeader.writeUInt8(64, 8);         // TTL
  ipHeader.writeUInt8(6, 9);          // Protocol: 6 (TCP)
  ipHeader.writeUInt16BE(0x0000, 10); // Checksum (0 for mock)
  // Src IP: 192.168.1.100
  ipHeader.writeUInt8(192, 12);
  ipHeader.writeUInt8(168, 13);
  ipHeader.writeUInt8(1, 14);
  ipHeader.writeUInt8(100, 15);
  // Dst IP: 10.10.15.5
  ipHeader.writeUInt8(10, 16);
  ipHeader.writeUInt8(10, 17);
  ipHeader.writeUInt8(15, 18);
  ipHeader.writeUInt8(5, 19);

  // TCP header (20 bytes)
  const tcpHeader = Buffer.alloc(20);
  tcpHeader.writeUInt16BE(8080, 0);     // Src Port
  tcpHeader.writeUInt16BE(49152, 2);    // Dst Port
  tcpHeader.writeUInt32BE(1000001, 4);  // Seq
  tcpHeader.writeUInt32BE(500001, 8);   // Ack
  tcpHeader.writeUInt8(0x50, 12);       // Data offset: 5 (20 bytes)
  tcpHeader.writeUInt8(0x18, 13);       // Flags: PSH, ACK
  tcpHeader.writeUInt16BE(64240, 14);   // Window size
  tcpHeader.writeUInt16BE(0x0000, 16);  // Checksum
  tcpHeader.writeUInt16BE(0x0000, 18);  // Urgent pointer

  const packetData = Buffer.concat([ethHeader, ipHeader, tcpHeader, httpPayload]);

  // Packet Header (16 bytes)
  const packetHeader = Buffer.alloc(16);
  const nowSec = Math.floor(Date.now() / 1000);
  packetHeader.writeUInt32LE(nowSec, 0);
  packetHeader.writeUInt32LE(123456, 4);
  packetHeader.writeUInt32LE(packetData.length, 8);  // Captured length
  packetHeader.writeUInt32LE(packetData.length, 12); // Wire length

  const fullPcap = Buffer.concat([globalHeader, packetHeader, packetData]);
  fs.writeFileSync(pcapPath, fullPcap);
  console.log('Created traffic_analysis.pcap, bytes:', fullPcap.length);
}

// 2. Generate stego_specimen.png with embedded metadata / comment
function generateStegoPng() {
  const pngPath = path.join(attachmentsDir, 'stego_specimen.png');

  // We can write a valid PNG from scratch:
  // Signature (8 bytes)
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // CRC32 helper
  function crc32(buf) {
    let table = [];
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[i] = c;
    }
    let crc = 0 ^ (-1);
    for (let i = 0; i < buf.length; i++) {
      crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xff];
    }
    return (crc ^ (-1)) >>> 0;
  }

  function makeChunk(type, data) {
    const len = data.length;
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(len, 0);

    const typeBuf = Buffer.from(type, 'ascii');
    const typeAndData = Buffer.concat([typeBuf, data]);
    const crcVal = crc32(typeAndData);
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crcVal, 0);

    return Buffer.concat([lenBuf, typeAndData, crcBuf]);
  }

  // IHDR: 13 bytes
  // Width: 120, Height: 120, 8-bit depth, RGB (2), Deflate (0), Filter (0), Interlace (0)
  const width = 120;
  const height = 120;
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData.writeUInt8(8, 8); // 8-bit
  ihdrData.writeUInt8(2, 9); // Color type: Truecolor (RGB)
  ihdrData.writeUInt8(0, 10);
  ihdrData.writeUInt8(0, 11);
  ihdrData.writeUInt8(0, 12);
  const ihdrChunk = makeChunk('IHDR', ihdrData);

  // tEXt chunk 1: Author
  const authorData = Buffer.from('Author\0Krypteia Cyber Security Club - St. Peter\'s Engineering College', 'latin1');
  const textChunk1 = makeChunk('tEXt', authorData);

  // tEXt chunk 2: Forensics Secret Flag from DB
  const forensicsFlag = getChallengeFlag('forensics-01');
  const flagData = Buffer.from(`Description\0FORENSICS_RECORD: Flag is ${forensicsFlag}`, 'latin1');
  const textChunk2 = makeChunk('tEXt', flagData);

  // tEXt chunk 3: Additional hint
  const hintData = Buffer.from('Comment\0Metadata inspection successful. Recovered from lab USB sector #09.', 'latin1');
  const textChunk3 = makeChunk('tEXt', hintData);

  // Image data: Raw RGB scanlines with filter byte 0
  const zlib = require('zlib');
  const rawRows = [];
  for (let y = 0; y < height; y++) {
    const row = Buffer.alloc(1 + width * 3);
    row[0] = 0; // Filter: none
    for (let x = 0; x < width; x++) {
      // Create a nice dark navy + cyan pattern
      const idx = 1 + x * 3;
      const r = Math.min(255, Math.floor((x / width) * 20));
      const g = Math.min(255, Math.floor(180 + Math.sin(x / 10) * 40));
      const b = Math.min(255, Math.floor(220 + Math.cos(y / 10) * 35));
      row[idx] = r;
      row[idx + 1] = g;
      row[idx + 2] = b;
    }
    rawRows.push(row);
  }
  const rawImage = Buffer.concat(rawRows);
  const compressedImage = zlib.deflateSync(rawImage);
  const idatChunk = makeChunk('IDAT', compressedImage);

  // IEND chunk
  const iendChunk = makeChunk('IEND', Buffer.alloc(0));

  const fullPng = Buffer.concat([signature, ihdrChunk, textChunk1, textChunk2, textChunk3, idatChunk, iendChunk]);
  fs.writeFileSync(pngPath, fullPng);
  console.log('Created stego_specimen.png, bytes:', fullPng.length);
}

// 3. Generate XOR encrypted stream
function generateXorStream() {
  const hexPath = path.join(attachmentsDir, 'xor_stream.hex');
  const plaintext = getChallengeFlag('crypto-02');
  const key = 'KRYPT';
  const ciphertextBytes = [];

  for (let i = 0; i < plaintext.length; i++) {
    const p = plaintext.charCodeAt(i);
    const k = key.charCodeAt(i % key.length);
    ciphertextBytes.push(p ^ k);
  }

  const hexString = Buffer.from(ciphertextBytes).toString('hex');
  fs.writeFileSync(hexPath, hexString + '\n');
  console.log('Created xor_stream.hex:', hexString);
}

// 4. Generate evidence_image.png for forensics-02 challenge
// Flag fragment 1 in tEXt metadata, fragment 2 appended after IEND
function generateEvidenceImage() {
  const pngPath = path.join(attachmentsDir, 'evidence_image.png');
  const zlib = require('zlib');

  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  function crc32(buf) {
    let table = [];
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[i] = c;
    }
    let crc = 0 ^ (-1);
    for (let i = 0; i < buf.length; i++) {
      crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xff];
    }
    return (crc ^ (-1)) >>> 0;
  }

  function makeChunk(type, data) {
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(data.length, 0);
    const typeBuf = Buffer.from(type, 'ascii');
    const typeAndData = Buffer.concat([typeBuf, data]);
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crc32(typeAndData), 0);
    return Buffer.concat([lenBuf, typeAndData, crcBuf]);
  }

  // IHDR: 100x100 8-bit RGB
  const width = 100;
  const height = 100;
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData.writeUInt8(8, 8);
  ihdrData.writeUInt8(2, 9);
  ihdrData.writeUInt8(0, 10);
  ihdrData.writeUInt8(0, 11);
  ihdrData.writeUInt8(0, 12);
  const ihdrChunk = makeChunk('IHDR', ihdrData);

  // tEXt chunk: Flag fragment 1 hidden in Comment metadata
  const forensics2Flag = getChallengeFlag('forensics-02');
  const frag1 = forensics2Flag ? forensics2Flag.substring(0, 18) : '';
  const metaData = Buffer.from(`Comment\0${frag1}`, 'latin1');
  const textChunk = makeChunk('tEXt', metaData);

  // tEXt chunk: Innocent-looking author info
  const authorData = Buffer.from('Author\0SPEC Incident Response Team', 'latin1');
  const authorChunk = makeChunk('tEXt', authorData);

  // Image data: Dark gradient pattern
  const rawRows = [];
  for (let y = 0; y < height; y++) {
    const row = Buffer.alloc(1 + width * 3);
    row[0] = 0;
    for (let x = 0; x < width; x++) {
      const idx = 1 + x * 3;
      row[idx] = Math.min(255, Math.floor(30 + (x / width) * 60));
      row[idx + 1] = Math.min(255, Math.floor(30 + (y / height) * 80));
      row[idx + 2] = Math.min(255, Math.floor(60 + Math.sin((x + y) / 15) * 40));
    }
    rawRows.push(row);
  }
  const rawImage = Buffer.concat(rawRows);
  const compressedImage = zlib.deflateSync(rawImage);
  const idatChunk = makeChunk('IDAT', compressedImage);

  // IEND chunk
  const iendChunk = makeChunk('IEND', Buffer.alloc(0));

  // Append fragment 2 AFTER IEND as hidden embedded artifact
  const frag2 = forensics2Flag ? forensics2Flag.substring(18) : '';
  const hiddenArtifact = Buffer.from(`\n--- EMBEDDED ARTIFACT ---\nRecovered from disk sector 0x4F:\n${frag2}\n--- END ARTIFACT ---\n`);

  const fullPng = Buffer.concat([signature, ihdrChunk, authorChunk, textChunk, idatChunk, iendChunk, hiddenArtifact]);
  fs.writeFileSync(pngPath, fullPng);
  console.log('Created evidence_image.png, bytes:', fullPng.length);
}

generatePcap();
generateStegoPng();
generateXorStream();
generateEvidenceImage();
console.log('All challenge assets generated successfully!');
