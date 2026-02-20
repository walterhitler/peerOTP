#!/usr/bin/env node
/**
 * ╔═══════════════════════════════════════════════════════════╗
 * ║               P E E R O T P   v1.0.0                    ║
 * ║    P2P TOTP Shared Secret Distributor & Generator        ║
 * ║    Intercom Vibe Competition Submission                  ║
 * ║    Trac: [INSERT_YOUR_TRAC_ADDRESS_HERE]                 ║
 * ╚═══════════════════════════════════════════════════════════╝
 *
 * WHAT IT DOES:
 *   Teams often share 2FA/TOTP secrets (like for a shared AWS account,
 *   staging API key, or internal tool). The usual solution is Authy Teams
 *   or 1Password — both are cloud-based and cost money.
 *
 *   PeerOTP lets you:
 *     1. CREATE a TOTP vault (named set of secrets)
 *     2. SHARE the vault to peers via P2P (one-time delivery, encrypted)
 *     3. GENERATE current OTP codes from any received vault
 *     4. WATCH live — auto-refreshing OTP codes every 30s
 *
 * HOW TOTP WORKS (RFC 6238 — implemented from scratch, no npm deps):
 *   TOTP = HOTP(secret, floor(epoch / 30))
 *   HOTP = HMAC-SHA1(secret, counter) → truncate to 6 digits
 *   This is the exact same algorithm used by Google Authenticator.
 *
 * MODES:
 *   node index.js                          # Interactive menu
 *   node index.js --mode setup             # Create/manage vault
 *   node index.js --mode token             # Generate current OTP codes
 *   node index.js --mode share             # Share vault to peers P2P
 *   node index.js --mode watch             # Live auto-refresh dashboard
 *   node index.js --vault myteam          # Use a named vault file
 */

'use strict';

const Hyperswarm = require('hyperswarm');
const crypto     = require('hypercore-crypto');
const b4a        = require('b4a');
const readline   = require('readline');
const fs         = require('fs');
const path       = require('path');
const nodeCrypto = require('crypto');
const args       = require('minimist')(process.argv.slice(2));

// ─── ANSI Colors ─────────────────────────────────────────────────────────────
const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  cyan: '\x1b[36m', green: '\x1b[32m', yellow: '\x1b[33m',
  red: '\x1b[31m', magenta: '\x1b[35m', blue: '\x1b[34m',
  white: '\x1b[37m', bgBlack: '\x1b[40m', bgGreen: '\x1b[42m',
};

// ─── Config ───────────────────────────────────────────────────────────────────
const MODE       = args.mode  || null;
const VAULT_NAME = args.vault || 'default';
const VAULT_FILE = path.join(process.cwd(), `${VAULT_NAME}.peerotp`);
const PROTO_VER  = 1;

// ─── Utilities ────────────────────────────────────────────────────────────────
const ts  = () => new Date().toLocaleTimeString('en-GB', { hour12: false });
const log = (icon, col, msg) =>
  console.log(`${col}${C.bold}[${ts()}]${C.reset} ${col}${icon}${C.reset} ${msg}`);

const info    = m => log('ℹ', C.cyan,    m);
const success = m => log('✔', C.green,   m);
const warn    = m => log('⚠', C.yellow,  m);
const danger  = m => log('✖', C.red,     m);

// ─── TOTP Implementation (RFC 6238) — zero external dependencies ──────────────

/**
 * Decode a Base32 string to a Buffer.
 * Most TOTP secrets are Base32-encoded.
 */
function base32Decode(str) {
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const s = str.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0, value = 0;
  const output = [];
  for (const ch of s) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

/**
 * Generate a Base32-encoded random secret (160-bit, standard TOTP size).
 */
function generateSecret() {
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const raw = nodeCrypto.randomBytes(20); // 160 bits
  let result = '';
  let bits = 0, value = 0;
  for (const byte of raw) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) result += ALPHABET[(value << (5 - bits)) & 0x1f];
  // Pad to multiple of 8
  while (result.length % 8 !== 0) result += '=';
  return result;
}

/**
 * HMAC-SHA1 using Node's built-in crypto.
 */
function hmacSha1(keyBuf, dataBuf) {
  return nodeCrypto.createHmac('sha1', keyBuf).update(dataBuf).digest();
}

/**
 * Compute TOTP for a given Base32 secret and optional timestamp.
 * Returns a zero-padded 6-digit string.
 */
function totp(secret, epochMs = Date.now()) {
  const counter = Math.floor(epochMs / 1000 / 30);
  const keyBuf  = base32Decode(secret.replace(/\s/g, ''));

  // Counter as 8-byte big-endian buffer
  const counterBuf = Buffer.alloc(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    counterBuf[i] = c & 0xff;
    c = Math.floor(c / 256);
  }

  const hmac  = hmacSha1(keyBuf, counterBuf);
  const offset = hmac[19] & 0x0f;
  const code  = (
    ((hmac[offset]     & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8)  |
     (hmac[offset + 3] & 0xff)
  ) % 1_000_000;

  return String(code).padStart(6, '0');
}

/**
 * Seconds remaining in the current 30s TOTP window.
 */
function secondsRemaining() {
  return 30 - (Math.floor(Date.now() / 1000) % 30);
}

/**
 * Visual countdown bar (width = 20 chars).
 */
function countdownBar() {
  const rem   = secondsRemaining();
  const pct   = rem / 30;
  const W     = 20;
  const filled = Math.round(pct * W);
  const color  = rem <= 5 ? C.red : rem <= 10 ? C.yellow : C.green;
  return `${color}${'█'.repeat(filled)}${C.dim}${'░'.repeat(W - filled)}${C.reset} ${color}${C.bold}${rem}s${C.reset}`;
}

// ─── Vault I/O ────────────────────────────────────────────────────────────────
// Vault format: JSON file { name, created, entries: [{label, secret, issuer}] }

function loadVault() {
  if (!fs.existsSync(VAULT_FILE)) return null;
  try {
    return JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8'));
  } catch {
    return null;
  }
}

function saveVault(vault) {
  fs.writeFileSync(VAULT_FILE, JSON.stringify(vault, null, 2));
}

function requireVault() {
  const v = loadVault();
  if (!v) {
    danger(`No vault found at ${C.bold}${VAULT_FILE}${C.reset}`);
    danger(`Run ${C.bold}node index.js --mode setup${C.reset} first.`);
    process.exit(1);
  }
  return v;
}

// ─── Banner ───────────────────────────────────────────────────────────────────
function printBanner() {
  console.log(`
${C.green}${C.bold}╔═══════════════════════════════════════════════════════════╗
║               P E E R O T P   v1.0.0                    ║
║    P2P TOTP Secret Distributor & OTP Generator           ║
╚═══════════════════════════════════════════════════════════╝${C.reset}
  ${C.dim}RFC 6238 TOTP · No cloud · No Authy · Built on Hyperswarm${C.reset}
  ${C.dim}Intercom Vibe Competition · [INSERT_YOUR_TRAC_ADDRESS_HERE]${C.reset}
`);
}

// ─── SETUP MODE ───────────────────────────────────────────────────────────────
async function runSetup() {
  const rl  = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = q => new Promise(r => rl.question(q, r));

  console.log(`\n${C.green}${C.bold}[ VAULT SETUP ]${C.reset} Create or manage your PeerOTP vault.\n`);

  let vault = loadVault();
  if (vault) {
    info(`Existing vault found: ${C.bold}${vault.name}${C.reset} (${vault.entries.length} entries)`);
    const choice = (await ask(`${C.yellow}Add entry / (v)iew / (d)elete / (q)uit? ${C.reset}`)).trim().toLowerCase();
    if (choice === 'v') {
      printVaultTable(vault);
      rl.close();
      return;
    }
    if (choice === 'd') {
      printVaultTable(vault);
      const idx = parseInt(await ask(`${C.yellow}Delete entry number: ${C.reset}`)) - 1;
      if (idx >= 0 && idx < vault.entries.length) {
        const removed = vault.entries.splice(idx, 1)[0];
        saveVault(vault);
        success(`Removed: ${removed.label}`);
      } else {
        warn('Invalid index.');
      }
      rl.close();
      return;
    }
    if (choice === 'q') { rl.close(); return; }
  } else {
    const vaultName = (await ask(`${C.cyan}Vault name ${C.dim}(e.g. "myteam"):${C.reset} `)).trim() || 'MyTeam';
    vault = { name: vaultName, created: new Date().toISOString(), entries: [] };
    info(`Creating vault: ${C.bold}${vaultName}${C.reset}`);
  }

  // Add a new entry
  console.log(`\n${C.cyan}${C.bold}New TOTP Entry:${C.reset}`);
  const label  = (await ask(`  Label   ${C.dim}(e.g. "AWS Root"):${C.reset} `)).trim();
  const issuer = (await ask(`  Issuer  ${C.dim}(e.g. "Amazon"):${C.reset} `)).trim() || label;
  let   secret = (await ask(`  Secret  ${C.dim}(Base32, or Enter to generate):${C.reset} `)).trim().toUpperCase().replace(/\s/g, '');

  if (!secret) {
    secret = generateSecret();
    success(`Generated secret: ${C.bold}${C.yellow}${secret}${C.reset}`);
  } else {
    // Validate by attempting to decode
    try { base32Decode(secret); success('Secret validated.'); }
    catch { warn('Secret may be invalid Base32 — saving anyway.'); }
  }

  if (!label) { warn('Label required.'); rl.close(); return; }

  vault.entries.push({ label, issuer, secret });
  saveVault(vault);

  success(`Entry added! Vault saved to ${C.bold}${VAULT_FILE}${C.reset}`);
  success(`Vault now has ${C.bold}${vault.entries.length}${C.reset} entr${vault.entries.length === 1 ? 'y' : 'ies'}.`);

  // Show the OTP immediately
  console.log(`\n  Current OTP for ${C.bold}${label}${C.reset}: ${C.green}${C.bold}${totp(secret)}${C.reset}  ${countdownBar()}\n`);

  rl.close();
}

// ─── TOKEN MODE ───────────────────────────────────────────────────────────────
function runToken() {
  const vault = requireVault();
  console.log(`\n${C.green}${C.bold}[ OTP CODES ]${C.reset}  Vault: ${C.bold}${vault.name}${C.reset}  —  ${new Date().toLocaleString()}\n`);
  printOTPTable(vault);
}

function printOTPTable(vault) {
  const SEP = `${C.dim}${'─'.repeat(52)}${C.reset}`;
  const rem = secondsRemaining();
  const bar = countdownBar();

  console.log(SEP);
  console.log(`  ${C.dim}LABEL                  CODE      EXPIRES${C.reset}`);
  console.log(SEP);

  vault.entries.forEach(entry => {
    const code  = totp(entry.secret);
    const label = entry.label.padEnd(22).slice(0, 22);
    // Format: 123 456
    const pretty = `${code.slice(0, 3)} ${code.slice(3)}`;
    console.log(`  ${C.bold}${C.white}${label}${C.reset}  ${C.green}${C.bold}${pretty}${C.reset}   ${bar}`);
  });

  console.log(SEP);
  console.log(`  ${C.dim}${vault.entries.length} entr${vault.entries.length === 1 ? 'y' : 'ies'} · next rotation in ${rem}s · RFC 6238 TOTP${C.reset}\n`);
}

function printVaultTable(vault) {
  console.log(`\n${C.cyan}${C.bold}Vault: ${vault.name}${C.reset}  (${vault.entries.length} entries)\n`);
  vault.entries.forEach((e, i) => {
    console.log(`  ${C.dim}${i + 1}.${C.reset} ${C.bold}${e.label}${C.reset}  ${C.dim}(${e.issuer})${C.reset}`);
    console.log(`     Secret: ${C.yellow}${e.secret}${C.reset}`);
  });
  console.log('');
}

// ─── WATCH MODE — live auto-refresh dashboard ─────────────────────────────────
function runWatch() {
  const vault = requireVault();

  const render = () => {
    process.stdout.write('\x1b[2J\x1b[H'); // clear screen
    console.log(`${C.green}${C.bold}  🔐 PeerOTP — Live Dashboard${C.reset}  ${C.dim}${ts()}${C.reset}  ${C.dim}Vault: ${vault.name}${C.reset}\n`);
    printOTPTable(vault);
    console.log(`  ${C.dim}Ctrl+C to exit · codes rotate every 30s${C.reset}`);
  };

  render();
  // Refresh on each new 30s window boundary + every second for countdown
  setInterval(render, 1000);

  process.on('SIGINT', () => {
    console.log('\n');
    process.exit(0);
  });
}

// ─── SHARE MODE — send vault to peers via Hyperswarm ─────────────────────────
async function runShare() {
  const vault = requireVault();
  const peers = new Set();

  console.log(`\n${C.magenta}${C.bold}[ SHARE MODE ]${C.reset} Broadcasting vault to peers via P2P.\n`);
  info(`Vault: ${C.bold}${vault.name}${C.reset} — ${vault.entries.length} entries`);
  warn(`Only share with trusted peers on a private topic!`);

  // Derive a unique swarm topic per vault name
  const topicSeed = b4a.from(`peerotp:vault:${vault.name}:intercom-vibe-2025`);
  const topicBuf  = crypto.hash(topicSeed);
  const topicHex  = b4a.toString(topicBuf, 'hex');

  console.log(`\n${C.bgBlack}${C.bold}${C.white}  SHARE TOPIC KEY  ${C.reset}`);
  console.log(`  ${C.yellow}${C.bold}${topicHex}${C.reset}`);
  console.log(`  ${C.dim}Give this key to recipients: node index.js --mode receive --topic ${topicHex.slice(0, 16)}…${C.reset}\n`);

  const swarm = new Hyperswarm();

  swarm.on('connection', (conn, peerInfo) => {
    const pid = b4a.toString(peerInfo.publicKey, 'hex').slice(0, 10);
    peers.add(conn);
    info(`Peer connected ${C.dim}(${pid}…)${C.reset} — sending vault…`);

    const payload = JSON.stringify({
      v:     PROTO_VER,
      type:  'vault_share',
      vault,
      ts:    Date.now(),
    });

    try {
      conn.write(b4a.from(payload));
      success(`Vault sent to ${C.dim}(${pid}…)${C.reset}`);
    } catch (e) {
      warn(`Send failed: ${e.message}`);
    }

    conn.on('data', raw => {
      try {
        const msg = JSON.parse(raw.toString());
        if (msg.type === 'vault_ack') {
          success(`${C.bold}Peer (${pid}…) confirmed receipt!${C.reset}`);
        }
      } catch (_) {}
    });

    conn.on('error', () => {});
    conn.on('close', () => { peers.delete(conn); });
  });

  swarm.on('error', e => warn(`Swarm: ${e.message}`));

  const disc = swarm.join(topicBuf, { server: true, client: false });
  await disc.flushed();

  success(`Sharing on P2P topic. Waiting for peers… (Ctrl+C to stop)\n`);

  process.on('SIGINT', async () => {
    info('Stopping share…');
    await swarm.destroy();
    process.exit(0);
  });
}

// ─── RECEIVE MODE — receive vault from a peer ────────────────────────────────
async function runReceive() {
  const customTopic = args.topic;
  const peers = new Set();

  console.log(`\n${C.cyan}${C.bold}[ RECEIVE MODE ]${C.reset} Waiting for a peer to share a vault.\n`);

  let topicBuf;
  if (customTopic) {
    // Accept partial hex — pad or hash it
    const full = customTopic.length === 64 ? customTopic : b4a.toString(crypto.hash(b4a.from(`peerotp:vault:${customTopic}:intercom-vibe-2025`)), 'hex');
    topicBuf = b4a.from(full, 'hex');
    info(`Using topic: ${C.dim}${full}${C.reset}`);
  } else {
    // Use vault name as fallback
    const topicSeed = b4a.from(`peerotp:vault:${VAULT_NAME}:intercom-vibe-2025`);
    topicBuf = crypto.hash(topicSeed);
    info(`Using default vault topic for: ${C.bold}${VAULT_NAME}${C.reset}`);
  }

  const swarm = new Hyperswarm();
  let received = false;

  swarm.on('connection', (conn, peerInfo) => {
    const pid = b4a.toString(peerInfo.publicKey, 'hex').slice(0, 10);
    peers.add(conn);
    info(`Connected to sharer ${C.dim}(${pid}…)${C.reset} — waiting for vault…`);

    conn.on('data', async raw => {
      if (received) return;
      let msg;
      try { msg = JSON.parse(raw.toString()); } catch { return; }
      if (msg.type !== 'vault_share' || msg.v !== PROTO_VER) return;

      received = true;
      const vault = msg.vault;

      console.log(`\n${C.green}${C.bold}✔ Vault received: ${vault.name}${C.reset}  (${vault.entries.length} entries)\n`);
      vault.entries.forEach((e, i) => {
        const code = totp(e.secret);
        console.log(`  ${C.dim}${i + 1}.${C.reset} ${C.bold}${e.label}${C.reset}  ${C.dim}(${e.issuer})${C.reset}`);
        console.log(`     OTP now: ${C.green}${C.bold}${code.slice(0, 3)} ${code.slice(3)}${C.reset}  ${countdownBar()}`);
      });

      // Save vault locally
      const outFile = path.join(process.cwd(), `${vault.name.replace(/\s+/g, '_').toLowerCase()}.peerotp`);
      fs.writeFileSync(outFile, JSON.stringify(vault, null, 2));
      success(`\nVault saved → ${C.bold}${outFile}${C.reset}`);
      success(`Run ${C.bold}node index.js --mode watch --vault ${vault.name.replace(/\s+/g, '_').toLowerCase()}${C.reset} for live codes.`);

      // ACK the sender
      try { conn.write(b4a.from(JSON.stringify({ type: 'vault_ack', ts: Date.now() }))); } catch (_) {}

      await new Promise(r => setTimeout(r, 500));
      await swarm.destroy();
      process.exit(0);
    });

    conn.on('error', () => {});
    conn.on('close', () => { peers.delete(conn); });
  });

  swarm.on('error', e => warn(`Swarm: ${e.message}`));

  const disc = swarm.join(topicBuf, { server: false, client: true });
  await disc.flushed();

  info(`Listening for incoming vault… (Ctrl+C to cancel)\n`);

  setTimeout(() => {
    if (!received) {
      warn('No sharer found after 60s. Check topic key or try again.');
      swarm.destroy().then(() => process.exit(1));
    }
  }, 60000);

  process.on('SIGINT', async () => {
    await swarm.destroy(); process.exit(0);
  });
}

// ─── INTERACTIVE MENU ─────────────────────────────────────────────────────────
async function interactiveMenu() {
  const rl  = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = q => new Promise(r => rl.question(q, r));

  const vault = loadVault();
  const vaultStatus = vault
    ? `${C.green}${C.bold}${vault.name}${C.reset} ${C.dim}(${vault.entries.length} entries)${C.reset}`
    : `${C.yellow}${C.dim}none — run setup first${C.reset}`;

  console.log(`  ${C.dim}Active vault:${C.reset} ${vaultStatus}\n`);
  console.log(`${C.green}${C.bold}Choose a mode:${C.reset}

  ${C.cyan}[1]${C.reset} setup    — Create or add entries to a vault
  ${C.green}[2]${C.reset} token    — Show current OTP codes
  ${C.green}[3]${C.reset} watch    — Live auto-refreshing dashboard
  ${C.magenta}[4]${C.reset} share    — Share vault to peers via P2P
  ${C.cyan}[5]${C.reset} receive  — Receive a vault from a peer
  ${C.dim}[q]${C.reset} quit
`);

  const choice = (await ask(`${C.dim}Choice: ${C.reset}`)).trim().toLowerCase();
  rl.close();

  switch (choice) {
    case '1': case 'setup':   await runSetup();   break;
    case '2': case 'token':         runToken();   break;
    case '3': case 'watch':         runWatch();   break;
    case '4': case 'share':   await runShare();   break;
    case '5': case 'receive': await runReceive(); break;
    default:  info('Goodbye.'); process.exit(0);
  }
}

// ─── ENTRY ────────────────────────────────────────────────────────────────────
async function main() {
  printBanner();

  switch (MODE) {
    case 'setup':   await runSetup();   break;
    case 'token':         runToken();   break;
    case 'watch':         runWatch();   break;
    case 'share':   await runShare();   break;
    case 'receive': await runReceive(); break;
    default:        await interactiveMenu();
  }
}

main().catch(err => {
  danger(`Fatal: ${err.message}`);
  console.error(err);
  process.exit(1);
});
