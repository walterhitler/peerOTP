# 🔐 PeerOTP

> **P2P TOTP Shared Secret Distributor — No Google. No Authy. No cloud. Just your team.**

[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-green)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue)](LICENSE)
[![RFC 6238](https://img.shields.io/badge/TOTP-RFC%206238-blueviolet)](https://datatracker.ietf.org/doc/html/rfc6238)
[![Built for](https://img.shields.io/badge/Built%20for-Intercom%20Vibe%20Competition-orange)](https://github.com/Trac-Systems/intercom)
[![Termux Ready](https://img.shields.io/badge/Termux-Ready-brightgreen)](https://termux.dev)

---

## The Problem

Your team shares 2FA access to a staging server, AWS account, or internal dashboard. Someone sets up Google Authenticator — but it's on their phone only. Others need Authy Teams ($$$) or 1Password ($$$) just to get the TOTP codes.

**PeerOTP fixes this with zero infrastructure.**

---

## What is PeerOTP?

PeerOTP lets you:

1. **Create** a named vault of TOTP secrets (like a shared Authenticator app)
2. **Generate** RFC 6238-compliant 6-digit OTP codes locally
3. **Share** the vault to teammates P2P via Hyperswarm — one-time delivery, no server
4. **Watch** a live auto-refreshing terminal dashboard of all current codes

Everything runs locally. The TOTP algorithm is implemented from scratch (HMAC-SHA1 + sliding window — RFC 6238) using only Node.js built-in `crypto`. No cloud, no accounts, no fees.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    VAULT (local file)                    │
│  myteam.peerotp                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ label: "AWS Root"    secret: JBSWY3DPEHPK3PXP      │  │
│  │ label: "GitHub Org"  secret: MFRA2YLBMFRA2YLB      │  │
│  │ label: "Staging API" secret: ORSXG5BR...           │  │
│  └────────────────────────────────────────────────────┘  │
└───────────────────────────┬──────────────────────────────┘
                            │
              node index.js --mode share
                            │
                     Hyperswarm P2P
                            │
            ┌───────────────┴────────────────┐
            │                                │
   [Termux/Android]                    [Laptop/Desktop]
   node index.js                       node index.js
   --mode receive                      --mode receive
            │                                │
    vault saved locally              vault saved locally
    node index.js --mode watch       node index.js --mode watch
            │                                │
   ┌────────────────┐              ┌────────────────┐
   │ AWS Root       │              │ AWS Root       │
   │ 482 193  ▓▓░░  │              │ 482 193  ▓▓░░  │ ← same codes!
   │ GitHub   │              │ GitHub         │
   │ 719 044  ▓▓░░  │              │ 719 044  ▓▓░░  │
   └────────────────┘              └────────────────┘
```

---

## TOTP Implementation

PeerOTP implements **RFC 6238 TOTP** from scratch — zero extra npm packages:

```
TOTP(secret, time) = HOTP(secret, floor(epoch / 30))
HOTP(secret, counter) = Truncate(HMAC-SHA1(secret, counter)) mod 10^6
```

This is the exact same algorithm used by Google Authenticator, Authy, and every TOTP-compatible 2FA app. Any secret that works in those apps works in PeerOTP.

---

## Installation

### Desktop / Linux / macOS

```bash
git clone https://github.com/walterhitler/peerotp
cd peerotp
npm install
node index.js
```

---

## Usage

### Step 1 — Create a vault with TOTP secrets

```bash
node index.js --mode setup
```

Follow the prompts:
- Enter a vault name (e.g. `myteam`)
- Add entries: label, issuer, secret (Base32)
- Press Enter on secret field to **auto-generate** a new secret

The vault is saved as `myteam.peerotp` (local JSON file).

### Step 2 — Generate current OTP codes

```bash
node index.js --mode token --vault myteam
```

Prints all current 6-digit codes with countdown timer.

### Step 3 — Live dashboard (auto-refresh every second)

```bash
node index.js --mode watch --vault myteam
```

Full-screen terminal dashboard. Codes refresh automatically at each 30s window boundary.

### Step 4 — Share vault to teammates P2P

**Sharer (you):**
```bash
node index.js --mode share --vault myteam
# Outputs a 64-char topic key — share it with teammates
```

**Recipient (teammate):**
```bash
node index.js --mode receive --topic <64-char-key>
# Vault is saved locally, ready to use immediately
```

---

## CLI Reference

| Flag | Example | Description |
|---|---|---|
| `--mode` | `--mode watch` | `setup`, `token`, `watch`, `share`, `receive` |
| `--vault` | `--vault myteam` | Vault name (maps to `myteam.peerotp` file) |
| `--topic` | `--topic abc123…` | P2P topic key for receive mode |

---

## Interactive Commands (main menu)

```
[1] setup    — Create or add entries to a vault
[2] token    — Show current OTP codes
[3] watch    — Live auto-refreshing dashboard
[4] share    — Share vault to peers via P2P
[5] receive  — Receive a vault from a peer
[q] quit
```

---

## Security Notes

- Vault files (`.peerotp`) are stored as **plain JSON** on disk. Protect them like any credentials file.
- P2P sharing uses Hyperswarm's built-in **Noise protocol** (authenticated + encrypted transport).
- For extra safety, share the vault over a **short-lived session** and delete the sharer's copy after.
- PeerOTP does **not** store secrets on any server, cloud, or third-party service.
- The TOTP algorithm is deterministic — the same secret + same 30s window = same code on every device.

---

## Compatibility

PeerOTP secrets are fully compatible with:
- Google Authenticator
- Authy
- Microsoft Authenticator
- Any RFC 6238-compliant TOTP app

You can import secrets generated by those apps into PeerOTP (use the Base32 secret from the QR code).

---

## Vault File Format

```json
{
  "name": "myteam",
  "created": "2026-02-19T09:00:00.000Z",
  "entries": [
    {
      "label": "AWS Root",
      "issuer": "Amazon",
      "secret": "JBSWY3DPEHPK3PXP"
    },
    {
      "label": "GitHub Org",
      "issuer": "GitHub",
      "secret": "MFRA2YLBMFRA2YLB"
    }
  ]
}
```

---

## Trac Address (for payouts)

trac1tvll5u5w0xkqpfe0p2rta2cd92f3vk45t2lvha7ej3td607kl80s20lt6g


---

## Competition Context

Submitted to the **Intercom Vibe Competition** by Trac Systems.

Forked from [Trac-Systems/intercom](https://github.com/Trac-Systems/intercom).

**Why PeerOTP stands out:**
- Solves a real, universal pain point for developer teams
- Zero dependencies beyond Hyperswarm — TOTP is pure Node.js `crypto`
- Cross-compatible with Google Authenticator secrets
- Works fully on mobile via Termux (no native modules)
- Clean separation: vault management + OTP generation + P2P sharing are all independent

---

## License

MIT © trac1tvll5u5w0xkqpfe0p2rta2cd92f3vk45t2lvha7ej3td607kl80s20lt6g]
