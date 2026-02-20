# PeerOTP — SKILL.md

> Intercom Vibe Competition submission. Agent instructions and protocol reference.

## What is PeerOTP?

A decentralized P2P TOTP (Time-based One-Time Password) secret distributor and OTP generator. Implements RFC 6238 TOTP from scratch using Node.js built-in `crypto`. Shares vaults across devices via Hyperswarm with zero cloud infrastructure.

## Modes

| Mode | Flag | Description |
|---|---|---|
| Interactive | *(none)* | Menu-driven, choose any mode |
| Setup | `--mode setup` | Create vault, add TOTP entries |
| Token | `--mode token` | Print current OTP codes |
| Watch | `--mode watch` | Live auto-refreshing dashboard |
| Share | `--mode share` | Broadcast vault to peers P2P |
| Receive | `--mode receive` | Accept vault from a peer |

## Vault Format

```json
{
  "name": "myteam",
  "created": "ISO8601",
  "entries": [
    { "label": "AWS Root", "issuer": "Amazon", "secret": "BASE32SECRET" }
  ]
}
```

Saved as `<vaultname>.peerotp` in the working directory.

## TOTP Algorithm (RFC 6238)

```
counter  = floor(epoch_ms / 1000 / 30)
key      = base32_decode(secret)
hmac     = HMAC-SHA1(key, counter_as_8_bytes_big_endian)
offset   = hmac[19] & 0x0f
code     = ((hmac[offset..offset+3] & 0x7fffffff) % 1_000_000).padStart(6,'0')
```

## P2P Share Protocol

```json
// Sharer → Receiver
{ "v": 1, "type": "vault_share", "vault": { ... }, "ts": 1718000000000 }

// Receiver → Sharer (acknowledgement)
{ "type": "vault_ack", "ts": 1718000000001 }
```

## Topic Derivation

```js
const crypto  = require('hypercore-crypto');
const b4a     = require('b4a');
const seed    = b4a.from(`peerotp:vault:${vaultName}:intercom-vibe-2025`);
const topic   = crypto.hash(seed); // 32-byte Buffer
```

Sharer joins with `{ server: true, client: false }`.
Receiver joins with `{ server: false, client: true }`.

## Security Model

- Vault files are plain JSON — protect like credentials
- P2P transport uses Hyperswarm Noise protocol (authenticated + encrypted)
- No secrets ever leave your machine to any central server
- Compatible with Google Authenticator, Authy, Microsoft Authenticator

## Trac Address

```
trac1tvll5u5w0xkqpfe0p2rta2cd92f3vk45t2lvha7ej3td607kl80s20lt6g
```

## License

MIT
