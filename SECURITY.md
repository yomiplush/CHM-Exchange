# Security Model & Threat Analysis — CHM-Exchange & CHM-DEVICE-PAIRING-v1

## 1. Security Architecture Summary

CHM-Exchange is a **public-key-only, zero-backend, static client library**. It contains **zero** server endpoints, **zero** outbound network calls, and **zero** telemetry. Private-key custody and IndexedDB storage belong strictly to the host application.

### Defense-in-Depth Input & Payload Controls (`CHM-Exchange` & `CHM-DEVICE-PAIRING-v1`)

| Control | Implementation |
|---|---|
| Payload size bounds | Exchange URLs `<= 4096` chars; pairing tokens `<= 3072` chars; pairing CBOR envelopes `<= 2048` bytes; registry exports `<= 256 KiB`; `.json` public-key imports `<= 4096` bytes; `displayName <= 64` UTF-8 bytes; notes `<= 160` (`<= 200` for trust notes) UTF-8 bytes. |
| Strict Base64url | Only `[A-Za-z0-9_-]`, unpadded, canonical round-trip check (`base64UrlEncode(decoded) === input`) rejecting non-canonical trailing bits. |
| Strict RFC 8949 CBOR | Rejects indefinite-length items, `undefined`, `NaN`/`Infinity`, duplicate keys, invalid UTF-8, unexpected integer map keys, and non-canonical encodings via byte-for-byte re-encode equality verification. |
| Strict Ed25519 validation | Requires exact 32-byte public keys and 64-byte signatures; rejects all-zero, small-order, and non-torsion-free curve points (`Point.fromBytes`); verifies signatures with `{ zip215: false }`. |
| Domain separation | Pairing requests (`CHM-DEVICE-PAIRING-v1:REQ\0`), certificates (`:CERT\0`), revocations (`:REVOKE\0`), and registry snapshots (`:REGISTRY\0`) cannot collide with each other or with artwork provenance signatures. |
| Cryptographic binding | Enrollment certificates embed `requestHash = SHA-256(canonicalRequestEnvelope)` plus `requestId`, 256-bit `nonce`, `deviceId`, `devicePublicKey`, and `requestExpiresAt`. Requests pinned to an Owner key or fingerprint cannot be satisfied by another Owner key. |
| Privilege boundary (`v1`) | Only `["device-identity"]` permission is allowed in `v1`. `root-signing`, `artwork-signing`, `device-approval`, `key-revocation`, `admin`, and `*` are explicitly forbidden, and `ownerPublicKey === devicePublicKey` is rejected. |
| Anti-replay & expiry | Pairing requests default to a 5-minute TTL (`<= 1h` max). Consumed `requestId` and 256-bit `nonce` values are rejected by host replay guards even if a device clock is skewed or rolled back. |
| Fingerprint recalculation | Always recomputes `SHA-256(publicKey32)` locally and rejects bundles whose declared `fingerprint` differs (using constant-time ASCII comparison). |
| Schema & prototype-pollution defense | Enforces exact `version === 1` (`UnsupportedExchangeVersionError` / `UnsupportedPairingVersionError`) and recursively rejects `__proto__`, `constructor`, and `prototype` keys. |
| Private-key isolation | Recursively blocks `privateKey`, `secretKey`, `seed`, `pkcs8`, `jwk`, `webCryptoPrivateKey`, `encryptedBackup`, `passphrase`, `ciphertext`, `salt`, `iv`, `d`, `private`, `secret`. Non-extractable `CryptoKey` handles are never accepted or returned. |
| XSS & spoofing prevention | UI renders all imported strings (`displayName`, notes) via escaped React text nodes — never `dangerouslySetInnerHTML`. Rejects ASCII control characters and Unicode bidirectional override/isolate controls (`U+202A–U+202E`, `U+2066–U+2069`). |
| Safe URL handling | Only `https:` and localhost `http:` are allowed for base URLs; incoming URLs reject non-HTTP(S) schemes such as `javascript:` and `data:`. |
| QR image hardening | Pre-flights PNG `IHDR` headers before `fast-png` decompression, capping files at `25 MB`, `8192px` per side, and `32 MP` total pixels. |
| Explicit consent & monotonic revocation | Unknown Owner/Artist public keys start **Unverified** — never auto-trusted by scanning a QR code. Local device revocations cannot be rolled back by importing older signed registry snapshots, and device key collisions enter `conflict-revoked`. |

---

## 2. What CHM-Exchange Guarantees vs. What It Cannot Prove

### Guarantees
- Integrity of imported 32-byte Ed25519 public keys relative to locally computed SHA-256 fingerprints.
- Cryptographic proof-of-possession that a pairing request was signed by the enrolling device's private key and approved by the Owner root key bound to that exact request (`requestHash` + `requestId` + `nonce`).
- Local isolation between private signing keys (`AuthorKeyRecord` / `DeviceIdentity`) and public exchange/pairing payloads.
- Explicit user consent before any scanned Owner or Artist key enters local trust stores, and monotonic preservation of known device revocations.

### Explicit Limitations (No Central Authority / Offline Design)
1. **Impersonation / Name Spoofing:** Anyone can generate an Ed25519 keypair with `displayName: "Famous Artist"`. A valid signature, bundle, or enrollment certificate proves **only** control of the private key matching that public key — **not** real-world legal identity. Always verify the short or full SHA-256 fingerprint out-of-band.
2. **Offline Revocation Propagation Lag (No Global CRL/OCSP):** Because there is zero central server, revoking a lost phone or tablet on your PC does **not** automatically notify your iPad or third-party verifiers. An offline device must NEVER claim a peer device is `"not revoked"` globally — only that no local revocation has been imported yet. Users should share revocation QR codes/files or updated signed registry snapshots between their devices.
3. **Browser / Device Compromise (XSS or Stolen Unlocked Device):** Non-extractable Web Crypto `CryptoKey` objects prevent exfiltrating raw private key bytes, but malware or XSS executing within the same browser origin (or an attacker holding an unlocked device) can still invoke `sign()` locally while unrevoked. Strict CSP (`connect-src 'self'`), sanitized React text rendering, and passphrases (for fallback encrypted seeds) mitigate this boundary.
4. **Local Clock Skew:** Expiry enforcement (`expiresAt`) relies on device clocks; replay prevention therefore additionally relies on persistent `requestId` + 256-bit `nonce` tracking in host IndexedDB rather than timestamps alone.
5. **No Proof of Human-Made Artwork & No Delegated Artwork Signing in v1:** Paired devices in `v1` hold only `device-identity` permission and CANNOT sign artworks on behalf of the root author key without explicitly importing the artist's `.chkey.json` backup.

---

## 3. Reporting Security Issues

If you discover a security vulnerability in `@yomiplush/chm-exchange`, please avoid disclosing exploits publicly until a fix is prepared, and open a private security advisory or report directly to the repository maintainer (`yomiplush/CHM-Exchange`).
