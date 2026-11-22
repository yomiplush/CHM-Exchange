# Security Model & Threat Analysis — CHM-Exchange

## 1. Security Architecture Summary

CHM-Exchange is a **public-key-only, zero-backend, static client library**. It contains **zero** server endpoints, **zero** outbound network calls, and **zero** telemetry.

### Defense-in-Depth Input & Payload Controls

| Control | Implementation |
|---|---|
| Payload size bounds | Exchange URLs `<= 4096` chars; tokens `<= 2048` chars; decoded exchange JSON `<= 1024` bytes; `.json` file imports `<= 4096` bytes; `displayName <= 64` UTF-8 bytes; trust `note <= 200` UTF-8 bytes. |
| Strict Base64url | Only `[A-Za-z0-9_-]`, unpadded, canonical round-trip check (`base64UrlEncode(decoded) === input`) rejecting non-canonical trailing bits. |
| Strict UTF-8 | Uses `new TextDecoder('utf-8', { fatal: true })`; malformed UTF-8 byte sequences fail closed. |
| Ed25519 key validation | Requires exact 32-byte decoded key length and rejects all-zero 32-byte keys. |
| Fingerprint recalculation | Always recomputes `SHA-256(publicKey32)` locally and rejects bundles whose declared `fingerprint` differs (using constant-time ASCII comparison). |
| Schema & version strictness | Enforces exact `version === 1` (`UnsupportedExchangeVersionError` otherwise) and whitelist-only JSON object fields. |
| Prototype-pollution defense | Recursively rejects `__proto__`, `constructor`, and `prototype` keys before accepting parsed objects. |
| Private-key isolation | Recursively blocks `privateKey`, `secretKey`, `seed`, `pkcs8`, `jwk`, `webCryptoPrivateKey`, `encryptedBackup`, `passphrase`, `ciphertext`, `salt`, `iv`, `d`, `private`, `secret`. Non-extractable `CryptoKey` handles are never accepted or returned. |
| XSS & spoofing prevention | UI renders all imported strings (`displayName`, notes) via escaped React text nodes — never `dangerouslySetInnerHTML`. Rejects ASCII control characters and Unicode bidirectional override/isolate controls (`U+202A–U+202E`, `U+2066–U+2069`). |
| Safe URL handling | Only `https:` and localhost `http:` are allowed for exchange base URLs; incoming URLs reject non-HTTP(S) schemes such as `javascript:` and `data:`. |
| QR image hardening | Pre-flights PNG `IHDR` headers before `fast-png` decompression, capping files at `25 MB`, `8192px` per side, and `32 MP` total pixels. |
| Duplicate & trust gating | Host adapters normalize keys to canonical Base64url to prevent duplicate trusted records. Imported keys always begin **Unverified** and require an explicit checkbox + confirmation submit before local trust is persisted. |
| Host CSP compatibility | Contains zero inline scripts, zero `eval`, zero external CDN fetches, and uses React SVG + Blob URLs / data-free rendering compatible with strict `default-src 'self'` CSPs. |

---

## 2. What CHM-Exchange Guarantees vs. What It Cannot Prove

### Guarantees
- Integrity of the imported 32-byte Ed25519 public key relative to its locally computed SHA-256 fingerprint.
- Local isolation between private signing keys (`AuthorKeyRecord`) and public exchange payloads.
- Explicit user consent before any key enters the host's Trusted Artists store.

### Explicit Limitations (No Central Authority)
1. **Impersonation / Name Spoofing:** Anyone can generate a new Ed25519 keypair with `displayName: "Famous Artist"`. A valid signature or bundle proves **only** possession of the private key matching that public key — **not** real-world legal identity. Always verify the short or full SHA-256 fingerprint out-of-band (official website, direct signed channel, or in-person QR scan).
2. **No Proof of Human-Made Artwork:** Cryptography binds bytes to a keypair; it cannot independently detect whether an image was hand-drawn or AI-generated.
3. **Key Loss:** Because there is no central server or custodial recovery, losing a private key (or encrypted backup + passphrase) permanently ends the artist's ability to sign with that fingerprint.
4. **Key Rotation:** If an artist switches to a new keypair, collectors must treat the new key as **Unverified** until its new fingerprint is independently verified again.
5. **No Global Revocation:** There is no global CRL/OCSP server. If a key is compromised or rotated, users remove local trust inside their own browser/device ("Remove Trust"); removing trust removes local "Trusted Artist" status without forging past signatures.

---

## 3. Reporting Security Issues

If you discover a security vulnerability in `@yomiplush/chm-exchange`, please avoid disclosing exploits publicly until a fix is prepared, and open a private security advisory or report directly to the repository maintainer (`yomiplush/CHM-Exchange`).
