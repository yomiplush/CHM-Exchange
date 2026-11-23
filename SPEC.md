# CHM-Exchange & CHM-DEVICE-PAIRING-v1 Protocol Specification

**Status:** Draft Standard (`v1`)
**Module:** `@yomiplush/chm-exchange`
**License:** MIT

---

## 1. Purpose & Design Goals

CHM-Exchange defines an open, zero-backend, offline-first wire format for sharing **Ed25519 artist public keys** across web apps, local tools, QR codes, links, and JSON files without relying on a server, registry, or PKI certificate authority.

Alongside public-key exchange, this package specifies **`CHM-DEVICE-PAIRING-v1`**, an offline, serverless **2-step QR device enrollment, revocation, and signed registry snapshot protocol** built on deterministic RFC 8949 CBOR and domain-separated Ed25519 signatures.

Compatible third-party implementations **do not** require Certified Handmade infrastructure to create, parse, or verify CHM-Exchange or CHM-DEVICE-PAIRING-v1 artifacts.

---

## 2. Cryptographic Primitives & Canonical Encodings

| Primitive / Encoding | Requirement |
|---|---|
| Signature key type | Ed25519 raw **32-byte** public key (RFC 8032). All-zero, small-order, and non-torsion-free curve points are rejected in strict verification (`zip215: false`). |
| Ed25519 signatures | Raw **64-byte** signatures verified with strict cofactor/canonical checks (`zip215: false`). |
| Binary-to-text | **Canonical unpadded Base64url** (RFC 4648 §5 without `=`). Decoders MUST verify round-trip canonical encoding to reject non-zero trailing bits. 32-byte keys encode to exactly **43 characters**. |
| Fingerprint hash | `SHA-256(publicKey32)` expressed as 64 lowercase hexadecimal ASCII characters (`fullHex`). |
| Short fingerprint | `CHM-` followed by the first **8 bytes** (16 uppercase hex chars) grouped by 4 with hyphens: `CHM-XXXX-XXXX-XXXX-XXXX`. |
| Text encoding | Strict **UTF-8** (`fatal: true`). ASCII control chars (`0x00–0x1F`, `0x7F`) and Unicode bidirectional override/isolate controls (`U+202A–U+202E`, `U+2066–U+2069`) are forbidden in metadata strings. |
| Deterministic CBOR (`CHM-DEVICE-PAIRING-v1`) | Strict **RFC 8949 Core Deterministic Encoding**: indefinite-length items, `undefined`, `NaN`/`Infinity`, duplicate map keys, non-canonical integers/lengths, and invalid UTF-8 MUST be rejected. Decoders MUST re-encode with `rfc8949EncodeOptions` and assert byte-for-byte equality. |

---

## 3. Canonical JSON Bundle Formats (`CHM-Exchange` Public-Key Sharing)

Implementations MUST support importing both schemas below and exporting `chm-exchange-public-key` (`v1`) or host-compatible `certified-handmade-public-key` (`v1`).

### 3.1 CHM-Exchange Bundle (`chm-exchange-public-key`)

```json
{
  "format": "chm-exchange-public-key",
  "version": 1,
  "algorithm": "Ed25519",
  "publicKey": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
  "fingerprint": "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9",
  "displayName": "YomiPlush",
  "exportedAt": "2026-11-23T00:00:00.000Z"
}
```

| Field | Required | Type & Constraints |
|---|---|---|
| `format` | Yes | Exact string `"chm-exchange-public-key"` |
| `version` | Yes | Integer `1` (other numbers or non-integers MUST throw `UnsupportedExchangeVersionError`) |
| `algorithm` | Yes | Exact string `"Ed25519"` |
| `publicKey` | Yes | Canonical unpadded Base64url string decoding to 32 non-zero bytes |
| `fingerprint` | Yes | 64-char hex SHA-256 digest matching locally recomputed `SHA-256(publicKey32)` |
| `displayName` | No | Self-declared UTF-8 string, trimmed, `<= 64` UTF-8 bytes |
| `exportedAt` | No | Valid ISO-8601 timestamp string (`<= 40` chars) |

Unknown keys MUST be rejected. Total UTF-8 JSON bundle size encoded into URL tokens MUST NOT exceed **1024 bytes**. Standalone `.json` file imports MUST NOT exceed **4096 bytes**.

### 3.2 Certified Handmade Host Export Compatibility (`certified-handmade-public-key`)

```json
{
  "format": "certified-handmade-public-key",
  "version": 1,
  "algorithm": "Ed25519",
  "publicKey": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
  "fingerprint": "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9",
  "label": "YomiPlush",
  "exportedAt": "2026-11-23T00:00:00.000Z"
}
```

On import, `label` maps onto `displayName`. Both formats normalize internally to `ChmPublicKeyBundle`.

---

## 4. Portable Exchange URL Format (`#key=`)

Recommended production URL:

```text
https://certified-handmade.com/exchange#key=<encoded-public-key-bundle>
```

- `<encoded-public-key-bundle>` is the **canonical unpadded Base64url encoding** of the UTF-8 serialized `chm-exchange-public-key` JSON string.
- Data is carried exclusively in the **URL fragment (`#key=...`)** so it is never transmitted in HTTP `GET` paths or server access logs.
- Custom host paths MUST use `https://`, localhost `http://` (`localhost`, `127.0.0.1`, `[::1]`), or an origin-relative path (`/exchange`). Unsafe URI schemes (`javascript:`, `data:`, `file:`, `//`) MUST be rejected.
- Maximum URL length: **4096 characters**. Maximum `key` token length: **2048 characters**.

Implementations accepting generic paste input MAY also decode:
1. Fragment-only `#key=<token>` or `key=<token>`.
2. Bare `<token>`.
3. Raw 43-character Base64url Ed25519 public key (interpreted with `sourceVersion: null` and empty `displayName`).

---

## 5. QR Code Encoding

- Encodes Portable URLs as UTF-8 / Byte mode QR with Error Correction Level `M` (configurable `L`/`M`/`Q`/`H`).
- Quiet zone MUST be at least **4 modules** of solid white around all edges.
- PNG raster outputs use `RGBA` 8-bit lossless PNG with high-contrast dark ink on pure white (`#ffffff`) so camera scanners can decode cleanly across dark/light host UI themes.

---

## 6. Local Verification & Fingerprint Rules

1. **Never trust declared fingerprints**: Recompute `SHA-256(publicKey32)` locally in constant time and reject if it differs from the declared `fingerprint` field.
2. **Never auto-trust**: Parsing a valid bundle or pairing certificate only establishes cryptographic integrity. Unknown Owner or Artist public keys ALWAYS begin **Unverified** until their SHA-256 fingerprint is explicitly confirmed out-of-band.
3. **Never serialize private keys**: Decoders, encoders, and host adapters MUST reject payloads containing private-key properties (`privateKey`, `secretKey`, `seed`, `pkcs8`, `jwk`, `webCryptoPrivateKey`, `encryptedBackup`, `d`, etc.) recursively.

---

## 7. Device Pairing Protocol (`CHM-DEVICE-PAIRING-v1`)

`CHM-DEVICE-PAIRING-v1` links an independent local Ed25519 **Device Identity** keypair on a secondary device (phone, tablet, PC) to a root **CHM Identity** (Owner Ed25519 keypair) via a **2-step QR handshake** without copying root private keys or calling any server.

### 7.1 Common Outer Envelope (Canonical CBOR 5-Element Array)

```text
[version: 1, protocol: "CHM-DEVICE-PAIRING-v1", kind: uint, payloadBytes: bstr, signature: bstr(64)]
```

| `kind` | Meaning | Signer | Domain Prefix (null-terminated ASCII) |
|---|---|---|---|
| `1` | Pairing Request | Enrolling Device Key | `CHM-DEVICE-PAIRING-v1:REQ\0` |
| `2` | Enrollment Certificate | Owner Root Key | `CHM-DEVICE-PAIRING-v1:CERT\0` |
| `3` | Device Revocation Notice | Owner Root Key | `CHM-DEVICE-PAIRING-v1:REVOKE\0` |
| `4` | Signed Device Registry Snapshot | Owner Root Key | `CHM-DEVICE-PAIRING-v1:REGISTRY\0` |

Signed bytes are always `domainPrefix || payloadBytes`. Envelopes exceeding `2048` bytes (or `262144` bytes for snapshots) MUST be rejected. Unknown `version` throws `UnsupportedPairingVersionError`.

### 7.2 Pairing Request Payload (`kind = 1`, CBOR Map Keys `1..12`)

| Key | Name | Type | Notes |
|---|---|---|---|
| `1` | `requestId` | `bstr(16)` | CSPRNG UUIDv4 |
| `2` | `deviceId` | `bstr(16)` | CSPRNG UUIDv4 identifying the device |
| `3` | `devicePublicKey` | `bstr(32)` | Strict Ed25519 public key (distinct from owner key) |
| `4` | `deviceDisplayName` | `tstr` | Trimmed, `1..64` UTF-8 bytes, no control/bidi chars |
| `5` | `ownerTargetKind` | `uint` | `1 = pinned-public-key`, `2 = pinned-fingerprint`, `3 = open-owner-binding` |
| `6` | `ownerPublicKey` | `bstr(32)` | Present only when `ownerTargetKind === 1` |
| `7` | `ownerFingerprint` | `bstr(32)` | Present only when `ownerTargetKind === 1` (`SHA-256(ownerPublicKey)`) or `2` |
| `8` | `nonce` | `bstr(32)` | 256-bit CSPRNG random nonce |
| `9` | `issuedAt` | `uint` | Unix seconds |
| `10` | `expiresAt` | `uint` | Unix seconds (`issuedAt + 1 .. issuedAt + 3600`, default TTL `300s`) |
| `11` | `permissions` | `tstr[]` | In `v1`, MUST be `["device-identity"]` only; privileged permissions are rejected |
| `12` | `ownerLabelHint` | `tstr` | Optional display hint |

### 7.3 Enrollment Certificate Payload (`kind = 2`, CBOR Map Keys `1..12`)

Cryptographically bound to the originating request via `requestHash = SHA-256(canonicalRequestEnvelopeBytes)`:

| Key | Name | Type | Notes |
|---|---|---|---|
| `1` | `certId` | `bstr(16)` | CSPRNG UUIDv4 |
| `2` | `requestId` | `bstr(16)` | Must match request `requestId` |
| `3` | `requestHash` | `bstr(32)` | `SHA-256(requestEnvelopeBytes)` |
| `4` | `nonce` | `bstr(32)` | Must match request `nonce` |
| `5` | `ownerPublicKey` | `bstr(32)` | Strict Ed25519 root key (`!== devicePublicKey`) |
| `6` | `ownerDisplayName` | `tstr` | Trimmed, `1..64` UTF-8 bytes |
| `7` | `deviceId` | `bstr(16)` | Must match request `deviceId` |
| `8` | `devicePublicKey` | `bstr(32)` | Must match request `devicePublicKey` |
| `9` | `deviceDisplayName` | `tstr` | Trimmed, `1..64` UTF-8 bytes |
| `10` | `permissions` | `tstr[]` | Non-escalating subset of request permissions (`["device-identity"]`) |
| `11` | `issuedAt` | `uint` | Unix seconds |
| `12` | `requestExpiresAt` | `uint` | Must match request `expiresAt` |

### 7.4 Device Revocation Notice Payload (`kind = 3`, CBOR Map Keys `1..8`)

| Key | Name | Type | Notes |
|---|---|---|---|
| `1` | `noticeId` | `bstr(16)` | CSPRNG UUIDv4 |
| `2` | `ownerPublicKey` | `bstr(32)` | Strict Ed25519 owner root key |
| `3` | `deviceId` | `bstr(16)` | Target device UUID |
| `4` | `devicePublicKey` | `bstr(32)` | Target device public key |
| `5` | `revokedAt` | `uint` | Unix seconds |
| `6` | `sequence` | `uint` | Monotonic positive integer (`>= 1`) |
| `7` | `reason` | `uint` | `1 = lost-device`, `2 = device-compromised`, `3 = retired`, `4 = other` |
| `8` | `note` | `tstr` | Optional `<= 160` UTF-8 bytes |

Revocations are **locally monotonic**: re-importing an older signed registry snapshot MUST NOT un-revoke a device already marked `revoked` or `conflict-revoked` in local storage.

### 7.5 Signed Registry Snapshot (`kind = 4`, `.chdevreg.json` / `.chdevreg.cbor`)

Encodes an Owner-signed list of embedded canonical `SignedEnrollmentCertificate` envelopes and `SignedDeviceRevocationNotice` envelopes (`certificates`, `revocations`, monotonic `sequence`). Inner certificates and revocations are individually re-verified, owner-consistency checked, and reconciled monotonically on import.

### 7.6 Pairing QR URLs & Tokens

- Pairing Request URL / Token: `https://certified-handmade.com/devices#pair-req=<b64u>` or `chm-pair-req:<b64u>`
- Enrollment Certificate URL / Token: `https://certified-handmade.com/devices#pair-cert=<b64u>` or `chm-pair-cert:<b64u>`
- Device Revocation URL / Token: `https://certified-handmade.com/devices#pair-rev=<b64u>` or `chm-pair-rev:<b64u>`
- Registry Snapshot Token / JSON: `chm-pair-reg:<b64u>` or `{ "format": "chm-device-registry", "version": 1, "protocol": "CHM-DEVICE-PAIRING-v1", ... }`

---

## 8. Normative Test Vector (RFC 8032 Key 1)

- **Public Key (hex):** `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`
- **Public Key (Base64url):** `11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo`
- **SHA-256 Fingerprint (`fullHex`):** `21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9`
- **Short Fingerprint (`shortDisplay`):** `CHM-21FE-31DF-A154-A261`
