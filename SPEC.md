# CHM-Exchange Protocol Specification (`v1`)

**Status:** Draft Standard (`version: 1`)
**Module:** `@yomiplush/chm-exchange`
**License:** MIT

---

## 1. Purpose & Design Goals

CHM-Exchange defines an open, zero-backend, offline-first wire format for sharing **Ed25519 artist public keys** across web apps, local tools, QR codes, links, and JSON files without relying on a server, registry, or PKI certificate authority.

Compatible third-party implementations **do not** require Certified Handmade infrastructure to create, parse, or verify CHM-Exchange bundles.

---

## 2. Cryptographic Primitives & Canonical Encodings

| Primitive / Encoding | Requirement |
|---|---|
| Signature key type | Ed25519 raw **32-byte** public key (RFC 8032). All-zero 32-byte keys are rejected. |
| Binary-to-text | **Canonical unpadded Base64url** (RFC 4648 §5 without `=`). Decoders MUST verify round-trip canonical encoding to reject non-zero trailing bits. 32-byte keys encode to exactly **43 characters**. |
| Fingerprint hash | `SHA-256(publicKey32)` expressed as 64 lowercase hexadecimal ASCII characters (`fullHex`). |
| Short fingerprint | `CHM-` followed by the first **8 bytes** (16 uppercase hex chars) grouped by 4 with hyphens: `CHM-XXXX-XXXX-XXXX-XXXX`. |
| Text encoding | Strict **UTF-8** (`fatal: true`). ASCII control chars (`0x00–0x1F`, `0x7F`) and Unicode bidirectional override/isolate controls (`U+202A–U+202E`, `U+2066–U+2069`) are forbidden in metadata strings. |

---

## 3. Canonical JSON Bundle Formats

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

## 4. Portable Exchange URL Format

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

- Encodes the **Portable Exchange URL** (`https://certified-handmade.com/exchange#key=...`) as UTF-8 / Byte mode QR with Error Correction Level `M` (configurable `L`/`M`/`Q`/`H`).
- Quiet zone MUST be at least **4 modules** of solid white around all edges.
- PNG raster outputs use `RGBA` 8-bit lossless PNG with high-contrast dark ink on pure white (`#ffffff`) so camera scanners can decode cleanly across dark/light host UI themes.

---

## 6. Local Verification & Fingerprint Rules

1. **Never trust declared fingerprints**: Recompute `SHA-256(publicKey32)` locally in constant time and reject if it differs from the declared `fingerprint` field.
2. **Never auto-trust**: Parsing a valid bundle only establishes cryptographic integrity of the public key bytes. Trust state starts as **Unverified** unless the exact 32-byte key already exists in the local trust store.
3. **Never serialize private keys**: Decoders and encoders MUST reject payloads containing private-key properties (`privateKey`, `secretKey`, `seed`, `pkcs8`, `jwk`, `webCryptoPrivateKey`, `encryptedBackup`, `d`, etc.) recursively.

---

## 7. Normative Test Vector (RFC 8032 Key 1)

- **Public Key (hex):** `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`
- **Public Key (Base64url):** `11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo`
- **SHA-256 Fingerprint (`fullHex`):** `21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9`
- **Short Fingerprint (`shortDisplay`):** `CHM-21FE-31DF-A154-A261`
