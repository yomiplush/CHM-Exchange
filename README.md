# CHM-Exchange (`@yomiplush/chm-exchange`)

**Independent, Zero-Backend, Offline-First Ed25519 Public-Key Exchange & Device Pairing Module for Certified Handmade**

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](./LICENSE)

CHM-Exchange is the authoritative, open-source implementation of the Certified Handmade (`CHM`) public-key exchange protocol (`#key=`), **`CHM-DEVICE-PAIRING-v1`** (offline 2-step QR multi-device enrollment, revocation, and signed registry snapshots), QR toolkit, host-adapter boundary, and React exchange interface — **without servers, accounts, telemetry, or central authorities**.

> **Cryptographic Boundary Notice:** A valid Ed25519 key or signature proves control of the matching private key — **never** real-world identity or human-made artwork authorship. Imported public keys and enrolling Owner keys always start **Unverified** until their SHA-256 fingerprint is confirmed out-of-band.

---

## Features

- **Versioned Exchange Protocol (`v1`)**: Canonical JSON payload encoded in unpadded Base64url inside URL fragments (`https://certified-handmade.com/exchange#key=<token>`).
- **Secure Device Pairing (`CHM-DEVICE-PAIRING-v1`)**:
  - Deterministic RFC 8949 CBOR envelopes (`request`, `enrollment certificate`, `revocation notice`, `signed registry snapshot`) checked byte-for-byte on decode.
  - Domain-separated strict Ed25519 signatures (`zip215: false`, curve-point small-order & torsion checks).
  - Cryptographic request-to-certificate binding (`requestHash = SHA-256(envelope)` + 256-bit `nonce` + `requestId`) preventing cross-owner substitution, replay, and privilege escalation.
  - Monotonic local revocation reconciliation preventing stale registry snapshot re-imports from un-revoking compromised/lost devices.
- **Zero Private-Key Exposure**: Rejects private-key fields (`privateKey`, `seed`, `webCryptoPrivateKey`, `encryptedBackup`, `jwk`, etc.) recursively at every boundary.
- **Host Compatibility**: Imports both `chm-exchange-public-key` (`v1`) bundles and Certified Handmade's `certified-handmade-public-key` (`v1`) JSON exports.
- **Local Fingerprint Recalculation**: Always recomputes `SHA-256(publicKey32)` locally (`fullHex` + `CHM-XXXX-XXXX-XXXX-XXXX`), rejecting tampered declared fingerprints.
- **QR Code Toolkit**:
  - Generates crisp vector SVG previews with an enforced 4-module white quiet zone.
  - Exports high-contrast PNG QR codes via `fast-png` + `qrcode`.
  - Decodes uploaded PNG/JPEG/WebP QR images (with IHDR anti-decompression-bomb preflight) and optional local camera scan via `BarcodeDetector` + `jsQR`.
- **Framework-Compatible Host Adapter**: `ChmExchangeHostAdapter` decouples public-key exchange UI and device identity metadata from host IndexedDB / Web Crypto private-key storage.
- **Accessible, Themeable React UI**: `<ChmExchangeView />`, `<QrCodeDisplay />`, and `<QrCameraScanner />` with scoped `.chmx-*` CSS variables, dark-navy/cyan glass styling, EN/JA built-in dictionaries, keyboard navigation, and `prefers-reduced-motion` support.

---

## Installation

### Git-Pinned Package (Recommended for Certified Handmade)

```bash
npm install github:yomiplush/CHM-Exchange#<commit-sha>
```

### Local Development Link / Tarball

```bash
npm --prefix /path/to/CHM-Exchange run build
npm install /path/to/CHM-Exchange
```

---

## Quick Start

### 1. Core Public-Key Exchange API (`@yomiplush/chm-exchange/core`)

```ts
import {
  createPublicKeyBundle,
  encodeExchangeUrl,
  parsePublicKeyExchangeInput,
  renderExchangeQrPng,
} from '@yomiplush/chm-exchange/core';

const bundle = createPublicKeyBundle({
  publicKey: ed25519PublicKeyBase64UrlOrBytes,
  displayName: 'YomiPlush',
  includeTimestamp: true,
});

const shareUrl = encodeExchangeUrl(bundle, 'https://certified-handmade.com/exchange');
const { pngBytes } = renderExchangeQrPng(shareUrl);

// Recipient inspects any pasted URL, token, raw 43-char key, or JSON:
const inspected = parsePublicKeyExchangeInput(shareUrl);
console.log(inspected.fingerprintShort); // CHM-XXXX-XXXX-XXXX-XXXX
```

### 2. Device Pairing Protocol (`CHM-DEVICE-PAIRING-v1`)

```ts
import {
  createSignedPairingRequest,
  createSignedEnrollmentCertificate,
  verifyEnrollmentCertificateBinding,
  encodePairingRequestUrl,
  encodeEnrollmentCertificateUrl,
  parsePairingQrInput,
} from '@yomiplush/chm-exchange/core';

// Step 1 (New Device): generate local device keypair on host, create signed request QR
const req = await createSignedPairingRequest({
  devicePublicKey,
  deviceDisplayName: 'iPhone',
  signWithDeviceKey, // signs with local device private key (non-extractable CryptoKey or seed)
});
const reqUrl = encodePairingRequestUrl(req, 'https://certified-handmade.com/devices');

// Step 2 (Owner Root Device): parse QR, obtain explicit user consent, issue Enrollment Certificate
const parsed = parsePairingQrInput(reqUrl);
if (parsed.kind === 'pairing-request') {
  const cert = await createSignedEnrollmentCertificate({
    request: parsed.request,
    ownerPublicKey,
    ownerDisplayName: 'YomiPlush',
    signWithOwnerKey, // signs with owner root key
  });
  const certUrl = encodeEnrollmentCertificateUrl(cert);
  // New device scans certUrl and verifies binding + replay guard + owner trust!
}
```

### 3. React UI + Host Adapter (`@yomiplush/chm-exchange/react`)

```tsx
import { ChmExchangeView } from '@yomiplush/chm-exchange/react';
import { createMemoryExchangeAdapter } from '@yomiplush/chm-exchange/core';
import '@yomiplush/chm-exchange/styles.css';

const adapter = createMemoryExchangeAdapter();

export function ExchangeScreen() {
  return (
    <ChmExchangeView
      adapter={adapter}
      exchangeBaseUrl="https://certified-handmade.com/exchange"
      locale="en"
    />
  );
}
```

---

## Repository Structure

```text
CHM-Exchange/
├── src/
│   ├── core/
│   │   ├── pairing/   # CHM-DEVICE-PAIRING-v1 (CBOR, crypto, protocol, registry)
│   │   └── ...        # Key exchange encoding, fingerprint, validation, QR, memory adapter
│   ├── i18n/          # English & Japanese UI dictionaries
│   ├── react/         # Scoped CSS, icons, QR SVG/camera components, ChmExchangeView
│   ├── core.ts        # Framework-agnostic entry point
│   ├── react.ts       # React UI entry point
│   └── index.ts       # Combined barrel export
├── tests/             # Unit, security, pairing protocol, QR round-trip, adapter, UI tests
├── examples/          # Standalone CLI + React examples
├── SPEC.md            # Normative CHM-Exchange & CHM-DEVICE-PAIRING-v1 specification
├── SECURITY.md        # Threat model, trust boundaries & known limitations
├── INTEGRATION.md     # Host integration guide (Certified Handmade & third-party apps)
└── CONTRIBUTING.md    # Development workflow & testing
```

CHM-Exchange is intentionally maintained separately from `yomiplush/hand-drawing-art-DRM-Toolkit`, which serves as the host application for artwork signing, private-key custody, IndexedDB persistence, `/devices` pairing & revocation UI, PWA offline caching, and Cloudflare Pages deployment.

---

## Development & Verification

```bash
npm install
npm run typecheck
npm run lint
npm test
npm run build
npm run example
```

## License

[MIT](./LICENSE)
