# CHM-Exchange (`@yomiplush/chm-exchange`)

**Independent, Zero-Backend, Offline-First Ed25519 Public-Key Exchange Module for Certified Handmade**

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](./LICENSE)

CHM-Exchange is the authoritative, open-source implementation of the Certified Handmade (`CHM`) public-key exchange protocol, QR toolkit, host-adapter boundary, and React exchange interface. It enables artists and collectors to share Ed25519 public keys via portable `#key=` URLs, QR codes (SVG/PNG + local scan/upload), and JSON bundles cleanly **without servers, accounts, telemetry, or central authorities**.

> **Cryptographic Boundary Notice:** A valid Ed25519 key or signature proves control of the matching private key — **never** real-world identity or human-made artwork authorship. Imported public keys always start **Unverified** until their SHA-256 fingerprint is confirmed out-of-band and explicitly trusted locally.

---

## Features

- **Versioned Exchange Protocol (`v1`)**: Canonical JSON payload encoded in unpadded Base64url inside URL fragments (`https://certified-handmade.com/exchange#key=<token>`).
- **Zero Private-Key Exposure**: Rejects private-key fields (`privateKey`, `seed`, `webCryptoPrivateKey`, `encryptedBackup`, `jwk`, etc.) recursively at every boundary.
- **Host Compatibility**: Imports both `chm-exchange-public-key` (`v1`) bundles and Certified Handmade's existing `certified-handmade-public-key` (`v1`) JSON exports.
- **Local Fingerprint Recalculation**: Always recomputes `SHA-256(publicKey32)` locally (`fullHex` + `CHM-XXXX-XXXX-XXXX-XXXX`), rejecting tampered declared fingerprints.
- **QR Code Toolkit**:
  - Generates crisp vector SVG previews with an enforced 4-module white quiet zone.
  - Exports high-contrast PNG QR codes via `fast-png` + `qrcode`.
  - Decodes uploaded PNG/JPEG/WebP QR images (with IHDR anti-decompression-bomb preflight) and optional local camera scan via `BarcodeDetector` + `jsQR`.
- **Framework-Compatible Host Adapter**: `ChmExchangeHostAdapter` cleanly decouples public-key exchange UI from host IndexedDB / Web Crypto private-key storage.
- **Accessible, Themeable React UI**: `<ChmExchangeView />` with scoped `.chmx-*` CSS variables, dark-navy/cyan glass styling, EN/JA built-in dictionaries, keyboard navigation, and `prefers-reduced-motion` support.

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

### 1. Core Protocol API (`@yomiplush/chm-exchange/core`)

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

### 2. React UI + Host Adapter (`@yomiplush/chm-exchange/react`)

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
│   ├── core/          # Protocol encoding, fingerprint, validation, QR, memory adapter
│   ├── i18n/          # English & Japanese UI dictionaries
│   ├── react/         # Scoped CSS, icons, QR SVG/camera components, ChmExchangeView
│   ├── core.ts        # Framework-agnostic entry point
│   ├── react.ts       # React UI entry point
│   └── index.ts       # Combined barrel export
├── tests/             # Unit, security, QR round-trip, adapter, and React UI tests
├── examples/          # Standalone CLI + React examples
├── SPEC.md            # Normative CHM-Exchange v1 wire & validation specification
├── SECURITY.md        # Threat model, trust boundaries & known limitations
├── INTEGRATION.md     # Host integration guide (Certified Handmade & third-party apps)
└── CONTRIBUTING.md    # Development workflow & testing
```

CHM-Exchange is intentionally maintained separately from `yomiplush/hand-drawing-art-DRM-Toolkit`, which serves as the host application for artwork signing, private-key custody, IndexedDB persistence, PWA offline caching, and Cloudflare Pages deployment.

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
