# Integration Guide — `@yomiplush/chm-exchange`

CHM-Exchange is built as a standalone npm library with a strict separation between **protocol/QR primitives (`CHM-Exchange`)** and **key custody/persistence/workflows (Host App)**.

---

## 1. Installing in a Host Application

### Option A: Pinned Git Commit (Recommended for Static Deployments & Cloudflare Pages)

In the host application's `package.json`:

```json
{
  "dependencies": {
    "@yomiplush/chm-exchange": "github:yomiplush/CHM-Exchange#<full-commit-sha>"
  }
}
```

Ensure `react` and `react-dom` are deduplicated in Vite so React is never bundled twice:

```ts
// vite.config.ts
export default defineConfig({
  resolve: {
    dedupe: ['react', 'react-dom'],
  },
});
```

---

## 2. Implementing `ChmExchangeHostAdapter`

The host application owns private-key generation, signing, encrypted backups, and IndexedDB storage. Pass an adapter implementing [`ChmExchangeHostAdapter`](./src/core/types.ts) to `<ChmExchangeView />`:

```ts
import type { ChmExchangeHostAdapter, HostSigningIdentity } from '@yomiplush/chm-exchange/core';
import { stripToPublicHostIdentity } from '@yomiplush/chm-exchange/core';

export function createMyHostAdapter(): ChmExchangeHostAdapter {
  return {
    async listPublicIdentities(): Promise<HostSigningIdentity[]> {
      const records = await loadMyIndexedDbAuthorKeys();
      // Pick ONLY public metadata — NEVER pass webCryptoPrivateKey or encryptedBackup!
      return records.map((r) =>
        stripToPublicHostIdentity({
          id: r.id,
          displayName: r.label,
          publicKeyBase64Url: r.publicKeyBase64Url,
          fingerprintHex: r.fingerprintHex,
          fingerprintShort: r.fingerprintShort,
          createdAt: r.createdAt,
        }),
      );
    },
    async listTrustedKeys() { /* ... */ },
    async getTrustStatus(publicKeyBase64Url) { /* ... */ },
    async addTrustedKey(request) { /* ... */ },
    async removeTrustedKey(publicKeyBase64Url) { /* ... */ },
    // Optional CHM-DEVICE-PAIRING-v1 public projections:
    async getLocalDeviceIdentity() { /* return HostDeviceIdentity | null (public metadata only) */ },
    async listPairedDevices(ownerFingerprintHex) { /* return PairedDeviceRegistryEntry[] */ },
  };
}
```

> **Security Rule:** `stripToPublicHostIdentity()` validates the public key, recalculates fingerprints, and throws `ChmExchangeError` if any sensitive field leaks into the identity object.

---

## 3. Mounting `<ChmExchangeView />` on `/exchange`

```tsx
import { ChmExchangeView } from '@yomiplush/chm-exchange/react';
import '@yomiplush/chm-exchange/styles.css';

export function ExchangePage({ adapter, locale }: Props) {
  return (
    <ChmExchangeView
      adapter={adapter}
      exchangeBaseUrl={`${window.location.origin}/exchange`}
      locale={locale === 'ja' ? 'ja' : 'en'}
      theme={{
        panelBg: 'rgba(15, 23, 42, 0.72)',
        accent: '#06b6d4',
        sky: '#38bdf8',
      }}
    />
  );
}
```

---

## 4. Integrating `CHM-DEVICE-PAIRING-v1` on `/devices`

`@yomiplush/chm-exchange/core` and `@yomiplush/chm-exchange/react` expose all protocol & QR building blocks while keeping key custody on the host:

1. **Host Device Custody:** Generate a per-device Ed25519 keypair in Web Crypto (`extractable: false`) or AES-GCM encrypted seed fallback, completely separate from Owner Root `authorKeys`.
2. **Host Replay & Session Store:** Persist pending pairing requests (`pairingSessions`), consumed `requestId` + `nonce` values (`usedPairingNonces`), paired device registry entries (`pairedDevices`), and monotonic local revocations (`deviceRevocations`) in IndexedDB.
3. **2-Step Pairing UI:** Reuse `<QrCodeDisplay />`, `<QrCameraScanner />`, `renderExchangeQrPng()`, and `decodeQrFromImageBytes()` from `@yomiplush/chm-exchange`, always requiring explicit user confirmation before approving a device or trusting an unverified Owner fingerprint.
4. **Signed Snapshots:** Use `createSignedDeviceRegistrySnapshot()`, `serializeDeviceRegistryJson()`, `decodeAndVerifyDeviceRegistryInput()`, and `reconcileRegistrySnapshotImport()` for portable `.chdevreg.json` / `.chdevreg.cbor` backups that preserve known local revocations monotonically.

---

## 5. Non-React Usage (CLI, Web Extensions, Other Frameworks)

Import `@yomiplush/chm-exchange/core` (zero React dependency) to encode/decode URLs, validate JSON bundles, verify SHA-256 fingerprints, render/decode QR PNGs, run `createMemoryExchangeAdapter()`, or encode/verify `CHM-DEVICE-PAIRING-v1` CBOR artifacts.
