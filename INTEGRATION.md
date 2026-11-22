# Integration Guide — `@yomiplush/chm-exchange`

CHM-Exchange is built as a standalone npm library with a strict separation between **protocol/UI (`CHM-Exchange`)** and **key custody/persistence (Host App)**.

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

### Supported Props
- `adapter`: Required `ChmExchangeHostAdapter`.
- `exchangeBaseUrl`: Target route for generated QR codes and `#key=` URLs (defaults to `https://certified-handmade.com/exchange`).
- `locale`: `'en' | 'ja'` (defaults to `'en'`).
- `messages`: Deep-partial `ChmExchangeMessages` override to customize copy or bridge host localization keys.
- `theme`: Optional `ChmExchangeTheme` mapping directly to scoped `--chmx-*` CSS variables.
- `initialTab`: `'share' | 'receive' | 'trusted'`.
- `initialIdentityId`: Pre-select an author identity in Share view (e.g., from `/keys?identity=...`).
- `initialInspectInput`: Pre-fill & auto-inspect a `#key=` URL, JSON, or raw Base64url public key (e.g., from `/verify`).
- `emptyIdentitiesAction`: Optional React node (such as a link to `/keys`) rendered when the user has zero author identities.
- `onTrustChanged`: Optional callback invoked after adding or removing a trusted key.

---

## 4. Non-React Usage (CLI, Web Extensions, Other Frameworks)

Import `@yomiplush/chm-exchange/core` (zero React dependency) to encode/decode URLs, validate JSON bundles, verify SHA-256 fingerprints, render/decode QR PNGs, or run `createMemoryExchangeAdapter()`.
