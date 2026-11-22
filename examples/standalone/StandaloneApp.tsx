import { useMemo, useState } from 'react';
import {
  base64UrlEncode,
  computePublicKeyFingerprintSync,
  createMemoryExchangeAdapter,
  hexToBytes,
} from '../../src/core.js';
import { ChmExchangeView } from '../../src/react.js';
import type { ChmExchangeLocale } from '../../src/react.js';
import '../../src/react/styles.css';

const DEMO_PUBLIC_KEY = hexToBytes(
  'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
);

export function StandaloneApp() {
  const [locale, setLocale] = useState<ChmExchangeLocale>('en');

  const adapter = useMemo(() => {
    const fp = computePublicKeyFingerprintSync(DEMO_PUBLIC_KEY);
    return createMemoryExchangeAdapter({
      identities: [
        {
          id: 'standalone-demo-key',
          displayName: 'Standalone Demo Artist',
          publicKeyBase64Url: base64UrlEncode(DEMO_PUBLIC_KEY),
          fingerprintHex: fp.fullHex,
          fingerprintShort: fp.shortDisplay,
          createdAt: '2026-11-23T00:00:00.000Z',
        },
      ],
    });
  }, []);

  return (
    <main style={{ minHeight: '100vh', background: '#030712', padding: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '1rem' }}>
        <button
          type="button"
          onClick={() => setLocale((prev) => (prev === 'en' ? 'ja' : 'en'))}
          style={{
            background: '#0f172a',
            color: '#e2e8f0',
            border: '1px solid #1e293b',
            borderRadius: '0.5rem',
            padding: '0.45rem 0.9rem',
            cursor: 'pointer',
          }}
        >
          Locale: {locale.toUpperCase()}
        </button>
      </div>
      <ChmExchangeView
        adapter={adapter}
        locale={locale}
        exchangeBaseUrl="https://certified-handmade.com/exchange"
      />
    </main>
  );
}
