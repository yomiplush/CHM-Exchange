import {
  base64UrlEncode,
  computePublicKeyFingerprintSync,
  createMemoryExchangeAdapter,
  createPublicKeyBundle,
  decodeExchangeUrl,
  decodeQrFromImageBytes,
  encodeExchangeUrl,
  hexToBytes,
  renderExchangeQrPng,
} from '../../dist/core.js';

// Example public key only (RFC 8032 test vector 1 — NEVER pass private keys into CHM-Exchange)
const demoPublicKeyBytes = hexToBytes(
  'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
);
const demoPublicKeyB64u = base64UrlEncode(demoPublicKeyBytes);
const fp = computePublicKeyFingerprintSync(demoPublicKeyBytes);

async function main() {
  console.log('=== CHM-Exchange Standalone Demo ===');

  const bundle = createPublicKeyBundle({
    publicKey: demoPublicKeyBytes,
    displayName: 'YomiPlush Demo Studio',
    includeTimestamp: true,
  });

  const shareUrl = encodeExchangeUrl(bundle, 'https://certified-handmade.com/exchange');
  console.log('1. Generated exchange URL:', shareUrl);
  console.log('   Short fingerprint:', fp.shortDisplay);

  const qr = renderExchangeQrPng(shareUrl, { moduleScale: 6, quietZoneModules: 4 });
  console.log(`2. Rendered QR PNG (${qr.width}x${qr.height}px, ${qr.pngBytes.byteLength} bytes)`);

  const scannedUrl = await decodeQrFromImageBytes(qr.pngBytes);
  const inspected = decodeExchangeUrl(scannedUrl);
  console.log('3. Decoded from QR PNG & verified locally:');
  console.log('   Declared displayName:', inspected.displayName);
  console.log('   Recomputed short fingerprint:', inspected.fingerprintShort);

  const adapter = createMemoryExchangeAdapter({
    identities: [
      {
        id: 'demo-1',
        displayName: 'Self Identity',
        publicKeyBase64Url: demoPublicKeyB64u,
        fingerprintHex: fp.fullHex,
        fingerprintShort: fp.shortDisplay,
      },
    ],
  });

  const initialTrust = await adapter.getTrustStatus(inspected.publicKeyBase64Url);
  console.log('4. Initial trust status (must always be false):', initialTrust.trusted);

  await adapter.addTrustedKey({
    publicKeyBase64Url: inspected.publicKeyBase64Url,
    fingerprintHex: inspected.fingerprintHex,
    displayName: inspected.displayName ?? 'Demo Artist',
    note: 'Fingerprint verified out-of-band during standalone demo',
  });

  const confirmedTrust = await adapter.getTrustStatus(inspected.publicKeyBase64Url);
  console.log('5. After explicit confirmation, trusted:', confirmedTrust.trusted);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
