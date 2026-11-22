import { describe, expect, it } from 'vitest';
import {
  ChmExchangeError,
  base64UrlEncode,
  computePublicKeyFingerprintSync,
  createMemoryExchangeAdapter,
  hexToBytes,
  stripToPublicHostIdentity,
} from '../../src/core.js';
import type { HostSigningIdentity } from '../../src/core.js';

const PUB_A = hexToBytes('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
const PUB_A_B64 = base64UrlEncode(PUB_A);
const FP_A = computePublicKeyFingerprintSync(PUB_A);

describe('CHM-Exchange Host Adapter & Private-Key Boundary', () => {
  it('strips/rejects sensitive fields and recalculates canonical fingerprints', () => {
    const leakyRecord = {
      id: 'id-1',
      displayName: 'YomiPlush',
      publicKeyBase64Url: PUB_A_B64,
      fingerprintHex: FP_A.fullHex,
      fingerprintShort: FP_A.shortDisplay,
      webCryptoPrivateKey: { type: 'private' },
    } as unknown as HostSigningIdentity;

    expect(() => stripToPublicHostIdentity(leakyRecord)).toThrow(ChmExchangeError);

    const cleanIdentity = stripToPublicHostIdentity({
      id: 'id-1',
      displayName: '  YomiPlush  ',
      publicKeyBase64Url: PUB_A_B64,
      fingerprintHex: '',
      fingerprintShort: '',
      createdAt: '2026-11-23T00:00:00.000Z',
    });

    expect(cleanIdentity).toEqual({
      id: 'id-1',
      displayName: 'YomiPlush',
      publicKeyBase64Url: PUB_A_B64,
      fingerprintHex: FP_A.fullHex,
      fingerprintShort: FP_A.shortDisplay,
      createdAt: '2026-11-23T00:00:00.000Z',
    });
  });

  it('supports listing, reading, adding, checking, and removing trusted keys', async () => {
    const adapter = createMemoryExchangeAdapter({
      identities: [
        {
          id: 'id-1',
          displayName: 'Main Author',
          publicKeyBase64Url: PUB_A_B64,
          fingerprintHex: FP_A.fullHex,
          fingerprintShort: FP_A.shortDisplay,
        },
      ],
    });

    const identities = await adapter.listPublicIdentities();
    expect(identities).toHaveLength(1);
    expect(await adapter.getPublicIdentity?.('id-1')).toEqual(identities[0]);
    expect(await adapter.getPublicIdentity?.('missing')).toBeNull();

    expect((await adapter.getTrustStatus(PUB_A_B64)).trusted).toBe(false);

    const added = await adapter.addTrustedKey({
      publicKeyBase64Url: PUB_A_B64,
      fingerprintHex: FP_A.fullHex,
      displayName: 'Verified Author',
      note: 'Checked fingerprint in person',
    });

    expect(added.fingerprintShort).toBe(FP_A.shortDisplay);
    expect((await adapter.getTrustStatus(PUB_A_B64)).trusted).toBe(true);
    expect(await adapter.listTrustedKeys()).toHaveLength(1);

    await adapter.removeTrustedKey(PUB_A_B64);
    expect((await adapter.getTrustStatus(PUB_A_B64)).trusted).toBe(false);
    expect(await adapter.listTrustedKeys()).toHaveLength(0);
  });
});
