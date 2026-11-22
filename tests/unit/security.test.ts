import { describe, expect, it } from 'vitest';
import {
  CHM_EXCHANGE_ALGORITHM,
  CHM_EXCHANGE_FORMAT,
  CHM_EXCHANGE_PROTOCOL_VERSION,
  ChmExchangeError,
  MAX_DISPLAY_NAME_UTF8_BYTES,
  MAX_EXCHANGE_BUNDLE_BYTES,
  MAX_EXCHANGE_JSON_BYTES,
  MAX_EXCHANGE_TOKEN_CHARS,
  MAX_EXCHANGE_URL_CHARS,
  base64UrlDecode,
  base64UrlEncode,
  createMemoryExchangeAdapter,
  createPublicKeyBundle,
  decodeExchangeBundleToken,
  decodeExchangeUrl,
  encodeExchangeUrl,
  hexToBytes,
  parseExchangeBundleJson,
  parsePublicKeyExchangeInput,
  sanitizeDisplayName,
  sanitizeTrustNote,
  utf8Encode,
} from '../../src/core.js';

const PUB_A = hexToBytes('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
const PUB_B = hexToBytes('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c');

describe('CHM-Exchange Security & Input Validation', () => {
  it('rejects malformed JSON and non-object JSON roots', () => {
    expect(() => parseExchangeBundleJson('{not valid json')).toThrow(ChmExchangeError);
    expect(() => parseExchangeBundleJson('[]')).toThrow(ChmExchangeError);
    expect(() => parseExchangeBundleJson('"string"')).toThrow(ChmExchangeError);
    expect(() => parseExchangeBundleJson('null')).toThrow(ChmExchangeError);
    expect(() => parsePublicKeyExchangeInput('   ')).toThrow(ChmExchangeError);
  });

  it('enforces strict canonical Base64url and strict UTF-8 decoding', () => {
    expect(() => base64UrlDecode('abc=')).toThrow(ChmExchangeError);
    expect(() => base64UrlDecode('abc+def/')).toThrow(ChmExchangeError);
    expect(() => base64UrlDecode('aaaaa')).toThrow(ChmExchangeError);

    // Non-canonical trailing bits in raw 32-byte key (last char 'B' instead of 'A'-aligned LSBs)
    const canonicalKey = base64UrlEncode(PUB_A);
    const corruptedLastChar = `${canonicalKey.slice(0, -1)}${canonicalKey.endsWith('B') ? 'C' : 'B'}`;
    expect(() => base64UrlDecode(corruptedLastChar)).toThrow(/Non-canonical base64url/);

    // Invalid UTF-8 bytes inside base64url token
    const invalidUtf8 = new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]);
    const badUtf8Token = base64UrlEncode(invalidUtf8);
    expect(() => decodeExchangeBundleToken(badUtf8Token)).toThrow(ChmExchangeError);
  });

  it('rejects incorrect Ed25519 key lengths and all-zero keys', () => {
    const shortKey = base64UrlEncode(PUB_A.slice(0, 31));
    const longKey = base64UrlEncode(new Uint8Array(33).fill(1));
    const zeroKey = base64UrlEncode(new Uint8Array(32));

    expect(() => createPublicKeyBundle({ publicKey: shortKey })).toThrow(ChmExchangeError);
    expect(() => createPublicKeyBundle({ publicKey: longKey })).toThrow(ChmExchangeError);
    expect(() => createPublicKeyBundle({ publicKey: zeroKey })).toThrow(ChmExchangeError);
    expect(() => parsePublicKeyExchangeInput(shortKey)).toThrow(ChmExchangeError);
    expect(() => parsePublicKeyExchangeInput(zeroKey)).toThrow(ChmExchangeError);
  });

  it('never trusts declared fingerprints and rejects mismatched or malformed fingerprints', () => {
    const bundle = createPublicKeyBundle({ publicKey: PUB_A, displayName: 'Artist A' });
    const otherBundle = createPublicKeyBundle({ publicKey: PUB_B, displayName: 'Artist B' });

    const tamperedFingerprintJson = JSON.stringify({
      ...bundle,
      fingerprint: otherBundle.fingerprint,
    });
    expect(() => parseExchangeBundleJson(tamperedFingerprintJson)).toThrow(/Fingerprint/i);

    const shortFpJson = JSON.stringify({ ...bundle, fingerprint: 'abcd' });
    expect(() => parseExchangeBundleJson(shortFpJson)).toThrow(ChmExchangeError);

    // Even if tampered inside a #key= URL
    const tamperedToken = base64UrlEncode(utf8Encode(tamperedFingerprintJson));
    expect(() => decodeExchangeUrl(`https://certified-handmade.com/exchange#key=${tamperedToken}`)).toThrow(
      ChmExchangeError,
    );
  });

  it('rejects private-key material and prototype pollution fields recursively', () => {
    const bundle = createPublicKeyBundle({ publicKey: PUB_A });
    const forbiddenFields = [
      'privateKey',
      'secretKey',
      'seed',
      'webCryptoPrivateKey',
      'encryptedBackup',
      'jwk',
      'd',
    ];

    for (const field of forbiddenFields) {
      const payload = JSON.stringify({ ...bundle, [field]: 'secret-material' });
      expect(() => parseExchangeBundleJson(payload)).toThrow(/Forbidden private-key field|PRIVATE_KEY/);
    }

    const protoPayload = '{"format":"chm-exchange-public-key","version":1,"algorithm":"Ed25519","publicKey":"' +
      bundle.publicKey +
      '","fingerprint":"' +
      bundle.fingerprint +
      '","__proto__":{"polluted":true}}';
    expect(() => parseExchangeBundleJson(protoPayload)).toThrow(ChmExchangeError);

    expect(() =>
      createPublicKeyBundle({
        publicKey: PUB_A,
        // @ts-expect-error testing runtime rejection of extra private fields
        webCryptoPrivateKey: { type: 'private' },
      }),
    ).toThrow(ChmExchangeError);
  });

  it('enforces payload, displayName, and trust note size bounds', () => {
    const tooLongName = 'a'.repeat(MAX_DISPLAY_NAME_UTF8_BYTES + 1);
    expect(() => sanitizeDisplayName(tooLongName)).toThrow(ChmExchangeError);
    expect(() => createPublicKeyBundle({ publicKey: PUB_A, displayName: tooLongName })).toThrow(
      ChmExchangeError,
    );

    // Multi-byte UTF-8 boundary check (22 3-byte kanji = 66 bytes > 64 bytes)
    const tooLongUtf8Name = 'あ'.repeat(22);
    expect(() => sanitizeDisplayName(tooLongUtf8Name)).toThrow(ChmExchangeError);

    const longNote = 'x'.repeat(201);
    expect(() => sanitizeTrustNote(longNote)).toThrow(ChmExchangeError);

    const oversizedUrl = `https://certified-handmade.com/exchange#key=${'A'.repeat(MAX_EXCHANGE_URL_CHARS)}`;
    expect(() => decodeExchangeUrl(oversizedUrl)).toThrow(/exceeds maximum/);

    const oversizedToken = 'A'.repeat(MAX_EXCHANGE_TOKEN_CHARS + 1);
    expect(() => decodeExchangeBundleToken(oversizedToken)).toThrow(/exceeds maximum/);

    const oversizedJson = JSON.stringify({
      format: CHM_EXCHANGE_FORMAT,
      version: CHM_EXCHANGE_PROTOCOL_VERSION,
      algorithm: CHM_EXCHANGE_ALGORITHM,
      padding: 'x'.repeat(MAX_EXCHANGE_JSON_BYTES + 10),
    });
    expect(() => parseExchangeBundleJson(oversizedJson)).toThrow(/exceeds maximum/);

    const hugeBytes = new Uint8Array(MAX_EXCHANGE_BUNDLE_BYTES + 20).fill(0x20);
    expect(() => decodeExchangeBundleToken(base64UrlEncode(hugeBytes))).toThrow(/exceeds maximum/);
  });

  it('blocks control characters, Unicode bidi overrides, and unsafe URI schemes', () => {
    expect(() => sanitizeDisplayName('Artist\u202Eevil')).toThrow(ChmExchangeError);
    expect(() => sanitizeDisplayName('Artist\x00Null')).toThrow(ChmExchangeError);
    expect(() => sanitizeTrustNote('Note\u2066bidi')).toThrow(ChmExchangeError);

    const bundle = createPublicKeyBundle({ publicKey: PUB_A });
    const validUrl = encodeExchangeUrl(bundle);
    const token = validUrl.split('#key=')[1];

    expect(() => decodeExchangeUrl(`javascript:alert(1)#key=${token}`)).toThrow(ChmExchangeError);
    expect(() => decodeExchangeUrl(`data:text/html,<script>alert(1)</script>#key=${token}`)).toThrow(
      ChmExchangeError,
    );
    expect(() => decodeExchangeUrl(`file:///etc/passwd#key=${token}`)).toThrow(ChmExchangeError);
  });

  it('never automatically trusts imported keys and detects duplicates in adapter', async () => {
    const adapter = createMemoryExchangeAdapter();
    const bundle = createPublicKeyBundle({ publicKey: PUB_A, displayName: 'Unverified Sender' });
    const imported = decodeExchangeUrl(encodeExchangeUrl(bundle));

    // Parsing/decoding must never add to adapter trust store
    expect(await adapter.listTrustedKeys()).toHaveLength(0);
    expect((await adapter.getTrustStatus(imported.publicKeyBase64Url)).trusted).toBe(false);

    // Explicitly adding trust switches status to trusted and avoids duplicates
    await adapter.addTrustedKey({
      publicKeyBase64Url: imported.publicKeyBase64Url,
      fingerprintHex: imported.fingerprintHex,
      displayName: 'Verified Sender',
      note: 'Verified over Matrix call',
    });
    expect((await adapter.getTrustStatus(imported.publicKeyBase64Url)).trusted).toBe(true);
    await adapter.addTrustedKey({
      publicKeyBase64Url: imported.publicKeyBase64Url,
      fingerprintHex: imported.fingerprintHex,
      displayName: 'Verified Sender Updated',
    });
    expect(await adapter.listTrustedKeys()).toHaveLength(1);
  });
});
