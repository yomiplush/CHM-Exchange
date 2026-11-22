import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  CHM_EXCHANGE_ALGORITHM,
  CHM_EXCHANGE_FORMAT,
  CHM_EXCHANGE_PROTOCOL_VERSION,
  CHM_HOST_EXPORT_FORMAT,
  ChmExchangeError,
  DEFAULT_EXCHANGE_BASE_URL,
  UnsupportedExchangeVersionError,
  base64UrlDecode,
  base64UrlEncode,
  computePublicKeyFingerprint,
  computePublicKeyFingerprintSync,
  createPublicKeyBundle,
  decodeExchangeBundleToken,
  decodeExchangeUrl,
  encodeExchangeBundleToken,
  encodeExchangeUrl,
  hexToBytes,
  parseExchangeBundleJson,
  parsePublicKeyExchangeInput,
  sanitizeExchangeBaseUrl,
  serializeExchangeBundleJson,
  toCertifiedHandmadePublicKeyJson,
} from '../../src/core.js';

// RFC 8032 Ed25519 Test Vector 1 public key
const VECTOR_PUBKEY_HEX = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const VECTOR_PUBKEY_BYTES = hexToBytes(VECTOR_PUBKEY_HEX);
const EXPECTED_FP_HEX = createHash('sha256').update(VECTOR_PUBKEY_BYTES).digest('hex');
const EXPECTED_SHORT_FP = `CHM-${EXPECTED_FP_HEX.slice(0, 16)
  .toUpperCase()
  .match(/.{1,4}/g)!
  .join('-')}`;

describe('CHM-Exchange Protocol & Bundle Serialization', () => {
  it('computes deterministic SHA-256 fingerprints matching RFC 8032 test vector', async () => {
    const syncFp = computePublicKeyFingerprintSync(VECTOR_PUBKEY_BYTES);
    const asyncFp = await computePublicKeyFingerprint(VECTOR_PUBKEY_BYTES);

    expect(syncFp.fullHex).toBe(EXPECTED_FP_HEX);
    expect(syncFp.shortDisplay).toBe(EXPECTED_SHORT_FP);
    expect(asyncFp.fullHex).toBe(EXPECTED_FP_HEX);
    expect(asyncFp.shortDisplay).toBe(EXPECTED_SHORT_FP);
  });

  it('creates a canonical v1 public-key bundle from raw bytes or base64url', () => {
    const b64u = base64UrlEncode(VECTOR_PUBKEY_BYTES);
    const fromBytes = createPublicKeyBundle({
      publicKey: VECTOR_PUBKEY_BYTES,
      displayName: '  YomiPlush Studio  ',
      exportedAt: '2026-11-23T00:00:00.000Z',
    });
    const fromString = createPublicKeyBundle({
      publicKey: b64u,
      displayName: 'YomiPlush Studio',
      exportedAt: '2026-11-23T00:00:00.000Z',
    });

    expect(fromBytes).toEqual({
      format: CHM_EXCHANGE_FORMAT,
      version: CHM_EXCHANGE_PROTOCOL_VERSION,
      algorithm: CHM_EXCHANGE_ALGORITHM,
      publicKey: b64u,
      fingerprint: EXPECTED_FP_HEX,
      displayName: 'YomiPlush Studio',
      exportedAt: '2026-11-23T00:00:00.000Z',
    });
    expect(fromString).toEqual(fromBytes);
  });

  it('round-trips CHM-Exchange JSON and Certified Handmade host JSON', () => {
    const bundle = createPublicKeyBundle({
      publicKey: VECTOR_PUBKEY_BYTES,
      displayName: 'Atelier Koto',
      exportedAt: '2026-11-23T01:00:00.000Z',
    });

    const exchangeJson = serializeExchangeBundleJson(bundle, { pretty: true });
    const parsedExchange = parseExchangeBundleJson(exchangeJson);
    expect(parsedExchange.sourceKind).toBe('exchange-json');
    expect(parsedExchange.sourceVersion).toBe(1);
    expect(parsedExchange.displayName).toBe('Atelier Koto');
    expect(parsedExchange.fingerprintHex).toBe(EXPECTED_FP_HEX);
    expect(parsedExchange.fingerprintShort).toBe(EXPECTED_SHORT_FP);
    expect(parsedExchange.publicKeyBytes).toEqual(VECTOR_PUBKEY_BYTES);

    const hostJson = serializeExchangeBundleJson(bundle, { pretty: true, hostCompatible: true });
    const hostParsedObj = JSON.parse(hostJson);
    expect(hostParsedObj.format).toBe(CHM_HOST_EXPORT_FORMAT);
    expect(hostParsedObj.label).toBe('Atelier Koto');

    const importedHost = parseExchangeBundleJson(hostJson);
    expect(importedHost.sourceKind).toBe('host-json');
    expect(importedHost.displayName).toBe('Atelier Koto');
    expect(importedHost.fingerprintHex).toBe(EXPECTED_FP_HEX);
    expect(importedHost.publicKeyBase64Url).toBe(bundle.publicKey);

    const directHost = toCertifiedHandmadePublicKeyJson(bundle);
    expect(directHost.fingerprint).toBe(EXPECTED_FP_HEX);
  });

  it('encodes and decodes #key= exchange URLs and standalone tokens', () => {
    const bundle = createPublicKeyBundle({
      publicKey: VECTOR_PUBKEY_BYTES,
      displayName: '手描き絵師',
    });

    const url = encodeExchangeUrl(bundle);
    expect(url.startsWith(`${DEFAULT_EXCHANGE_BASE_URL}#key=`)).toBe(true);

    const decodedFromUrl = decodeExchangeUrl(url);
    expect(decodedFromUrl.sourceKind).toBe('exchange-url');
    expect(decodedFromUrl.publicKeyBase64Url).toBe(bundle.publicKey);
    expect(decodedFromUrl.fingerprintHex).toBe(EXPECTED_FP_HEX);
    expect(decodedFromUrl.displayName).toBe('手描き絵師');

    // Fragment-only and key= prefix support
    const hashOnly = `#key=${encodeExchangeBundleToken(bundle)}`;
    expect(parsePublicKeyExchangeInput(hashOnly).fingerprintHex).toBe(EXPECTED_FP_HEX);

    const tokenOnly = encodeExchangeBundleToken(bundle);
    const decodedToken = decodeExchangeBundleToken(tokenOnly);
    expect(decodedToken.sourceKind).toBe('exchange-token');
    expect(decodedToken.displayName).toBe('手描き絵師');

    // Raw 43-char base64url Ed25519 key support
    const decodedRaw = parsePublicKeyExchangeInput(bundle.publicKey);
    expect(decodedRaw.sourceKind).toBe('raw-public-key');
    expect(decodedRaw.sourceVersion).toBeNull();
    expect(decodedRaw.fingerprintHex).toBe(EXPECTED_FP_HEX);
  });

  it('supports custom exchangeBaseUrl including https, localhost http, and relative paths', () => {
    const bundle = createPublicKeyBundle({ publicKey: VECTOR_PUBKEY_BYTES });
    expect(encodeExchangeUrl(bundle, 'https://example.org/keys/')).toMatch(
      /^https:\/\/example\.org\/keys#key=/,
    );
    expect(encodeExchangeUrl(bundle, 'http://localhost:5173/exchange')).toMatch(
      /^http:\/\/localhost:5173\/exchange#key=/,
    );
    expect(encodeExchangeUrl(bundle, '/exchange?foo=bar#old')).toMatch(/^\/exchange#key=/);
    expect(() => sanitizeExchangeBaseUrl('//evil.example/exchange')).toThrow(ChmExchangeError);
    expect(() => sanitizeExchangeBaseUrl('http://insecure.example.com/exchange')).toThrow(
      ChmExchangeError,
    );
  });

  it('rejects unsupported protocol versions cleanly', () => {
    const bundle = createPublicKeyBundle({ publicKey: VECTOR_PUBKEY_BYTES });
    const v2Json = JSON.stringify({ ...bundle, version: 2 });
    const v0Json = JSON.stringify({ ...bundle, version: 0 });
    const strVerJson = JSON.stringify({ ...bundle, version: '1' });

    expect(() => parseExchangeBundleJson(v2Json)).toThrow(UnsupportedExchangeVersionError);
    expect(() => parseExchangeBundleJson(v0Json)).toThrow(UnsupportedExchangeVersionError);
    expect(() => parseExchangeBundleJson(strVerJson)).toThrow(UnsupportedExchangeVersionError);

    const badToken = base64UrlEncode(new TextEncoder().encode(v2Json));
    expect(() => decodeExchangeBundleToken(badToken)).toThrow(UnsupportedExchangeVersionError);
  });

  it('round-trips canonical base64url bytes without padding', () => {
    const raw = VECTOR_PUBKEY_BYTES;
    const encoded = base64UrlEncode(raw);
    expect(encoded).toHaveLength(43);
    expect(encoded.includes('=')).toBe(false);
    expect(base64UrlDecode(encoded)).toEqual(raw);
  });
});
