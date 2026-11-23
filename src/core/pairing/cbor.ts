import { decode as cborDecode, encode as cborEncode, rfc8949EncodeOptions } from 'cborg';
import type { DecodeOptions } from 'cborg';
import { bytesToHex, constantTimeEqual } from '../encoding.js';
import { ChmExchangeError } from '../types.js';
import { PAIRING_UUID_BYTES } from './constants.js';

export const STRICT_CBOR_DECODE_OPTIONS: DecodeOptions = {
  allowIndefinite: false,
  allowUndefined: false,
  coerceUndefinedToNull: false,
  allowInfinity: false,
  allowNaN: false,
  allowBigInt: false,
  strict: true,
  useMaps: true,
  rejectDuplicateMapKeys: true,
  rejectInvalidUtf8: true,
};

export function encodeCanonicalCbor(value: unknown): Uint8Array {
  return cborEncode(value, rfc8949EncodeOptions);
}

export function decodeCanonicalCbor(bytes: Uint8Array, label = 'CBOR payload'): unknown {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw new ChmExchangeError('INVALID_CBOR', `${label} must be non-empty bytes`);
  }
  let decoded: unknown;
  try {
    decoded = cborDecode(bytes, STRICT_CBOR_DECODE_OPTIONS);
  } catch (err) {
    throw new ChmExchangeError(
      'INVALID_CBOR',
      `${label} could not be strictly CBOR-decoded: ${err instanceof Error ? err.message : 'invalid CBOR'}`,
    );
  }
  const reEncoded = cborEncode(decoded, rfc8949EncodeOptions);
  if (!constantTimeEqual(reEncoded, bytes)) {
    throw new ChmExchangeError(
      'NON_CANONICAL_CBOR',
      `${label} is not canonically RFC 8949 CBOR-encoded`,
    );
  }
  return decoded;
}

export function randomCryptographicBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0 || length > 4096) {
    throw new ChmExchangeError('INVALID_LENGTH', 'Invalid random byte length');
  }
  if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.getRandomValues) {
    throw new ChmExchangeError('CSPRNG_UNAVAILABLE', 'Web Crypto CSPRNG is unavailable');
  }
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function generatePairingUuidBytes(): Uint8Array {
  const bytes = randomCryptographicBytes(PAIRING_UUID_BYTES);
  // RFC 4122 UUIDv4 version/variant bits
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return bytes;
}

export function formatUuidHex(uuid16: Uint8Array): string {
  assertExactBytes(uuid16, PAIRING_UUID_BYTES, 'uuid');
  const h = bytesToHex(uuid16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export function assertExactBytes(
  value: unknown,
  expectedLength: number,
  fieldName: string,
): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== expectedLength) {
    throw new ChmExchangeError(
      'INVALID_FIELD_BYTES',
      `${fieldName} must be exactly ${expectedLength} bytes`,
    );
  }
  return new Uint8Array(value);
}

export function assertSafeIntegerInRange(
  value: unknown,
  min: number,
  max: number,
  fieldName: string,
): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    throw new ChmExchangeError(
      'INVALID_INTEGER',
      `${fieldName} must be a safe integer in [${min}, ${max}]`,
    );
  }
  return value;
}

export function assertAllowedIntegerMapKeys(
  map: unknown,
  allowedKeys: ReadonlySet<number>,
  label: string,
): Map<number, unknown> {
  if (!(map instanceof Map)) {
    throw new ChmExchangeError('INVALID_CBOR_MAP', `${label} must be a CBOR map`);
  }
  for (const key of map.keys()) {
    if (typeof key !== 'number' || !Number.isSafeInteger(key) || !allowedKeys.has(key)) {
      throw new ChmExchangeError(
        'UNEXPECTED_CBOR_FIELD',
        `Unknown or disallowed CBOR field key "${String(key)}" in ${label}`,
      );
    }
  }
  return map as Map<number, unknown>;
}
