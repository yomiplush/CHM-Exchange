import {
  CHM_EXCHANGE_ALGORITHM,
  CHM_EXCHANGE_FORMAT,
  CHM_EXCHANGE_PROTOCOL_VERSION,
  CHM_HOST_EXPORT_FORMAT,
  ED25519_PUBLIC_KEY_BYTES,
  FORBIDDEN_PRIVATE_KEYS,
  MAX_DISPLAY_NAME_UTF8_BYTES,
  MAX_TRUST_NOTE_UTF8_BYTES,
  SHA256_HEX_CHARS,
} from './constants.js';
import {
  base64UrlDecode,
  base64UrlEncode,
  constantTimeEqualAscii,
  utf8ByteLength,
} from './encoding.js';
import { computePublicKeyFingerprintSync } from './fingerprint.js';
import { ChmExchangeError, UnsupportedExchangeVersionError } from './types.js';
import type { ChmPublicKeyBundle, HostSigningIdentity } from './types.js';

// ASCII C0/DEL control chars + Unicode bidi override/isolate controls
// eslint-disable-next-line no-control-regex
const CONTROL_AND_BIDI_RE = /[\u0000-\u001F\u007F\u202A-\u202E\u2066-\u2069]/;
const ALLOWED_EXCHANGE_KEYS = new Set([
  'format',
  'version',
  'algorithm',
  'publicKey',
  'fingerprint',
  'displayName',
  'exportedAt',
]);
const ALLOWED_HOST_KEYS = new Set([
  'format',
  'version',
  'algorithm',
  'publicKey',
  'fingerprint',
  'label',
  'exportedAt',
]);

export function assertNoControlOrBidiChars(value: string, fieldName: string): void {
  if (CONTROL_AND_BIDI_RE.test(value)) {
    throw new ChmExchangeError(
      'DISALLOWED_CHARACTERS',
      `${fieldName} contains disallowed control or bidirectional override characters`,
    );
  }
}

export function sanitizeDisplayName(
  raw: unknown,
  fieldName = 'displayName',
): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== 'string') {
    throw new ChmExchangeError('INVALID_DISPLAY_NAME', `${fieldName} must be a string`);
  }
  assertNoControlOrBidiChars(raw, fieldName);
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  if (utf8ByteLength(trimmed) > MAX_DISPLAY_NAME_UTF8_BYTES) {
    throw new ChmExchangeError(
      'DISPLAY_NAME_TOO_LONG',
      `${fieldName} exceeds maximum ${MAX_DISPLAY_NAME_UTF8_BYTES} UTF-8 bytes`,
    );
  }
  return trimmed;
}

export function sanitizeTrustNote(raw: unknown): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== 'string') {
    throw new ChmExchangeError('INVALID_NOTE', 'Trust note must be a string');
  }
  assertNoControlOrBidiChars(raw, 'note');
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  if (utf8ByteLength(trimmed) > MAX_TRUST_NOTE_UTF8_BYTES) {
    throw new ChmExchangeError(
      'NOTE_TOO_LONG',
      `Trust note exceeds maximum ${MAX_TRUST_NOTE_UTF8_BYTES} UTF-8 bytes`,
    );
  }
  return trimmed;
}

export function assertNoPrivateKeyMaterial(value: unknown, depth = 0): void {
  if (depth > 5 || value === null || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    for (const item of value) {
      assertNoPrivateKeyMaterial(item, depth + 1);
    }
    return;
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (
      FORBIDDEN_PRIVATE_KEYS.has(key) ||
      FORBIDDEN_PRIVATE_KEYS.has(key.toLowerCase())
    ) {
      throw new ChmExchangeError(
        'PRIVATE_KEY_MATERIAL_FORBIDDEN',
        `Forbidden private-key field "${key}" must never appear in public-key exchange payloads`,
      );
    }
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new ChmExchangeError('PROTOTYPE_POLLUTION_KEY', `Disallowed object key "${key}"`);
    }
    assertNoPrivateKeyMaterial(record[key], depth + 1);
  }
}

export function stripToPublicHostIdentity(
  identity: HostSigningIdentity,
): HostSigningIdentity {
  assertNoPrivateKeyMaterial(identity);
  const pubBytes = decodeAndValidateEd25519PublicKey(identity.publicKeyBase64Url);
  const fp = computePublicKeyFingerprintSync(pubBytes);
  if (
    identity.fingerprintHex &&
    !constantTimeEqualAscii(identity.fingerprintHex.toLowerCase(), fp.fullHex)
  ) {
    throw new ChmExchangeError(
      'FINGERPRINT_MISMATCH',
      'Host identity fingerprint does not match its Ed25519 public key',
    );
  }
  const displayName = sanitizeDisplayName(identity.displayName, 'displayName') ?? 'Artist Key';
  return {
    id: String(identity.id),
    displayName,
    publicKeyBase64Url: base64UrlEncode(pubBytes),
    fingerprintHex: fp.fullHex,
    fingerprintShort: fp.shortDisplay,
    ...(typeof identity.createdAt === 'string' ? { createdAt: identity.createdAt } : {}),
  };
}

export function decodeAndValidateEd25519PublicKey(base64UrlKey: string): Uint8Array {
  if (typeof base64UrlKey !== 'string') {
    throw new ChmExchangeError('INVALID_PUBLIC_KEY', 'Public key must be a base64url string');
  }
  const trimmed = base64UrlKey.trim();
  const bytes = base64UrlDecode(trimmed);
  if (bytes.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new ChmExchangeError(
      'INVALID_PUBLIC_KEY_LENGTH',
      `Ed25519 public key must decode to exactly ${ED25519_PUBLIC_KEY_BYTES} bytes (got ${bytes.length})`,
    );
  }
  let allZero = true;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) {
      allZero = false;
      break;
    }
  }
  if (allZero) {
    throw new ChmExchangeError(
      'INVALID_PUBLIC_KEY',
      'Ed25519 public key cannot be all-zero bytes',
    );
  }
  return bytes;
}

function validateOptionalExportedAt(raw: unknown): string | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== 'string') {
    throw new ChmExchangeError('INVALID_TIMESTAMP', 'exportedAt must be an ISO-8601 string');
  }
  assertNoControlOrBidiChars(raw, 'exportedAt');
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.length > 40) {
    throw new ChmExchangeError('INVALID_TIMESTAMP', 'exportedAt has invalid length');
  }
  const parsedTime = Date.parse(trimmed);
  if (Number.isNaN(parsedTime)) {
    throw new ChmExchangeError('INVALID_TIMESTAMP', 'exportedAt is not a valid ISO-8601 date');
  }
  return trimmed;
}

export function validateExchangeBundleObject(
  raw: unknown,
): {
  bundle: ChmPublicKeyBundle;
  publicKeyBytes: Uint8Array;
  fingerprintHex: string;
  fingerprintShort: string;
  sourceFormat: typeof CHM_EXCHANGE_FORMAT | typeof CHM_HOST_EXPORT_FORMAT;
} {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ChmExchangeError('MALFORMED_BUNDLE', 'Exchange bundle must be a JSON object');
  }

  assertNoPrivateKeyMaterial(raw);

  const obj = raw as Record<string, unknown>;
  const format = obj.format;
  if (format !== CHM_EXCHANGE_FORMAT && format !== CHM_HOST_EXPORT_FORMAT) {
    throw new ChmExchangeError(
      'INVALID_FORMAT',
      `Unsupported public-key bundle format: ${String(format)}`,
    );
  }

  const allowedKeys =
    format === CHM_EXCHANGE_FORMAT ? ALLOWED_EXCHANGE_KEYS : ALLOWED_HOST_KEYS;
  for (const key of Object.keys(obj)) {
    if (!allowedKeys.has(key)) {
      throw new ChmExchangeError(
        'UNEXPECTED_FIELD',
        `Unexpected field "${key}" in ${format} bundle`,
      );
    }
  }

  if (obj.version !== CHM_EXCHANGE_PROTOCOL_VERSION) {
    throw new UnsupportedExchangeVersionError(obj.version);
  }

  if (obj.algorithm !== CHM_EXCHANGE_ALGORITHM) {
    throw new ChmExchangeError(
      'UNSUPPORTED_ALGORITHM',
      `Unsupported public-key algorithm: ${String(obj.algorithm)}`,
    );
  }

  if (typeof obj.publicKey !== 'string') {
    throw new ChmExchangeError('INVALID_PUBLIC_KEY', 'Bundle publicKey must be a string');
  }

  const publicKeyBytes = decodeAndValidateEd25519PublicKey(obj.publicKey);
  const canonicalPublicKey = base64UrlEncode(publicKeyBytes);
  const computedFp = computePublicKeyFingerprintSync(publicKeyBytes);

  if (typeof obj.fingerprint !== 'string') {
    throw new ChmExchangeError('MISSING_FINGERPRINT', 'Bundle fingerprint is required');
  }
  const declaredFp = obj.fingerprint.trim().toLowerCase();
  if (declaredFp.length !== SHA256_HEX_CHARS || !/^[0-9a-f]{64}$/.test(declaredFp)) {
    throw new ChmExchangeError(
      'INVALID_FINGERPRINT',
      'Declared fingerprint must be a 64-character SHA-256 hex string',
    );
  }
  if (!constantTimeEqualAscii(declaredFp, computedFp.fullHex)) {
    throw new ChmExchangeError(
      'FINGERPRINT_MISMATCH',
      'Declared fingerprint does not match the locally computed SHA-256 fingerprint of this public key',
    );
  }

  const rawName = format === CHM_EXCHANGE_FORMAT ? obj.displayName : obj.label;
  const displayName = sanitizeDisplayName(
    rawName,
    format === CHM_EXCHANGE_FORMAT ? 'displayName' : 'label',
  );
  const exportedAt = validateOptionalExportedAt(obj.exportedAt);

  const bundle: ChmPublicKeyBundle = {
    format: CHM_EXCHANGE_FORMAT,
    version: CHM_EXCHANGE_PROTOCOL_VERSION,
    algorithm: CHM_EXCHANGE_ALGORITHM,
    publicKey: canonicalPublicKey,
    fingerprint: computedFp.fullHex,
    ...(displayName ? { displayName } : {}),
    ...(exportedAt ? { exportedAt } : {}),
  };

  return {
    bundle,
    publicKeyBytes,
    fingerprintHex: computedFp.fullHex,
    fingerprintShort: computedFp.shortDisplay,
    sourceFormat: format,
  };
}
