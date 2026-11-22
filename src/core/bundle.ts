import {
  CHM_EXCHANGE_ALGORITHM,
  CHM_EXCHANGE_FORMAT,
  CHM_EXCHANGE_PROTOCOL_VERSION,
  CHM_HOST_EXPORT_FORMAT,
  ED25519_PUBLIC_KEY_BYTES,
  MAX_EXCHANGE_BUNDLE_BYTES,
  MAX_EXCHANGE_JSON_BYTES,
  MAX_EXCHANGE_TOKEN_CHARS,
} from './constants.js';
import {
  base64UrlDecode,
  base64UrlEncode,
  utf8ByteLength,
  utf8DecodeStrict,
  utf8Encode,
} from './encoding.js';
import { computePublicKeyFingerprintSync } from './fingerprint.js';
import { ChmExchangeError } from './types.js';
import type {
  CertifiedHandmadePublicKeyJson,
  ChmPublicKeyBundle,
  VerifiedPublicKeyImport,
} from './types.js';
import {
  assertNoPrivateKeyMaterial,
  decodeAndValidateEd25519PublicKey,
  sanitizeDisplayName,
  validateExchangeBundleObject,
} from './validation.js';

export interface CreatePublicKeyBundleOptions {
  publicKey: Uint8Array | string;
  displayName?: string;
  exportedAt?: string;
  includeTimestamp?: boolean;
}

export function createPublicKeyBundle(options: CreatePublicKeyBundleOptions): ChmPublicKeyBundle {
  if (!options || typeof options !== 'object') {
    throw new ChmExchangeError('INVALID_INPUT', 'Options object is required');
  }
  assertNoPrivateKeyMaterial(options);

  let publicKeyBytes: Uint8Array;
  if (options.publicKey instanceof Uint8Array) {
    if (options.publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
      throw new ChmExchangeError(
        'INVALID_PUBLIC_KEY_LENGTH',
        `Ed25519 public key must be exactly ${ED25519_PUBLIC_KEY_BYTES} bytes`,
      );
    }
    publicKeyBytes = decodeAndValidateEd25519PublicKey(base64UrlEncode(options.publicKey));
  } else if (typeof options.publicKey === 'string') {
    publicKeyBytes = decodeAndValidateEd25519PublicKey(options.publicKey);
  } else {
    throw new ChmExchangeError(
      'INVALID_PUBLIC_KEY',
      'publicKey must be a 32-byte Uint8Array or base64url string',
    );
  }

  const fp = computePublicKeyFingerprintSync(publicKeyBytes);
  const displayName = sanitizeDisplayName(options.displayName, 'displayName');
  const exportedAt =
    options.exportedAt !== undefined
      ? options.exportedAt
      : options.includeTimestamp
        ? new Date().toISOString()
        : undefined;

  const candidate: ChmPublicKeyBundle = {
    format: CHM_EXCHANGE_FORMAT,
    version: CHM_EXCHANGE_PROTOCOL_VERSION,
    algorithm: CHM_EXCHANGE_ALGORITHM,
    publicKey: base64UrlEncode(publicKeyBytes),
    fingerprint: fp.fullHex,
    ...(displayName ? { displayName } : {}),
    ...(exportedAt ? { exportedAt } : {}),
  };

  const validated = validateExchangeBundleObject(candidate);
  const encodedBytes = utf8Encode(JSON.stringify(validated.bundle));
  if (encodedBytes.byteLength > MAX_EXCHANGE_BUNDLE_BYTES) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Serialized exchange bundle exceeds ${MAX_EXCHANGE_BUNDLE_BYTES} bytes`,
    );
  }
  return validated.bundle;
}

export function toCertifiedHandmadePublicKeyJson(
  bundle: ChmPublicKeyBundle,
  fallbackLabel = 'Artist Key',
): CertifiedHandmadePublicKeyJson {
  const validated = validateExchangeBundleObject(bundle);
  return {
    format: CHM_HOST_EXPORT_FORMAT,
    version: CHM_EXCHANGE_PROTOCOL_VERSION,
    algorithm: CHM_EXCHANGE_ALGORITHM,
    publicKey: validated.bundle.publicKey,
    fingerprint: validated.fingerprintHex,
    label: validated.bundle.displayName ?? fallbackLabel,
    exportedAt: validated.bundle.exportedAt ?? new Date().toISOString(),
  };
}

export function serializeExchangeBundleJson(
  bundle: ChmPublicKeyBundle,
  options?: { pretty?: boolean; hostCompatible?: boolean },
): string {
  const validated = validateExchangeBundleObject(bundle);
  const payload = options?.hostCompatible
    ? toCertifiedHandmadePublicKeyJson(validated.bundle)
    : validated.bundle;
  return options?.pretty ? JSON.stringify(payload, null, 2) : JSON.stringify(payload);
}

export function encodeExchangeBundleToken(bundle: ChmPublicKeyBundle): string {
  const validated = validateExchangeBundleObject(bundle);
  const json = JSON.stringify(validated.bundle);
  const bytes = utf8Encode(json);
  if (bytes.byteLength > MAX_EXCHANGE_BUNDLE_BYTES) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Exchange bundle exceeds ${MAX_EXCHANGE_BUNDLE_BYTES} bytes`,
    );
  }
  return base64UrlEncode(bytes);
}

export function parseExchangeBundleJson(rawJson: string): VerifiedPublicKeyImport {
  if (typeof rawJson !== 'string') {
    throw new ChmExchangeError('INVALID_JSON', 'JSON input must be a string');
  }
  const trimmed = rawJson.trim();
  if (!trimmed) {
    throw new ChmExchangeError('EMPTY_INPUT', 'JSON input is empty');
  }
  if (utf8ByteLength(trimmed) > MAX_EXCHANGE_JSON_BYTES) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `JSON payload exceeds maximum ${MAX_EXCHANGE_JSON_BYTES} bytes`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new ChmExchangeError('MALFORMED_JSON', 'Input is not valid JSON');
  }

  const validated = validateExchangeBundleObject(parsed);
  return {
    publicKeyBytes: validated.publicKeyBytes,
    publicKeyBase64Url: validated.bundle.publicKey,
    fingerprintHex: validated.fingerprintHex,
    fingerprintShort: validated.fingerprintShort,
    displayName: validated.bundle.displayName,
    exportedAt: validated.bundle.exportedAt,
    sourceKind: validated.sourceFormat === CHM_HOST_EXPORT_FORMAT ? 'host-json' : 'exchange-json',
    sourceVersion: validated.bundle.version,
    bundle: validated.bundle,
  };
}

export function decodeExchangeBundleToken(token: string): VerifiedPublicKeyImport {
  if (typeof token !== 'string') {
    throw new ChmExchangeError('INVALID_TOKEN', 'Exchange token must be a string');
  }
  const trimmed = token.trim();
  if (!trimmed) {
    throw new ChmExchangeError('EMPTY_INPUT', 'Exchange token is empty');
  }
  if (trimmed.length > MAX_EXCHANGE_TOKEN_CHARS) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Exchange token exceeds maximum ${MAX_EXCHANGE_TOKEN_CHARS} characters`,
    );
  }

  const bytes = base64UrlDecode(trimmed);
  if (bytes.byteLength === ED25519_PUBLIC_KEY_BYTES) {
    const publicKeyBytes = decodeAndValidateEd25519PublicKey(trimmed);
    const fp = computePublicKeyFingerprintSync(publicKeyBytes);
    const bundle = createPublicKeyBundle({ publicKey: publicKeyBytes });
    return {
      publicKeyBytes,
      publicKeyBase64Url: bundle.publicKey,
      fingerprintHex: fp.fullHex,
      fingerprintShort: fp.shortDisplay,
      sourceKind: 'raw-public-key',
      sourceVersion: null,
      bundle,
    };
  }

  if (bytes.byteLength > MAX_EXCHANGE_BUNDLE_BYTES) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Decoded exchange bundle exceeds maximum ${MAX_EXCHANGE_BUNDLE_BYTES} bytes`,
    );
  }

  const jsonText = utf8DecodeStrict(bytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    throw new ChmExchangeError('MALFORMED_JSON', 'Decoded exchange token does not contain valid JSON');
  }

  const validated = validateExchangeBundleObject(parsed);
  return {
    publicKeyBytes: validated.publicKeyBytes,
    publicKeyBase64Url: validated.bundle.publicKey,
    fingerprintHex: validated.fingerprintHex,
    fingerprintShort: validated.fingerprintShort,
    displayName: validated.bundle.displayName,
    exportedAt: validated.bundle.exportedAt,
    sourceKind: 'exchange-token',
    sourceVersion: validated.bundle.version,
    bundle: validated.bundle,
  };
}
