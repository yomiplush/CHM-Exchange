import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { ED25519_PUBLIC_KEY_BYTES } from '../constants.js';
import { base64UrlDecode, base64UrlEncode } from '../encoding.js';
import { ChmExchangeError } from '../types.js';
import { ED25519_SIGNATURE_BYTES } from './constants.js';
import { randomCryptographicBytes } from './cbor.js';

// Ensure audited SHA-512 hash function is configured for @noble/ed25519 v3
ed25519.hashes.sha512 = sha512;

/**
 * Strictly validates an Ed25519 public key for CHM-DEVICE-PAIRING-v1:
 * - Exactly 32 bytes
 * - Not all-zero
 * - Valid compressed Edwards curve point
 * - Non-small-order and torsion-free (rejects identity & low-order points like [1, 0...0])
 */
export function assertStrictEd25519PublicKey(
  rawPublicKey: Uint8Array | string,
  fieldName = 'publicKey',
): Uint8Array {
  const bytes =
    typeof rawPublicKey === 'string' ? base64UrlDecode(rawPublicKey.trim()) : rawPublicKey;

  if (!(bytes instanceof Uint8Array) || bytes.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new ChmExchangeError(
      'INVALID_PUBLIC_KEY_LENGTH',
      `${fieldName} must be exactly ${ED25519_PUBLIC_KEY_BYTES} bytes`,
    );
  }

  let nonZero = 0;
  for (let i = 0; i < bytes.length; i++) {
    nonZero |= bytes[i];
  }
  if (nonZero === 0) {
    throw new ChmExchangeError('INVALID_PUBLIC_KEY', `${fieldName} cannot be all-zero bytes`);
  }

  try {
    const point = ed25519.Point.fromBytes(bytes);
    if (point.isSmallOrder() || !point.isTorsionFree()) {
      throw new ChmExchangeError(
        'INVALID_PUBLIC_KEY',
        `${fieldName} is a small-order or non-torsion-free Ed25519 point`,
      );
    }
  } catch (err) {
    if (err instanceof ChmExchangeError) throw err;
    throw new ChmExchangeError(
      'INVALID_PUBLIC_KEY',
      `${fieldName} is not a valid Ed25519 curve point`,
    );
  }

  return new Uint8Array(bytes);
}

export function buildDomainSeparatedMessage(
  domainPrefix: Uint8Array,
  payloadBytes: Uint8Array,
): Uint8Array {
  const msg = new Uint8Array(domainPrefix.length + payloadBytes.length);
  msg.set(domainPrefix, 0);
  msg.set(payloadBytes, domainPrefix.length);
  return msg;
}

/**
 * Strict RFC 8032 / canonical Ed25519 verification (`zip215: false`):
 * - Rejects small-order public keys & R points
 * - Rejects non-canonical S >= L signature malleability
 */
export function verifyStrictEd25519Signature(
  publicKey32: Uint8Array,
  message: Uint8Array,
  signature64: Uint8Array,
): boolean {
  if (!(signature64 instanceof Uint8Array) || signature64.length !== ED25519_SIGNATURE_BYTES) {
    return false;
  }
  try {
    const validPub = assertStrictEd25519PublicKey(publicKey32);
    return ed25519.verify(signature64, message, validPub, { zip215: false });
  } catch {
    return false;
  }
}

export function signEd25519WithSeedSync(seed32: Uint8Array, message: Uint8Array): Uint8Array {
  if (!(seed32 instanceof Uint8Array) || seed32.length !== 32) {
    throw new ChmExchangeError('INVALID_SEED', 'Ed25519 private seed must be 32 bytes');
  }
  return ed25519.sign(message, seed32);
}

export function deriveEd25519PublicKeySync(seed32: Uint8Array): Uint8Array {
  if (!(seed32 instanceof Uint8Array) || seed32.length !== 32) {
    throw new ChmExchangeError('INVALID_SEED', 'Ed25519 private seed must be 32 bytes');
  }
  return assertStrictEd25519PublicKey(ed25519.getPublicKey(seed32));
}

export function generateEd25519TestKeypairSync(): {
  seed32: Uint8Array;
  publicKey32: Uint8Array;
  publicKeyBase64Url: string;
} {
  const seed32 = randomCryptographicBytes(32);
  const publicKey32 = deriveEd25519PublicKeySync(seed32);
  return {
    seed32,
    publicKey32,
    publicKeyBase64Url: base64UrlEncode(publicKey32),
  };
}
