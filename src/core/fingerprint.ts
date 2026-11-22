import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { ED25519_PUBLIC_KEY_BYTES } from './constants.js';
import { bytesToHex } from './encoding.js';
import { ChmExchangeError } from './types.js';

export interface PublicKeyFingerprint {
  digest: Uint8Array;
  fullHex: string;
  shortDisplay: string;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    try {
      const copy = new Uint8Array(data.byteLength);
      copy.set(data);
      const digest = await globalThis.crypto.subtle.digest('SHA-256', copy.buffer);
      return new Uint8Array(digest);
    } catch {
      // Fallback to @noble/hashes in restricted/non-secure contexts
    }
  }
  return nobleSha256(data);
}

export function sha256Sync(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

export function formatShortFingerprint(fullHex: string): string {
  const shortHex = fullHex.slice(0, 16).toUpperCase();
  const groups = shortHex.match(/.{1,4}/g) ?? [];
  return `CHM-${groups.slice(0, 4).join('-')}`;
}

export function computePublicKeyFingerprintSync(publicKey32: Uint8Array): PublicKeyFingerprint {
  if (!(publicKey32 instanceof Uint8Array) || publicKey32.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new ChmExchangeError(
      'INVALID_PUBLIC_KEY_LENGTH',
      `Ed25519 public key must be exactly ${ED25519_PUBLIC_KEY_BYTES} bytes`,
    );
  }
  const digest = sha256Sync(publicKey32);
  const fullHex = bytesToHex(digest);
  return {
    digest,
    fullHex,
    shortDisplay: formatShortFingerprint(fullHex),
  };
}

export async function computePublicKeyFingerprint(
  publicKey32: Uint8Array,
): Promise<PublicKeyFingerprint> {
  if (!(publicKey32 instanceof Uint8Array) || publicKey32.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new ChmExchangeError(
      'INVALID_PUBLIC_KEY_LENGTH',
      `Ed25519 public key must be exactly ${ED25519_PUBLIC_KEY_BYTES} bytes`,
    );
  }
  const digest = await sha256(publicKey32);
  const fullHex = bytesToHex(digest);
  return {
    digest,
    fullHex,
    shortDisplay: formatShortFingerprint(fullHex),
  };
}
