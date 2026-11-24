import { sha256Sync } from '../fingerprint.js';
import { assertExactBytes } from './cbor.js';
import { PAIRING_CONFIRM_DOMAIN_PREFIX, PAIRING_NONCE_BYTES } from './constants.js';
import { assertStrictEd25519PublicKey } from './crypto.js';

// 32-character Crockford-style unambiguous alphabet (excludes 0, 1, I, O)
const PAIRING_CONFIRM_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

/**
 * Computes an 8-character human-verifiable confirmation code (e.g. "A7K9-M2P4")
 * deterministically from:
 *   SHA-256("CHM-PAIR-CONFIRM1\0" || requestHash || nonce || devicePublicKey)
 *
 * Both the New Device (request QR panel + enrollment certificate preview) and
 * the Owner Device (approval dialog + approval QR panel) compute this identical
 * value so QR substitution / MitM attacks are caught out-of-band before approval.
 */
export function computePairingConfirmationCode(params: {
  requestHash: Uint8Array;
  nonce: Uint8Array;
  devicePublicKey: Uint8Array;
}): string {
  const requestHash = assertExactBytes(params.requestHash, 32, 'requestHash');
  const nonce = assertExactBytes(params.nonce, PAIRING_NONCE_BYTES, 'nonce');
  const devicePublicKey = assertStrictEd25519PublicKey(params.devicePublicKey, 'devicePublicKey');

  const input = new Uint8Array(
    PAIRING_CONFIRM_DOMAIN_PREFIX.length + requestHash.length + nonce.length + devicePublicKey.length,
  );
  let offset = 0;
  input.set(PAIRING_CONFIRM_DOMAIN_PREFIX, offset);
  offset += PAIRING_CONFIRM_DOMAIN_PREFIX.length;
  input.set(requestHash, offset);
  offset += requestHash.length;
  input.set(nonce, offset);
  offset += nonce.length;
  input.set(devicePublicKey, offset);

  const digest = sha256Sync(input);
  let chars = '';
  for (let i = 0; i < 8; i++) {
    chars += PAIRING_CONFIRM_ALPHABET[digest[i] & 0x1f];
  }
  return `${chars.slice(0, 4)}-${chars.slice(4, 8)}`;
}
