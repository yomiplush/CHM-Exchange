import { ChmExchangeError } from './types.js';

const textEncoder = new TextEncoder();
const textDecoderFatal = new TextDecoder('utf-8', { fatal: true });

export function utf8Encode(text: string): Uint8Array {
  return textEncoder.encode(text);
}

export function utf8DecodeStrict(bytes: Uint8Array): string {
  try {
    return textDecoderFatal.decode(bytes);
  } catch {
    throw new ChmExchangeError('INVALID_UTF8', 'Payload contains invalid UTF-8 byte sequences');
  }
}

export function utf8ByteLength(text: string): number {
  return textEncoder.encode(text).byteLength;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new ChmExchangeError('INVALID_HEX', 'Hex input must be a string');
  }
  const clean = hex.trim().toLowerCase();
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-f]+$/.test(clean)) {
    throw new ChmExchangeError('INVALID_HEX', 'Invalid hexadecimal string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlDecode(input: string): Uint8Array {
  if (typeof input !== 'string' || input.length === 0) {
    throw new ChmExchangeError('INVALID_BASE64URL', 'Empty base64url input');
  }
  if (!/^[A-Za-z0-9_-]+$/.test(input)) {
    throw new ChmExchangeError('INVALID_BASE64URL', 'Input contains invalid base64url characters');
  }
  if (input.length % 4 === 1) {
    throw new ChmExchangeError('INVALID_BASE64URL', 'Invalid base64url length');
  }
  const padded =
    input.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (input.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new ChmExchangeError('INVALID_BASE64URL', 'Failed to decode base64url payload');
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  // Enforce canonical unpadded base64url (reject non-zero trailing padding bits)
  if (base64UrlEncode(out) !== input) {
    throw new ChmExchangeError('INVALID_BASE64URL', 'Non-canonical base64url encoding');
  }
  return out;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function constantTimeEqualAscii(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
