import {
  DEFAULT_EXCHANGE_BASE_URL,
  MAX_EXCHANGE_JSON_BYTES,
  MAX_EXCHANGE_TOKEN_CHARS,
  MAX_EXCHANGE_URL_CHARS,
} from './constants.js';
import {
  decodeExchangeBundleToken,
  encodeExchangeBundleToken,
  parseExchangeBundleJson,
} from './bundle.js';
import { utf8ByteLength } from './encoding.js';
import { ChmExchangeError } from './types.js';
import type { ChmPublicKeyBundle, VerifiedPublicKeyImport } from './types.js';

export function sanitizeExchangeBaseUrl(rawUrl?: string): string {
  const trimmed = (rawUrl ?? '').trim();
  if (!trimmed) {
    return DEFAULT_EXCHANGE_BASE_URL;
  }
  if (trimmed.startsWith('/')) {
    if (trimmed.startsWith('//')) {
      throw new ChmExchangeError(
        'INVALID_BASE_URL',
        'Protocol-relative URLs are not allowed as exchange base URL',
      );
    }
    return trimmed.split('#')[0].split('?')[0];
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new ChmExchangeError('INVALID_BASE_URL', 'Exchange base URL must be a valid URL');
  }

  const isLocalHttp =
    parsed.protocol === 'http:' &&
    (parsed.hostname === 'localhost' ||
      parsed.hostname === '127.0.0.1' ||
      parsed.hostname === '[::1]');

  if (parsed.protocol !== 'https:' && !isLocalHttp) {
    throw new ChmExchangeError(
      'INVALID_BASE_URL',
      'Exchange base URL must use https:// (or localhost http://)',
    );
  }

  parsed.search = '';
  parsed.hash = '';
  const str = parsed.toString();
  return str.endsWith('/') && parsed.pathname !== '/' ? str.slice(0, -1) : str.replace(/\/$/, '');
}

export function encodeExchangeUrl(
  bundle: ChmPublicKeyBundle,
  baseUrl: string = DEFAULT_EXCHANGE_BASE_URL,
): string {
  const cleanBase = sanitizeExchangeBaseUrl(baseUrl);
  const token = encodeExchangeBundleToken(bundle);
  const url = `${cleanBase}#key=${token}`;
  if (url.length > MAX_EXCHANGE_URL_CHARS) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Generated exchange URL exceeds ${MAX_EXCHANGE_URL_CHARS} characters`,
    );
  }
  return url;
}

export function extractExchangeTokenFromUrl(rawInput: string): string {
  if (typeof rawInput !== 'string') {
    throw new ChmExchangeError('INVALID_INPUT', 'Exchange URL input must be a string');
  }
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new ChmExchangeError('EMPTY_INPUT', 'Exchange URL input is empty');
  }
  if (trimmed.length > MAX_EXCHANGE_URL_CHARS) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Exchange URL exceeds maximum ${MAX_EXCHANGE_URL_CHARS} characters`,
    );
  }

  // Reject dangerous URI schemes before parsing fragment
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new ChmExchangeError('INVALID_URL', 'Input is not a valid URL');
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      throw new ChmExchangeError(
        'UNSAFE_URL_SCHEME',
        `Unsupported URL scheme "${parsed.protocol}". Only https:// or http:// exchange URLs are allowed.`,
      );
    }
    if (!parsed.hash || !parsed.hash.includes('key=')) {
      throw new ChmExchangeError(
        'MISSING_KEY_FRAGMENT',
        'Exchange URL fragment does not contain a "key" parameter',
      );
    }
    const params = new URLSearchParams(parsed.hash.slice(1));
    const token = params.get('key');
    if (!token) {
      throw new ChmExchangeError('MISSING_KEY_FRAGMENT', 'Exchange URL "key" parameter is empty');
    }
    if (token.length > MAX_EXCHANGE_TOKEN_CHARS) {
      throw new ChmExchangeError(
        'PAYLOAD_TOO_LARGE',
        `Exchange token exceeds maximum ${MAX_EXCHANGE_TOKEN_CHARS} characters`,
      );
    }
    return token;
  }

  let fragment: string;
  if (trimmed.includes('#')) {
    fragment = trimmed.slice(trimmed.indexOf('#') + 1);
  } else if (trimmed.startsWith('key=')) {
    fragment = trimmed;
  } else {
    throw new ChmExchangeError(
      'MISSING_KEY_FRAGMENT',
      'Input does not contain a #key=... fragment',
    );
  }

  const params = new URLSearchParams(fragment);
  const token = params.get('key');
  if (!token) {
    throw new ChmExchangeError(
      'MISSING_KEY_FRAGMENT',
      'URL fragment does not contain a "key" parameter',
    );
  }
  if (token.length > MAX_EXCHANGE_TOKEN_CHARS) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Exchange token exceeds maximum ${MAX_EXCHANGE_TOKEN_CHARS} characters`,
    );
  }
  return token;
}

export function decodeExchangeUrl(rawInput: string): VerifiedPublicKeyImport {
  const token = extractExchangeTokenFromUrl(rawInput);
  const decoded = decodeExchangeBundleToken(token);
  return {
    ...decoded,
    sourceKind: 'exchange-url',
  };
}

/**
 * Unified, strict parser for any public-key exchange input:
 * 1. Exchange URL (`https://.../exchange#key=...`, `#key=...`, or `key=...`)
 * 2. JSON bundle (`chm-exchange-public-key` or `certified-handmade-public-key`)
 * 3. Base64url-encoded exchange bundle token
 * 4. Raw 43-character Base64url Ed25519 public key (32 bytes)
 */
export function parsePublicKeyExchangeInput(rawInput: string): VerifiedPublicKeyImport {
  if (typeof rawInput !== 'string') {
    throw new ChmExchangeError('INVALID_INPUT', 'Input must be a string');
  }
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new ChmExchangeError('EMPTY_INPUT', 'Public-key input is empty');
  }

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    if (utf8ByteLength(trimmed) > MAX_EXCHANGE_JSON_BYTES) {
      throw new ChmExchangeError(
        'PAYLOAD_TOO_LARGE',
        `JSON input exceeds maximum ${MAX_EXCHANGE_JSON_BYTES} bytes`,
      );
    }
    return parseExchangeBundleJson(trimmed);
  }

  if (
    trimmed.includes('#') ||
    trimmed.startsWith('key=') ||
    /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)
  ) {
    return decodeExchangeUrl(trimmed);
  }

  return decodeExchangeBundleToken(trimmed);
}
