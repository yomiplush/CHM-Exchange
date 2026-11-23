import { SHA256_HEX_CHARS } from '../constants.js';
import {
  base64UrlDecode,
  base64UrlEncode,
  bytesToHex,
  constantTimeEqual,
  constantTimeEqualAscii,
  hexToBytes,
  utf8ByteLength,
} from '../encoding.js';
import { sanitizeExchangeBaseUrl } from '../exchangeUrl.js';
import { computePublicKeyFingerprintSync, sha256Sync } from '../fingerprint.js';
import { ChmExchangeError } from '../types.js';
import { assertNoControlOrBidiChars, sanitizeDisplayName } from '../validation.js';
import {
  assertAllowedIntegerMapKeys,
  assertExactBytes,
  assertSafeIntegerInRange,
  decodeCanonicalCbor,
  encodeCanonicalCbor,
  formatUuidHex,
  generatePairingUuidBytes,
  randomCryptographicBytes,
} from './cbor.js';
import {
  ALLOWED_PAIRING_PERMISSIONS_V1,
  CHM_DEVICE_PAIRING_PROTOCOL_ID,
  CHM_DEVICE_PAIRING_VERSION,
  DEFAULT_CLOCK_SKEW_SECONDS,
  DEFAULT_DEVICES_BASE_URL,
  DEFAULT_PAIRING_TTL_SECONDS,
  DEVICE_REVOCATION_DOMAIN_PREFIX,
  DEVICE_REVOCATION_TOKEN_PREFIX,
  ED25519_SIGNATURE_BYTES,
  ENROLLMENT_CERT_DOMAIN_PREFIX,
  ENROLLMENT_CERT_TOKEN_PREFIX,
  MAX_DEVICE_DISPLAY_NAME_UTF8_BYTES,
  MAX_PAIRING_CBOR_BYTES,
  MAX_PAIRING_NOTE_UTF8_BYTES,
  MAX_PAIRING_QR_URL_CHARS,
  MAX_PAIRING_TOKEN_CHARS,
  MAX_PAIRING_TTL_SECONDS,
  OWNER_TARGET_KIND,
  PAIRING_ENVELOPE_KIND,
  PAIRING_NONCE_BYTES,
  PAIRING_REQUEST_DOMAIN_PREFIX,
  PAIRING_REQUEST_TOKEN_PREFIX,
  PAIRING_UUID_BYTES,
  RESERVED_PRIVILEGED_PERMISSIONS,
} from './constants.js';
import {
  assertStrictEd25519PublicKey,
  buildDomainSeparatedMessage,
  verifyStrictEd25519Signature,
} from './crypto.js';
import { UnsupportedPairingVersionError } from './types.js';
import type {
  DevicePermission,
  DeviceRevocationReason,
  OwnerTarget,
  OwnerTrustStatus,
  PairingSignerFn,
  ParsedPairingQrArtifact,
  SignedDeviceRevocationNotice,
  SignedEnrollmentCertificate,
  SignedPairingRequest,
  VerifiedPairingBindingResult,
} from './types.js';

const ALLOWED_REQUEST_KEYS = new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
const ALLOWED_CERT_KEYS = new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
const ALLOWED_REVOKE_KEYS = new Set([1, 2, 3, 4, 5, 6, 7, 8]);

const REVOCATION_REASON_TO_CODE: Record<DeviceRevocationReason, number> = {
  'lost-device': 1,
  'device-compromised': 2,
  retired: 3,
  other: 4,
};

const CODE_TO_REVOCATION_REASON: Record<number, DeviceRevocationReason> = {
  1: 'lost-device',
  2: 'device-compromised',
  3: 'retired',
  4: 'other',
};

export function validatePairingPermissions(raw: unknown): DevicePermission[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new ChmExchangeError(
      'INVALID_PERMISSIONS',
      'Permissions must be a non-empty array',
    );
  }
  const seen = new Set<string>();
  const out: DevicePermission[] = [];
  for (const item of raw) {
    if (typeof item !== 'string') {
      throw new ChmExchangeError('INVALID_PERMISSIONS', 'Each permission must be a string');
    }
    if (RESERVED_PRIVILEGED_PERMISSIONS.has(item)) {
      throw new ChmExchangeError(
        'PRIVILEGE_ESCALATION_FORBIDDEN',
        `Permission "${item}" is privileged and forbidden in CHM-DEVICE-PAIRING-v1`,
      );
    }
    if (!ALLOWED_PAIRING_PERMISSIONS_V1.includes(item as DevicePermission)) {
      throw new ChmExchangeError(
        'PRIVILEGE_ESCALATION_FORBIDDEN',
        `Unknown or unsupported pairing permission "${item}"`,
      );
    }
    if (seen.has(item)) {
      throw new ChmExchangeError('INVALID_PERMISSIONS', `Duplicate permission "${item}"`);
    }
    seen.add(item);
    out.push(item as DevicePermission);
  }
  return out;
}

export function sanitizeRequiredDisplayName(
  raw: unknown,
  fieldName: string,
): string {
  const sanitized = sanitizeDisplayName(raw, fieldName);
  if (!sanitized) {
    throw new ChmExchangeError('INVALID_DISPLAY_NAME', `${fieldName} cannot be empty`);
  }
  if (utf8ByteLength(sanitized) > MAX_DEVICE_DISPLAY_NAME_UTF8_BYTES) {
    throw new ChmExchangeError(
      'DISPLAY_NAME_TOO_LONG',
      `${fieldName} exceeds ${MAX_DEVICE_DISPLAY_NAME_UTF8_BYTES} UTF-8 bytes`,
    );
  }
  return sanitized;
}

export function sanitizeOptionalPairingNote(raw: unknown): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== 'string') {
    throw new ChmExchangeError('INVALID_NOTE', 'Pairing note must be a string');
  }
  assertNoControlOrBidiChars(raw, 'note');
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  if (utf8ByteLength(trimmed) > MAX_PAIRING_NOTE_UTF8_BYTES) {
    throw new ChmExchangeError(
      'NOTE_TOO_LONG',
      `Pairing note exceeds ${MAX_PAIRING_NOTE_UTF8_BYTES} UTF-8 bytes`,
    );
  }
  return trimmed;
}

export function decodePairingEnvelope(
  envelopeBytes: Uint8Array,
  expectedKind: number,
  maxBytes = MAX_PAIRING_CBOR_BYTES,
): { payloadBytes: Uint8Array; signature: Uint8Array } {
  if (!(envelopeBytes instanceof Uint8Array) || envelopeBytes.length === 0) {
    throw new ChmExchangeError('INVALID_PAIRING_ENVELOPE', 'Pairing envelope must be non-empty');
  }
  if (envelopeBytes.length > maxBytes) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Pairing payload (${envelopeBytes.length} bytes) exceeds maximum ${maxBytes} bytes`,
    );
  }

  const outer = decodeCanonicalCbor(envelopeBytes, 'pairing envelope');
  if (!Array.isArray(outer) || outer.length !== 5) {
    throw new ChmExchangeError(
      'INVALID_PAIRING_ENVELOPE',
      'Pairing envelope must be a 5-element canonical CBOR array',
    );
  }
  const [version, protocolId, kind, payloadBytes, signature] = outer;
  if (version !== CHM_DEVICE_PAIRING_VERSION) {
    throw new UnsupportedPairingVersionError(version);
  }
  if (protocolId !== CHM_DEVICE_PAIRING_PROTOCOL_ID) {
    throw new ChmExchangeError(
      'UNSUPPORTED_PAIRING_PROTOCOL',
      `Unsupported pairing protocol identifier: ${String(protocolId)}`,
    );
  }
  if (kind !== expectedKind) {
    throw new ChmExchangeError(
      'WRONG_PAIRING_MESSAGE_KIND',
      `Expected pairing message kind ${expectedKind}, got ${String(kind)}`,
    );
  }
  if (!(payloadBytes instanceof Uint8Array) || payloadBytes.length === 0) {
    throw new ChmExchangeError('INVALID_PAIRING_PAYLOAD', 'Pairing payload must be non-empty bytes');
  }
  const sig = assertExactBytes(signature, ED25519_SIGNATURE_BYTES, 'signature');
  return { payloadBytes: new Uint8Array(payloadBytes), signature: sig };
}

export function encodePairingEnvelope(
  kind: number,
  payloadBytes: Uint8Array,
  signature64: Uint8Array,
  maxBytes = MAX_PAIRING_CBOR_BYTES,
): Uint8Array {
  assertExactBytes(signature64, ED25519_SIGNATURE_BYTES, 'signature');
  const encoded = encodeCanonicalCbor([
    CHM_DEVICE_PAIRING_VERSION,
    CHM_DEVICE_PAIRING_PROTOCOL_ID,
    kind,
    payloadBytes,
    signature64,
  ]);
  if (encoded.length > maxBytes) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Encoded pairing envelope (${encoded.length} bytes) exceeds maximum ${maxBytes} bytes`,
    );
  }
  return encoded;
}

export function normalizeOwnerTarget(input?: {
  ownerPublicKey?: Uint8Array | string;
  ownerFingerprintHex?: string;
}): OwnerTarget {
  if (input?.ownerPublicKey !== undefined) {
    const pk = assertStrictEd25519PublicKey(input.ownerPublicKey, 'ownerPublicKey');
    const fp = sha256Sync(pk);
    if (input.ownerFingerprintHex !== undefined) {
      const cleanHex = input.ownerFingerprintHex.trim().toLowerCase();
      if (cleanHex.length !== SHA256_HEX_CHARS || !/^[0-9a-f]{64}$/.test(cleanHex)) {
        throw new ChmExchangeError('INVALID_FINGERPRINT', 'ownerFingerprintHex must be 64 hex chars');
      }
      if (!constantTimeEqualAscii(cleanHex, bytesToHex(fp))) {
        throw new ChmExchangeError(
          'FINGERPRINT_MISMATCH',
          'ownerFingerprintHex does not match ownerPublicKey',
        );
      }
    }
    return { kind: 'pinned-public-key', ownerPublicKey: pk, ownerFingerprint: fp };
  }
  if (input?.ownerFingerprintHex !== undefined) {
    const cleanHex = input.ownerFingerprintHex.trim().toLowerCase();
    if (cleanHex.length !== SHA256_HEX_CHARS || !/^[0-9a-f]{64}$/.test(cleanHex)) {
      throw new ChmExchangeError('INVALID_FINGERPRINT', 'ownerFingerprintHex must be 64 hex chars');
    }
    return { kind: 'pinned-fingerprint', ownerFingerprint: hexToBytes(cleanHex) };
  }
  return { kind: 'open-owner-binding' };
}

export function buildPairingRequestSigningMessage(payloadBytes: Uint8Array): Uint8Array {
  return buildDomainSeparatedMessage(PAIRING_REQUEST_DOMAIN_PREFIX, payloadBytes);
}

export function buildEnrollmentCertificateSigningMessage(payloadBytes: Uint8Array): Uint8Array {
  return buildDomainSeparatedMessage(ENROLLMENT_CERT_DOMAIN_PREFIX, payloadBytes);
}

export function buildDeviceRevocationSigningMessage(payloadBytes: Uint8Array): Uint8Array {
  return buildDomainSeparatedMessage(DEVICE_REVOCATION_DOMAIN_PREFIX, payloadBytes);
}

export async function createSignedPairingRequest(params: {
  deviceId?: Uint8Array;
  devicePublicKey: Uint8Array | string;
  deviceDisplayName: string;
  signWithDeviceKey: PairingSignerFn;
  ownerPublicKey?: Uint8Array | string;
  ownerFingerprintHex?: string;
  ownerLabelHint?: string;
  ttlSeconds?: number;
  issuedAt?: number;
  permissions?: DevicePermission[];
}): Promise<SignedPairingRequest> {
  const requestId = generatePairingUuidBytes();
  const deviceId = params.deviceId
    ? assertExactBytes(params.deviceId, PAIRING_UUID_BYTES, 'deviceId')
    : generatePairingUuidBytes();
  const devicePublicKey = assertStrictEd25519PublicKey(params.devicePublicKey, 'devicePublicKey');
  const deviceDisplayName = sanitizeRequiredDisplayName(
    params.deviceDisplayName,
    'deviceDisplayName',
  );
  const ownerTarget = normalizeOwnerTarget({
    ownerPublicKey: params.ownerPublicKey,
    ownerFingerprintHex: params.ownerFingerprintHex,
  });
  if (
    ownerTarget.kind === 'pinned-public-key' &&
    constantTimeEqual(ownerTarget.ownerPublicKey, devicePublicKey)
  ) {
    throw new ChmExchangeError(
      'DEVICE_CANNOT_BE_OWNER',
      'Device keypair must be distinct from the Owner root identity key',
    );
  }
  const ownerLabelHint = sanitizeDisplayName(params.ownerLabelHint, 'ownerLabelHint');
  const nonce = randomCryptographicBytes(PAIRING_NONCE_BYTES);
  const issuedAt = assertSafeIntegerInRange(
    params.issuedAt ?? Math.floor(Date.now() / 1000),
    0,
    Number.MAX_SAFE_INTEGER,
    'issuedAt',
  );
  const ttl = assertSafeIntegerInRange(
    params.ttlSeconds ?? DEFAULT_PAIRING_TTL_SECONDS,
    1,
    MAX_PAIRING_TTL_SECONDS,
    'ttlSeconds',
  );
  const expiresAt = assertSafeIntegerInRange(issuedAt + ttl, issuedAt + 1, Number.MAX_SAFE_INTEGER, 'expiresAt');
  const permissions = validatePairingPermissions(params.permissions ?? ['device-identity']);

  const map = new Map<number, unknown>();
  map.set(1, requestId);
  map.set(2, deviceId);
  map.set(3, devicePublicKey);
  map.set(4, deviceDisplayName);
  if (ownerTarget.kind === 'pinned-public-key') {
    map.set(5, OWNER_TARGET_KIND.PINNED_PUBLIC_KEY);
    map.set(6, ownerTarget.ownerPublicKey);
    map.set(7, ownerTarget.ownerFingerprint);
  } else if (ownerTarget.kind === 'pinned-fingerprint') {
    map.set(5, OWNER_TARGET_KIND.PINNED_FINGERPRINT);
    map.set(7, ownerTarget.ownerFingerprint);
  } else {
    map.set(5, OWNER_TARGET_KIND.OPEN_OWNER_BINDING);
  }
  map.set(8, nonce);
  map.set(9, issuedAt);
  map.set(10, expiresAt);
  map.set(11, permissions);
  if (ownerLabelHint !== undefined) {
    map.set(12, ownerLabelHint);
  }

  const payloadBytes = encodeCanonicalCbor(map);
  const signingMsg = buildPairingRequestSigningMessage(payloadBytes);
  const rawSig = await params.signWithDeviceKey(signingMsg);
  const signature = assertExactBytes(rawSig, ED25519_SIGNATURE_BYTES, 'deviceSignature');
  if (!verifyStrictEd25519Signature(devicePublicKey, signingMsg, signature)) {
    throw new ChmExchangeError(
      'INVALID_SIGNATURE',
      'Produced pairing request signature failed strict verification against devicePublicKey',
    );
  }

  const envelopeBytes = encodePairingEnvelope(PAIRING_ENVELOPE_KIND.REQUEST, payloadBytes, signature);
  const requestHash = sha256Sync(envelopeBytes);
  const fp = computePublicKeyFingerprintSync(devicePublicKey);

  return {
    envelopeBytes,
    payloadBytes,
    signature,
    requestHash,
    requestHashHex: bytesToHex(requestHash),
    token: `${PAIRING_REQUEST_TOKEN_PREFIX}${base64UrlEncode(envelopeBytes)}`,
    payload: {
      version: CHM_DEVICE_PAIRING_VERSION,
      protocol: CHM_DEVICE_PAIRING_PROTOCOL_ID,
      requestId,
      requestIdHex: formatUuidHex(requestId),
      deviceId,
      deviceIdHex: formatUuidHex(deviceId),
      devicePublicKey,
      devicePublicKeyBase64Url: base64UrlEncode(devicePublicKey),
      deviceFingerprintHex: fp.fullHex,
      deviceFingerprintShort: fp.shortDisplay,
      deviceDisplayName,
      ownerTarget,
      ownerLabelHint,
      nonce,
      nonceHex: bytesToHex(nonce),
      issuedAt,
      expiresAt,
      permissions,
    },
  };
}

export function decodeAndVerifyPairingRequestBytes(
  envelopeBytes: Uint8Array,
): SignedPairingRequest {
  const { payloadBytes, signature } = decodePairingEnvelope(
    envelopeBytes,
    PAIRING_ENVELOPE_KIND.REQUEST,
  );
  const decoded = decodeCanonicalCbor(payloadBytes, 'pairing request payload');
  const map = assertAllowedIntegerMapKeys(decoded, ALLOWED_REQUEST_KEYS, 'pairing request');

  const requestId = assertExactBytes(map.get(1), PAIRING_UUID_BYTES, 'requestId');
  const deviceId = assertExactBytes(map.get(2), PAIRING_UUID_BYTES, 'deviceId');
  const devicePublicKey = assertStrictEd25519PublicKey(
    assertExactBytes(map.get(3), 32, 'devicePublicKey'),
    'devicePublicKey',
  );
  const deviceDisplayName = sanitizeRequiredDisplayName(map.get(4), 'deviceDisplayName');

  const targetKindCode = map.get(5);
  let ownerTarget: OwnerTarget;
  if (targetKindCode === OWNER_TARGET_KIND.PINNED_PUBLIC_KEY) {
    const ownerPublicKey = assertStrictEd25519PublicKey(
      assertExactBytes(map.get(6), 32, 'ownerPublicKey'),
      'ownerPublicKey',
    );
    const ownerFingerprint = assertExactBytes(map.get(7), 32, 'ownerFingerprint');
    if (!constantTimeEqual(sha256Sync(ownerPublicKey), ownerFingerprint)) {
      throw new ChmExchangeError(
        'FINGERPRINT_MISMATCH',
        'ownerFingerprint does not match ownerPublicKey in pairing request',
      );
    }
    if (constantTimeEqual(ownerPublicKey, devicePublicKey)) {
      throw new ChmExchangeError(
        'DEVICE_CANNOT_BE_OWNER',
        'Pairing request devicePublicKey cannot equal ownerPublicKey',
      );
    }
    ownerTarget = { kind: 'pinned-public-key', ownerPublicKey, ownerFingerprint };
  } else if (targetKindCode === OWNER_TARGET_KIND.PINNED_FINGERPRINT) {
    if (map.has(6)) {
      throw new ChmExchangeError(
        'UNEXPECTED_CBOR_FIELD',
        'ownerPublicKey is disallowed when ownerTargetKind is pinned-fingerprint',
      );
    }
    const ownerFingerprint = assertExactBytes(map.get(7), 32, 'ownerFingerprint');
    if (constantTimeEqual(sha256Sync(devicePublicKey), ownerFingerprint)) {
      throw new ChmExchangeError(
        'DEVICE_CANNOT_BE_OWNER',
        'Pairing request device fingerprint cannot equal ownerFingerprint',
      );
    }
    ownerTarget = { kind: 'pinned-fingerprint', ownerFingerprint };
  } else if (targetKindCode === OWNER_TARGET_KIND.OPEN_OWNER_BINDING) {
    if (map.has(6) || map.has(7)) {
      throw new ChmExchangeError(
        'UNEXPECTED_CBOR_FIELD',
        'Pinned owner fields are disallowed when ownerTargetKind is open-owner-binding',
      );
    }
    ownerTarget = { kind: 'open-owner-binding' };
  } else {
    throw new ChmExchangeError(
      'INVALID_OWNER_TARGET',
      `Unknown ownerTargetKind: ${String(targetKindCode)}`,
    );
  }

  const nonce = assertExactBytes(map.get(8), PAIRING_NONCE_BYTES, 'nonce');
  const issuedAt = assertSafeIntegerInRange(map.get(9), 0, Number.MAX_SAFE_INTEGER, 'issuedAt');
  const expiresAt = assertSafeIntegerInRange(
    map.get(10),
    issuedAt + 1,
    issuedAt + MAX_PAIRING_TTL_SECONDS,
    'expiresAt',
  );
  const permissions = validatePairingPermissions(map.get(11));

  let ownerLabelHint: string | undefined;
  if (map.has(12)) {
    ownerLabelHint = sanitizeRequiredDisplayName(map.get(12), 'ownerLabelHint');
  }

  const signingMsg = buildPairingRequestSigningMessage(payloadBytes);
  if (!verifyStrictEd25519Signature(devicePublicKey, signingMsg, signature)) {
    throw new ChmExchangeError(
      'INVALID_SIGNATURE',
      'Pairing request proof-of-possession Ed25519 signature verification failed',
    );
  }

  const requestHash = sha256Sync(envelopeBytes);
  const fp = computePublicKeyFingerprintSync(devicePublicKey);

  return {
    envelopeBytes: new Uint8Array(envelopeBytes),
    payloadBytes,
    signature,
    requestHash,
    requestHashHex: bytesToHex(requestHash),
    token: `${PAIRING_REQUEST_TOKEN_PREFIX}${base64UrlEncode(envelopeBytes)}`,
    payload: {
      version: CHM_DEVICE_PAIRING_VERSION,
      protocol: CHM_DEVICE_PAIRING_PROTOCOL_ID,
      requestId,
      requestIdHex: formatUuidHex(requestId),
      deviceId,
      deviceIdHex: formatUuidHex(deviceId),
      devicePublicKey,
      devicePublicKeyBase64Url: base64UrlEncode(devicePublicKey),
      deviceFingerprintHex: fp.fullHex,
      deviceFingerprintShort: fp.shortDisplay,
      deviceDisplayName,
      ownerTarget,
      ownerLabelHint,
      nonce,
      nonceHex: bytesToHex(nonce),
      issuedAt,
      expiresAt,
      permissions,
    },
  };
}

export async function createSignedEnrollmentCertificate(params: {
  request: SignedPairingRequest;
  ownerPublicKey: Uint8Array | string;
  ownerDisplayName: string;
  signWithOwnerKey: PairingSignerFn;
  grantedPermissions?: DevicePermission[];
  issuedAt?: number;
  nowUnix?: number;
  clockSkewSeconds?: number;
}): Promise<SignedEnrollmentCertificate> {
  // Re-verify the request strictly from canonical bytes so forged objects cannot bypass validation
  const verifiedRequest = decodeAndVerifyPairingRequestBytes(params.request.envelopeBytes);
  const ownerPublicKey = assertStrictEd25519PublicKey(params.ownerPublicKey, 'ownerPublicKey');
  const ownerDisplayName = sanitizeRequiredDisplayName(params.ownerDisplayName, 'ownerDisplayName');

  if (constantTimeEqual(ownerPublicKey, verifiedRequest.payload.devicePublicKey)) {
    throw new ChmExchangeError(
      'DEVICE_CANNOT_BE_OWNER',
      'Owner public key cannot match the enrolling device public key',
    );
  }

  const ownerFpBytes = sha256Sync(ownerPublicKey);
  const target = verifiedRequest.payload.ownerTarget;
  if (target.kind === 'pinned-public-key' && !constantTimeEqual(target.ownerPublicKey, ownerPublicKey)) {
    throw new ChmExchangeError(
      'OWNER_MISMATCH',
      'This pairing request is pinned to a different Owner public key',
    );
  }
  if (
    target.kind === 'pinned-fingerprint' &&
    !constantTimeEqual(target.ownerFingerprint, ownerFpBytes)
  ) {
    throw new ChmExchangeError(
      'OWNER_MISMATCH',
      'This pairing request is pinned to a different Owner fingerprint',
    );
  }

  const nowUnix = params.nowUnix ?? params.issuedAt ?? Math.floor(Date.now() / 1000);
  const clockSkew = params.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
  if (nowUnix > verifiedRequest.payload.expiresAt) {
    throw new ChmExchangeError('PAIRING_REQUEST_EXPIRED', 'Cannot approve an expired pairing request');
  }
  if (verifiedRequest.payload.issuedAt > nowUnix + clockSkew) {
    throw new ChmExchangeError(
      'PAIRING_REQUEST_NOT_YET_VALID',
      'Pairing request issuedAt is too far in the future',
    );
  }

  const permissions = validatePairingPermissions(
    params.grantedPermissions ?? verifiedRequest.payload.permissions,
  );
  // Cannot grant a permission not requested
  for (const perm of permissions) {
    if (!verifiedRequest.payload.permissions.includes(perm)) {
      throw new ChmExchangeError(
        'PRIVILEGE_ESCALATION_FORBIDDEN',
        `Granted permission "${perm}" was not requested by the device`,
      );
    }
  }

  const certId = generatePairingUuidBytes();
  const issuedAt = assertSafeIntegerInRange(
    params.issuedAt ?? nowUnix,
    0,
    Number.MAX_SAFE_INTEGER,
    'issuedAt',
  );

  const map = new Map<number, unknown>();
  map.set(1, certId);
  map.set(2, verifiedRequest.payload.requestId);
  map.set(3, verifiedRequest.requestHash);
  map.set(4, verifiedRequest.payload.nonce);
  map.set(5, ownerPublicKey);
  map.set(6, ownerDisplayName);
  map.set(7, verifiedRequest.payload.deviceId);
  map.set(8, verifiedRequest.payload.devicePublicKey);
  map.set(9, verifiedRequest.payload.deviceDisplayName);
  map.set(10, permissions);
  map.set(11, issuedAt);
  map.set(12, verifiedRequest.payload.expiresAt);

  const payloadBytes = encodeCanonicalCbor(map);
  const signingMsg = buildEnrollmentCertificateSigningMessage(payloadBytes);
  const rawSig = await params.signWithOwnerKey(signingMsg);
  const signature = assertExactBytes(rawSig, ED25519_SIGNATURE_BYTES, 'ownerSignature');
  if (!verifyStrictEd25519Signature(ownerPublicKey, signingMsg, signature)) {
    throw new ChmExchangeError(
      'INVALID_SIGNATURE',
      'Produced enrollment certificate signature failed verification against ownerPublicKey',
    );
  }

  const envelopeBytes = encodePairingEnvelope(
    PAIRING_ENVELOPE_KIND.CERTIFICATE,
    payloadBytes,
    signature,
  );
  const ownerFp = computePublicKeyFingerprintSync(ownerPublicKey);
  const deviceFp = computePublicKeyFingerprintSync(verifiedRequest.payload.devicePublicKey);

  return {
    envelopeBytes,
    payloadBytes,
    signature,
    token: `${ENROLLMENT_CERT_TOKEN_PREFIX}${base64UrlEncode(envelopeBytes)}`,
    payload: {
      version: CHM_DEVICE_PAIRING_VERSION,
      protocol: CHM_DEVICE_PAIRING_PROTOCOL_ID,
      certId,
      certIdHex: formatUuidHex(certId),
      requestId: verifiedRequest.payload.requestId,
      requestIdHex: verifiedRequest.payload.requestIdHex,
      requestHash: verifiedRequest.requestHash,
      requestHashHex: verifiedRequest.requestHashHex,
      nonce: verifiedRequest.payload.nonce,
      nonceHex: verifiedRequest.payload.nonceHex,
      ownerPublicKey,
      ownerPublicKeyBase64Url: base64UrlEncode(ownerPublicKey),
      ownerFingerprintHex: ownerFp.fullHex,
      ownerFingerprintShort: ownerFp.shortDisplay,
      ownerDisplayName,
      deviceId: verifiedRequest.payload.deviceId,
      deviceIdHex: verifiedRequest.payload.deviceIdHex,
      devicePublicKey: verifiedRequest.payload.devicePublicKey,
      devicePublicKeyBase64Url: verifiedRequest.payload.devicePublicKeyBase64Url,
      deviceFingerprintHex: deviceFp.fullHex,
      deviceFingerprintShort: deviceFp.shortDisplay,
      deviceDisplayName: verifiedRequest.payload.deviceDisplayName,
      permissions,
      issuedAt,
      requestExpiresAt: verifiedRequest.payload.expiresAt,
    },
  };
}

export function decodeAndVerifyEnrollmentCertificateBytes(
  envelopeBytes: Uint8Array,
): SignedEnrollmentCertificate {
  const { payloadBytes, signature } = decodePairingEnvelope(
    envelopeBytes,
    PAIRING_ENVELOPE_KIND.CERTIFICATE,
  );
  const decoded = decodeCanonicalCbor(payloadBytes, 'enrollment certificate payload');
  const map = assertAllowedIntegerMapKeys(decoded, ALLOWED_CERT_KEYS, 'enrollment certificate');

  const certId = assertExactBytes(map.get(1), PAIRING_UUID_BYTES, 'certId');
  const requestId = assertExactBytes(map.get(2), PAIRING_UUID_BYTES, 'requestId');
  const requestHash = assertExactBytes(map.get(3), 32, 'requestHash');
  const nonce = assertExactBytes(map.get(4), PAIRING_NONCE_BYTES, 'nonce');
  const ownerPublicKey = assertStrictEd25519PublicKey(
    assertExactBytes(map.get(5), 32, 'ownerPublicKey'),
    'ownerPublicKey',
  );
  const ownerDisplayName = sanitizeRequiredDisplayName(map.get(6), 'ownerDisplayName');
  const deviceId = assertExactBytes(map.get(7), PAIRING_UUID_BYTES, 'deviceId');
  const devicePublicKey = assertStrictEd25519PublicKey(
    assertExactBytes(map.get(8), 32, 'devicePublicKey'),
    'devicePublicKey',
  );
  if (constantTimeEqual(ownerPublicKey, devicePublicKey)) {
    throw new ChmExchangeError(
      'DEVICE_CANNOT_BE_OWNER',
      'Enrollment certificate ownerPublicKey cannot equal devicePublicKey',
    );
  }
  const deviceDisplayName = sanitizeRequiredDisplayName(map.get(9), 'deviceDisplayName');
  const permissions = validatePairingPermissions(map.get(10));
  const issuedAt = assertSafeIntegerInRange(map.get(11), 0, Number.MAX_SAFE_INTEGER, 'issuedAt');
  const requestExpiresAt = assertSafeIntegerInRange(
    map.get(12),
    1,
    Number.MAX_SAFE_INTEGER,
    'requestExpiresAt',
  );

  const signingMsg = buildEnrollmentCertificateSigningMessage(payloadBytes);
  if (!verifyStrictEd25519Signature(ownerPublicKey, signingMsg, signature)) {
    throw new ChmExchangeError(
      'INVALID_SIGNATURE',
      'Enrollment certificate Ed25519 signature verification failed',
    );
  }

  const ownerFp = computePublicKeyFingerprintSync(ownerPublicKey);
  const deviceFp = computePublicKeyFingerprintSync(devicePublicKey);

  return {
    envelopeBytes: new Uint8Array(envelopeBytes),
    payloadBytes,
    signature,
    token: `${ENROLLMENT_CERT_TOKEN_PREFIX}${base64UrlEncode(envelopeBytes)}`,
    payload: {
      version: CHM_DEVICE_PAIRING_VERSION,
      protocol: CHM_DEVICE_PAIRING_PROTOCOL_ID,
      certId,
      certIdHex: formatUuidHex(certId),
      requestId,
      requestIdHex: formatUuidHex(requestId),
      requestHash,
      requestHashHex: bytesToHex(requestHash),
      nonce,
      nonceHex: bytesToHex(nonce),
      ownerPublicKey,
      ownerPublicKeyBase64Url: base64UrlEncode(ownerPublicKey),
      ownerFingerprintHex: ownerFp.fullHex,
      ownerFingerprintShort: ownerFp.shortDisplay,
      ownerDisplayName,
      deviceId,
      deviceIdHex: formatUuidHex(deviceId),
      devicePublicKey,
      devicePublicKeyBase64Url: base64UrlEncode(devicePublicKey),
      deviceFingerprintHex: deviceFp.fullHex,
      deviceFingerprintShort: deviceFp.shortDisplay,
      deviceDisplayName,
      permissions,
      issuedAt,
      requestExpiresAt,
    },
  };
}

export function verifyEnrollmentCertificateBinding(params: {
  certificate: SignedEnrollmentCertificate | Uint8Array;
  expectedRequest?: SignedPairingRequest | Uint8Array;
  expectedDevicePublicKey?: Uint8Array | string;
  expectedOwnerPublicKey?: Uint8Array | string;
  expectedOwnerFingerprintHex?: string;
  trustedOwnerPublicKeys?: ReadonlyArray<Uint8Array | string>;
  nowUnix?: number;
  clockSkewSeconds?: number;
  enforceRequestExpiry?: boolean;
  isReplayConsumed?: (info: { requestIdHex: string; nonceHex: string }) => boolean;
}): VerifiedPairingBindingResult {
  const cert =
    params.certificate instanceof Uint8Array
      ? decodeAndVerifyEnrollmentCertificateBytes(params.certificate)
      : decodeAndVerifyEnrollmentCertificateBytes(params.certificate.envelopeBytes);

  const req =
    params.expectedRequest === undefined
      ? undefined
      : params.expectedRequest instanceof Uint8Array
        ? decodeAndVerifyPairingRequestBytes(params.expectedRequest)
        : decodeAndVerifyPairingRequestBytes(params.expectedRequest.envelopeBytes);

  const errors: string[] = [];
  const warnings: string[] = [];
  const nowUnix = params.nowUnix ?? Math.floor(Date.now() / 1000);
  const skew = params.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
  const enforceRequestExpiry = params.enforceRequestExpiry ?? true;

  let requestBindingValid: boolean | undefined;
  let ownerMatchValid = true;
  let deviceMatchValid = true;

  if (req) {
    const hashOk = constantTimeEqual(cert.payload.requestHash, req.requestHash);
    const reqIdOk = constantTimeEqual(cert.payload.requestId, req.payload.requestId);
    const nonceOk = constantTimeEqual(cert.payload.nonce, req.payload.nonce);
    const devIdOk = constantTimeEqual(cert.payload.deviceId, req.payload.deviceId);
    const devPkOk = constantTimeEqual(cert.payload.devicePublicKey, req.payload.devicePublicKey);
    const expOk = cert.payload.requestExpiresAt === req.payload.expiresAt;
    const permOk = cert.payload.permissions.every((p) => req.payload.permissions.includes(p));

    requestBindingValid = hashOk && reqIdOk && nonceOk && devIdOk && devPkOk && expOk && permOk;
    if (!hashOk) errors.push('Enrollment certificate requestHash does not match the pairing request.');
    if (!reqIdOk || !nonceOk) errors.push('Enrollment certificate requestId or nonce mismatch.');
    if (!devIdOk || !devPkOk) {
      deviceMatchValid = false;
      errors.push('Enrollment certificate targets a different device identity or public key.');
    }
    if (!expOk) errors.push('Enrollment certificate expiration timestamp diverges from request.');
    if (!permOk) errors.push('Enrollment certificate escalates permissions beyond request.');

    if (req.payload.ownerTarget.kind === 'pinned-public-key') {
      if (!constantTimeEqual(req.payload.ownerTarget.ownerPublicKey, cert.payload.ownerPublicKey)) {
        ownerMatchValid = false;
        errors.push('Certificate signer does not match pinned Owner public key in request.');
      }
    } else if (req.payload.ownerTarget.kind === 'pinned-fingerprint') {
      const certOwnerFp = sha256Sync(cert.payload.ownerPublicKey);
      if (!constantTimeEqual(req.payload.ownerTarget.ownerFingerprint, certOwnerFp)) {
        ownerMatchValid = false;
        errors.push('Certificate signer does not match pinned Owner fingerprint in request.');
      }
    }
  }

  if (params.expectedDevicePublicKey !== undefined) {
    const expectedDev = assertStrictEd25519PublicKey(
      params.expectedDevicePublicKey,
      'expectedDevicePublicKey',
    );
    if (!constantTimeEqual(cert.payload.devicePublicKey, expectedDev)) {
      deviceMatchValid = false;
      errors.push('Enrollment certificate does not belong to this device public key.');
    }
  }

  if (params.expectedOwnerPublicKey !== undefined) {
    const expectedOwner = assertStrictEd25519PublicKey(
      params.expectedOwnerPublicKey,
      'expectedOwnerPublicKey',
    );
    if (!constantTimeEqual(cert.payload.ownerPublicKey, expectedOwner)) {
      ownerMatchValid = false;
      errors.push('Enrollment certificate was issued by a different Owner public key.');
    }
  }

  if (params.expectedOwnerFingerprintHex !== undefined) {
    const cleanHex = params.expectedOwnerFingerprintHex.trim().toLowerCase();
    if (!constantTimeEqualAscii(cert.payload.ownerFingerprintHex, cleanHex)) {
      ownerMatchValid = false;
      errors.push('Enrollment certificate owner fingerprint does not match expected Owner ID.');
    }
  }

  let notExpired = true;
  if (enforceRequestExpiry && nowUnix > cert.payload.requestExpiresAt) {
    notExpired = false;
    errors.push('Pairing session expired before enrollment completion.');
  }
  if (cert.payload.issuedAt > nowUnix + skew) {
    notExpired = false;
    errors.push('Enrollment certificate issuedAt timestamp is beyond allowed clock skew.');
  }
  if (req && req.payload.issuedAt > nowUnix + skew) {
    notExpired = false;
    errors.push('Pairing request issuedAt timestamp is beyond allowed clock skew.');
  }

  let replayCheckPassed = true;
  if (
    params.isReplayConsumed &&
    params.isReplayConsumed({
      requestIdHex: cert.payload.requestIdHex,
      nonceHex: cert.payload.nonceHex,
    })
  ) {
    replayCheckPassed = false;
    errors.push('Pairing request ID or nonce has already been consumed or invalidated.');
  }

  // Determine whether the Owner identity is already locally trusted (NEVER auto-promote)
  let ownerTrustStatus: OwnerTrustStatus = 'unverified';
  if (params.trustedOwnerPublicKeys && params.trustedOwnerPublicKeys.length > 0) {
    for (const candidate of params.trustedOwnerPublicKeys) {
      try {
        const candidateBytes = assertStrictEd25519PublicKey(candidate);
        if (constantTimeEqual(candidateBytes, cert.payload.ownerPublicKey)) {
          ownerTrustStatus = 'trusted';
          break;
        }
      } catch {
        // Ignore invalid entries
      }
    }
  }

  if (ownerTrustStatus === 'unverified') {
    warnings.push(
      'Owner public key is not yet in this device’s local Trusted Owners list; verify the Owner fingerprint before confirming.',
    );
  }

  return {
    valid: errors.length === 0,
    checks: {
      requestSignatureValid: req ? true : undefined,
      certificateSignatureValid: true,
      requestBindingValid,
      ownerMatchValid,
      deviceMatchValid,
      permissionsValid: true,
      notExpired,
      replayCheckPassed,
      ownerTrustStatus,
    },
    errors,
    warnings,
    certificate: cert,
    request: req,
  };
}

export async function createSignedDeviceRevocationNotice(params: {
  ownerPublicKey: Uint8Array | string;
  signWithOwnerKey: PairingSignerFn;
  deviceId: Uint8Array;
  devicePublicKey: Uint8Array | string;
  reason: DeviceRevocationReason;
  sequence?: number;
  revokedAt?: number;
  note?: string;
}): Promise<SignedDeviceRevocationNotice> {
  const noticeId = generatePairingUuidBytes();
  const ownerPublicKey = assertStrictEd25519PublicKey(params.ownerPublicKey, 'ownerPublicKey');
  const deviceId = assertExactBytes(params.deviceId, PAIRING_UUID_BYTES, 'deviceId');
  const devicePublicKey = assertStrictEd25519PublicKey(params.devicePublicKey, 'devicePublicKey');
  if (constantTimeEqual(ownerPublicKey, devicePublicKey)) {
    throw new ChmExchangeError(
      'DEVICE_CANNOT_BE_OWNER',
      'Revoked device public key cannot equal owner public key',
    );
  }
  const reasonCode = REVOCATION_REASON_TO_CODE[params.reason];
  if (!reasonCode) {
    throw new ChmExchangeError('INVALID_REVOCATION_REASON', `Invalid revocation reason: ${String(params.reason)}`);
  }
  const sequence = assertSafeIntegerInRange(
    params.sequence ?? 1,
    1,
    Number.MAX_SAFE_INTEGER,
    'sequence',
  );
  const revokedAt = assertSafeIntegerInRange(
    params.revokedAt ?? Math.floor(Date.now() / 1000),
    0,
    Number.MAX_SAFE_INTEGER,
    'revokedAt',
  );
  const note = sanitizeOptionalPairingNote(params.note);

  const map = new Map<number, unknown>();
  map.set(1, noticeId);
  map.set(2, ownerPublicKey);
  map.set(3, deviceId);
  map.set(4, devicePublicKey);
  map.set(5, revokedAt);
  map.set(6, sequence);
  map.set(7, reasonCode);
  if (note !== undefined) {
    map.set(8, note);
  }

  const payloadBytes = encodeCanonicalCbor(map);
  const signingMsg = buildDeviceRevocationSigningMessage(payloadBytes);
  const rawSig = await params.signWithOwnerKey(signingMsg);
  const signature = assertExactBytes(rawSig, ED25519_SIGNATURE_BYTES, 'ownerSignature');
  if (!verifyStrictEd25519Signature(ownerPublicKey, signingMsg, signature)) {
    throw new ChmExchangeError(
      'INVALID_SIGNATURE',
      'Device revocation notice signature verification failed against ownerPublicKey',
    );
  }

  const envelopeBytes = encodePairingEnvelope(
    PAIRING_ENVELOPE_KIND.REVOCATION,
    payloadBytes,
    signature,
  );
  const ownerFp = computePublicKeyFingerprintSync(ownerPublicKey);
  const deviceFp = computePublicKeyFingerprintSync(devicePublicKey);

  return {
    envelopeBytes,
    payloadBytes,
    signature,
    token: `${DEVICE_REVOCATION_TOKEN_PREFIX}${base64UrlEncode(envelopeBytes)}`,
    payload: {
      version: CHM_DEVICE_PAIRING_VERSION,
      protocol: CHM_DEVICE_PAIRING_PROTOCOL_ID,
      noticeId,
      noticeIdHex: formatUuidHex(noticeId),
      ownerPublicKey,
      ownerPublicKeyBase64Url: base64UrlEncode(ownerPublicKey),
      ownerFingerprintHex: ownerFp.fullHex,
      ownerFingerprintShort: ownerFp.shortDisplay,
      deviceId,
      deviceIdHex: formatUuidHex(deviceId),
      devicePublicKey,
      devicePublicKeyBase64Url: base64UrlEncode(devicePublicKey),
      deviceFingerprintHex: deviceFp.fullHex,
      deviceFingerprintShort: deviceFp.shortDisplay,
      revokedAt,
      sequence,
      reason: params.reason,
      note,
    },
  };
}

export function decodeAndVerifyDeviceRevocationBytes(
  envelopeBytes: Uint8Array,
): SignedDeviceRevocationNotice {
  const { payloadBytes, signature } = decodePairingEnvelope(
    envelopeBytes,
    PAIRING_ENVELOPE_KIND.REVOCATION,
  );
  const decoded = decodeCanonicalCbor(payloadBytes, 'device revocation payload');
  const map = assertAllowedIntegerMapKeys(decoded, ALLOWED_REVOKE_KEYS, 'device revocation notice');

  const noticeId = assertExactBytes(map.get(1), PAIRING_UUID_BYTES, 'noticeId');
  const ownerPublicKey = assertStrictEd25519PublicKey(
    assertExactBytes(map.get(2), 32, 'ownerPublicKey'),
    'ownerPublicKey',
  );
  const deviceId = assertExactBytes(map.get(3), PAIRING_UUID_BYTES, 'deviceId');
  const devicePublicKey = assertStrictEd25519PublicKey(
    assertExactBytes(map.get(4), 32, 'devicePublicKey'),
    'devicePublicKey',
  );
  if (constantTimeEqual(ownerPublicKey, devicePublicKey)) {
    throw new ChmExchangeError(
      'DEVICE_CANNOT_BE_OWNER',
      'Revocation ownerPublicKey cannot equal devicePublicKey',
    );
  }
  const revokedAt = assertSafeIntegerInRange(map.get(5), 0, Number.MAX_SAFE_INTEGER, 'revokedAt');
  const sequence = assertSafeIntegerInRange(map.get(6), 1, Number.MAX_SAFE_INTEGER, 'sequence');
  const reasonCode = map.get(7);
  const reason = typeof reasonCode === 'number' ? CODE_TO_REVOCATION_REASON[reasonCode] : undefined;
  if (!reason) {
    throw new ChmExchangeError('INVALID_REVOCATION_REASON', 'Unknown revocation reason code');
  }

  let note: string | undefined;
  if (map.has(8)) {
    note = sanitizeOptionalPairingNote(map.get(8));
    if (note === undefined) {
      throw new ChmExchangeError('INVALID_NOTE', 'Revocation note cannot be empty when present');
    }
  }

  const signingMsg = buildDeviceRevocationSigningMessage(payloadBytes);
  if (!verifyStrictEd25519Signature(ownerPublicKey, signingMsg, signature)) {
    throw new ChmExchangeError(
      'INVALID_SIGNATURE',
      'Device revocation notice Ed25519 signature verification failed',
    );
  }

  const ownerFp = computePublicKeyFingerprintSync(ownerPublicKey);
  const deviceFp = computePublicKeyFingerprintSync(devicePublicKey);

  return {
    envelopeBytes: new Uint8Array(envelopeBytes),
    payloadBytes,
    signature,
    token: `${DEVICE_REVOCATION_TOKEN_PREFIX}${base64UrlEncode(envelopeBytes)}`,
    payload: {
      version: CHM_DEVICE_PAIRING_VERSION,
      protocol: CHM_DEVICE_PAIRING_PROTOCOL_ID,
      noticeId,
      noticeIdHex: formatUuidHex(noticeId),
      ownerPublicKey,
      ownerPublicKeyBase64Url: base64UrlEncode(ownerPublicKey),
      ownerFingerprintHex: ownerFp.fullHex,
      ownerFingerprintShort: ownerFp.shortDisplay,
      deviceId,
      deviceIdHex: formatUuidHex(deviceId),
      devicePublicKey,
      devicePublicKeyBase64Url: base64UrlEncode(devicePublicKey),
      deviceFingerprintHex: deviceFp.fullHex,
      deviceFingerprintShort: deviceFp.shortDisplay,
      revokedAt,
      sequence,
      reason,
      note,
    },
  };
}

function extractHashParam(rawInput: string, paramNames: string[]): { key: string; value: string } | null {
  const trimmed = rawInput.trim();
  if (!trimmed) return null;

  if (trimmed.length > MAX_PAIRING_QR_URL_CHARS) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Pairing QR/URL input exceeds maximum ${MAX_PAIRING_QR_URL_CHARS} characters`,
    );
  }

  let fragment: string | null = null;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed) && !trimmed.startsWith('chm-pair-')) {
    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new ChmExchangeError('INVALID_URL', 'Pairing input is not a valid URL');
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      throw new ChmExchangeError(
        'UNSAFE_URL_SCHEME',
        `Unsupported URL scheme "${parsed.protocol}"`,
      );
    }
    fragment = parsed.hash.startsWith('#') ? parsed.hash.slice(1) : parsed.hash;
  } else if (trimmed.includes('#')) {
    fragment = trimmed.slice(trimmed.indexOf('#') + 1);
  } else if (paramNames.some((n) => trimmed.startsWith(`${n}=`))) {
    fragment = trimmed;
  }

  if (!fragment) return null;
  const search = new URLSearchParams(fragment);
  for (const name of paramNames) {
    const val = search.get(name);
    if (val) {
      return { key: name, value: val };
    }
  }
  return null;
}

export function encodePairingRequestUrl(
  request: SignedPairingRequest,
  baseUrl: string = DEFAULT_DEVICES_BASE_URL,
): string {
  const cleanBase = sanitizeExchangeBaseUrl(baseUrl);
  const b64 = base64UrlEncode(request.envelopeBytes);
  const url = `${cleanBase}#pair-req=${b64}`;
  if (url.length > MAX_PAIRING_QR_URL_CHARS) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Pairing request URL exceeds maximum ${MAX_PAIRING_QR_URL_CHARS} characters`,
    );
  }
  return url;
}

export function encodeEnrollmentCertificateUrl(
  certificate: SignedEnrollmentCertificate,
  baseUrl: string = DEFAULT_DEVICES_BASE_URL,
): string {
  const cleanBase = sanitizeExchangeBaseUrl(baseUrl);
  const b64 = base64UrlEncode(certificate.envelopeBytes);
  const url = `${cleanBase}#pair-cert=${b64}`;
  if (url.length > MAX_PAIRING_QR_URL_CHARS) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Enrollment certificate URL exceeds maximum ${MAX_PAIRING_QR_URL_CHARS} characters`,
    );
  }
  return url;
}

export function encodeDeviceRevocationUrl(
  revocation: SignedDeviceRevocationNotice,
  baseUrl: string = DEFAULT_DEVICES_BASE_URL,
): string {
  const cleanBase = sanitizeExchangeBaseUrl(baseUrl);
  const b64 = base64UrlEncode(revocation.envelopeBytes);
  const url = `${cleanBase}#pair-rev=${b64}`;
  if (url.length > MAX_PAIRING_QR_URL_CHARS) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Device revocation URL exceeds maximum ${MAX_PAIRING_QR_URL_CHARS} characters`,
    );
  }
  return url;
}

export function parsePairingQrInput(rawInput: string | Uint8Array): ParsedPairingQrArtifact {
  if (rawInput instanceof Uint8Array) {
    const outer = decodeCanonicalCbor(rawInput, 'binary pairing artifact');
    if (!Array.isArray(outer) || outer.length !== 5) {
      throw new ChmExchangeError('INVALID_PAIRING_ENVELOPE', 'Malformed pairing CBOR envelope');
    }
    const kind = outer[2];
    if (kind === PAIRING_ENVELOPE_KIND.REQUEST) {
      return { kind: 'pairing-request', request: decodeAndVerifyPairingRequestBytes(rawInput) };
    }
    if (kind === PAIRING_ENVELOPE_KIND.CERTIFICATE) {
      return {
        kind: 'enrollment-certificate',
        certificate: decodeAndVerifyEnrollmentCertificateBytes(rawInput),
      };
    }
    if (kind === PAIRING_ENVELOPE_KIND.REVOCATION) {
      return {
        kind: 'device-revocation',
        revocation: decodeAndVerifyDeviceRevocationBytes(rawInput),
      };
    }
    if (kind === PAIRING_ENVELOPE_KIND.REGISTRY) {
      return { kind: 'device-registry', envelopeBytes: new Uint8Array(rawInput) };
    }
    throw new ChmExchangeError('WRONG_PAIRING_MESSAGE_KIND', `Unknown pairing kind: ${String(kind)}`);
  }

  if (typeof rawInput !== 'string') {
    throw new ChmExchangeError('INVALID_INPUT', 'Pairing input must be a string or Uint8Array');
  }
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new ChmExchangeError('EMPTY_INPUT', 'Pairing input is empty');
  }
  if (trimmed.length > MAX_PAIRING_QR_URL_CHARS) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      `Pairing input exceeds maximum ${MAX_PAIRING_QR_URL_CHARS} characters`,
    );
  }

  const hashParam = extractHashParam(trimmed, ['pair-req', 'pair-cert', 'pair-rev']);
  if (hashParam) {
    if (hashParam.value.length > MAX_PAIRING_TOKEN_CHARS) {
      throw new ChmExchangeError(
        'PAYLOAD_TOO_LARGE',
        `Pairing token exceeds maximum ${MAX_PAIRING_TOKEN_CHARS} characters`,
      );
    }
    const bytes = base64UrlDecode(hashParam.value);
    if (hashParam.key === 'pair-req') {
      return { kind: 'pairing-request', request: decodeAndVerifyPairingRequestBytes(bytes) };
    }
    if (hashParam.key === 'pair-cert') {
      return {
        kind: 'enrollment-certificate',
        certificate: decodeAndVerifyEnrollmentCertificateBytes(bytes),
      };
    }
    return { kind: 'device-revocation', revocation: decodeAndVerifyDeviceRevocationBytes(bytes) };
  }

  if (trimmed.startsWith(PAIRING_REQUEST_TOKEN_PREFIX)) {
    const b64 = trimmed.slice(PAIRING_REQUEST_TOKEN_PREFIX.length).trim();
    return {
      kind: 'pairing-request',
      request: decodeAndVerifyPairingRequestBytes(base64UrlDecode(b64)),
    };
  }
  if (trimmed.startsWith(ENROLLMENT_CERT_TOKEN_PREFIX)) {
    const b64 = trimmed.slice(ENROLLMENT_CERT_TOKEN_PREFIX.length).trim();
    return {
      kind: 'enrollment-certificate',
      certificate: decodeAndVerifyEnrollmentCertificateBytes(base64UrlDecode(b64)),
    };
  }
  if (trimmed.startsWith(DEVICE_REVOCATION_TOKEN_PREFIX)) {
    const b64 = trimmed.slice(DEVICE_REVOCATION_TOKEN_PREFIX.length).trim();
    return {
      kind: 'device-revocation',
      revocation: decodeAndVerifyDeviceRevocationBytes(base64UrlDecode(b64)),
    };
  }

  throw new ChmExchangeError(
    'UNRECOGNIZED_PAIRING_INPUT',
    'Input is not a valid CHM-DEVICE-PAIRING-v1 request, certificate, or revocation token/URL',
  );
}
