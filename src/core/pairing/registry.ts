import {
  base64UrlDecode,
  base64UrlEncode,
  constantTimeEqual,
  constantTimeEqualAscii,
  utf8ByteLength,
} from '../encoding.js';
import { computePublicKeyFingerprintSync } from '../fingerprint.js';
import { ChmExchangeError } from '../types.js';
import { assertNoPrivateKeyMaterial } from '../validation.js';
import {
  assertAllowedIntegerMapKeys,
  assertExactBytes,
  assertSafeIntegerInRange,
  decodeCanonicalCbor,
  encodeCanonicalCbor,
  formatUuidHex,
  generatePairingUuidBytes,
} from './cbor.js';
import {
  CHM_DEVICE_PAIRING_PROTOCOL_ID,
  CHM_DEVICE_PAIRING_VERSION,
  CHM_DEVICE_REGISTRY_FORMAT,
  DEVICE_REGISTRY_DOMAIN_PREFIX,
  DEVICE_REGISTRY_TOKEN_PREFIX,
  ED25519_SIGNATURE_BYTES,
  MAX_REGISTRY_EXPORT_BYTES,
  PAIRING_ENVELOPE_KIND,
  PAIRING_UUID_BYTES,
} from './constants.js';
import {
  assertStrictEd25519PublicKey,
  buildDomainSeparatedMessage,
  verifyStrictEd25519Signature,
} from './crypto.js';
import {
  decodeAndVerifyDeviceRevocationBytes,
  decodeAndVerifyEnrollmentCertificateBytes,
  decodePairingEnvelope,
  encodePairingEnvelope,
  sanitizeRequiredDisplayName,
} from './protocol.js';
import type {
  DeviceLocalVerificationStatus,
  OwnerTrustStatus,
  PairedDeviceRegistryEntry,
  PairingSignerFn,
  PortableDeviceRegistryJson,
  SignedDeviceRegistrySnapshot,
  SignedDeviceRevocationNotice,
  SignedEnrollmentCertificate,
  VerifiedRegistryReconciliationResult,
} from './types.js';

const ALLOWED_REGISTRY_PAYLOAD_KEYS = new Set([1, 2, 3, 4, 5, 6, 7]);
const ALLOWED_REGISTRY_JSON_KEYS = new Set([
  'format',
  'version',
  'protocol',
  'ownerPublicKey',
  'ownerFingerprint',
  'ownerDisplayName',
  'exportedAt',
  'sequence',
  'envelopeBase64Url',
  'token',
]);

export function buildDeviceRegistrySigningMessage(payloadBytes: Uint8Array): Uint8Array {
  return buildDomainSeparatedMessage(DEVICE_REGISTRY_DOMAIN_PREFIX, payloadBytes);
}

export async function createSignedDeviceRegistrySnapshot(params: {
  ownerPublicKey: Uint8Array | string;
  ownerDisplayName: string;
  signWithOwnerKey: PairingSignerFn;
  certificates: SignedEnrollmentCertificate[];
  revocations: SignedDeviceRevocationNotice[];
  sequence?: number;
  exportedAt?: number;
}): Promise<SignedDeviceRegistrySnapshot> {
  const snapshotId = generatePairingUuidBytes();
  const ownerPublicKey = assertStrictEd25519PublicKey(params.ownerPublicKey, 'ownerPublicKey');
  const ownerDisplayName = sanitizeRequiredDisplayName(params.ownerDisplayName, 'ownerDisplayName');
  const exportedAt = assertSafeIntegerInRange(
    params.exportedAt ?? Math.floor(Date.now() / 1000),
    0,
    Number.MAX_SAFE_INTEGER,
    'exportedAt',
  );
  const sequence = assertSafeIntegerInRange(
    params.sequence ?? 1,
    1,
    Number.MAX_SAFE_INTEGER,
    'sequence',
  );

  // Deduplicate & verify every included certificate and revocation belongs to ownerPublicKey
  const certMap = new Map<string, SignedEnrollmentCertificate>();
  for (const cert of params.certificates) {
    const verified = decodeAndVerifyEnrollmentCertificateBytes(cert.envelopeBytes);
    if (!constantTimeEqual(verified.payload.ownerPublicKey, ownerPublicKey)) {
      throw new ChmExchangeError(
        'OWNER_MISMATCH',
        'Cannot export certificate issued by a different Owner public key',
      );
    }
    certMap.set(verified.payload.deviceIdHex, verified);
  }

  const revMap = new Map<string, SignedDeviceRevocationNotice>();
  for (const rev of params.revocations) {
    const verified = decodeAndVerifyDeviceRevocationBytes(rev.envelopeBytes);
    if (!constantTimeEqual(verified.payload.ownerPublicKey, ownerPublicKey)) {
      throw new ChmExchangeError(
        'OWNER_MISMATCH',
        'Cannot export revocation notice signed by a different Owner public key',
      );
    }
    const existing = revMap.get(verified.payload.deviceIdHex);
    if (!existing || verified.payload.sequence >= existing.payload.sequence) {
      revMap.set(verified.payload.deviceIdHex, verified);
    }
  }

  const verifiedCerts = Array.from(certMap.values()).sort((a, b) =>
    a.payload.deviceIdHex.localeCompare(b.payload.deviceIdHex),
  );
  const verifiedRevs = Array.from(revMap.values()).sort((a, b) =>
    a.payload.deviceIdHex.localeCompare(b.payload.deviceIdHex),
  );

  const map = new Map<number, unknown>();
  map.set(1, snapshotId);
  map.set(2, ownerPublicKey);
  map.set(3, ownerDisplayName);
  map.set(4, exportedAt);
  map.set(5, sequence);
  map.set(
    6,
    verifiedCerts.map((c) => new Uint8Array(c.envelopeBytes)),
  );
  map.set(
    7,
    verifiedRevs.map((r) => new Uint8Array(r.envelopeBytes)),
  );

  const payloadBytes = encodeCanonicalCbor(map);
  const signingMsg = buildDeviceRegistrySigningMessage(payloadBytes);
  const rawSig = await params.signWithOwnerKey(signingMsg);
  const signature = assertExactBytes(rawSig, ED25519_SIGNATURE_BYTES, 'ownerSignature');
  if (!verifyStrictEd25519Signature(ownerPublicKey, signingMsg, signature)) {
    throw new ChmExchangeError(
      'INVALID_SIGNATURE',
      'Signed device registry snapshot signature failed verification against ownerPublicKey',
    );
  }

  const envelopeBytes = encodePairingEnvelope(
    PAIRING_ENVELOPE_KIND.REGISTRY,
    payloadBytes,
    signature,
    MAX_REGISTRY_EXPORT_BYTES,
  );
  const ownerFp = computePublicKeyFingerprintSync(ownerPublicKey);

  return {
    envelopeBytes,
    payloadBytes,
    signature,
    token: `${DEVICE_REGISTRY_TOKEN_PREFIX}${base64UrlEncode(envelopeBytes)}`,
    payload: {
      version: CHM_DEVICE_PAIRING_VERSION,
      protocol: CHM_DEVICE_PAIRING_PROTOCOL_ID,
      snapshotId,
      snapshotIdHex: formatUuidHex(snapshotId),
      ownerPublicKey,
      ownerPublicKeyBase64Url: base64UrlEncode(ownerPublicKey),
      ownerFingerprintHex: ownerFp.fullHex,
      ownerFingerprintShort: ownerFp.shortDisplay,
      ownerDisplayName,
      exportedAt,
      sequence,
      certificates: verifiedCerts,
      revocations: verifiedRevs,
    },
  };
}

export function toPortableDeviceRegistryJson(
  snapshot: SignedDeviceRegistrySnapshot,
): PortableDeviceRegistryJson {
  const envelopeBase64Url = base64UrlEncode(snapshot.envelopeBytes);
  return {
    format: CHM_DEVICE_REGISTRY_FORMAT,
    version: CHM_DEVICE_PAIRING_VERSION,
    protocol: CHM_DEVICE_PAIRING_PROTOCOL_ID,
    ownerPublicKey: snapshot.payload.ownerPublicKeyBase64Url,
    ownerFingerprint: snapshot.payload.ownerFingerprintHex,
    ownerDisplayName: snapshot.payload.ownerDisplayName,
    exportedAt: new Date(snapshot.payload.exportedAt * 1000).toISOString(),
    sequence: snapshot.payload.sequence,
    envelopeBase64Url,
    token: `${DEVICE_REGISTRY_TOKEN_PREFIX}${envelopeBase64Url}`,
  };
}

export function serializeDeviceRegistryJson(
  snapshot: SignedDeviceRegistrySnapshot,
  pretty = true,
): string {
  const json = JSON.stringify(toPortableDeviceRegistryJson(snapshot), null, pretty ? 2 : undefined);
  if (utf8ByteLength(json) > MAX_REGISTRY_EXPORT_BYTES * 2) {
    throw new ChmExchangeError(
      'PAYLOAD_TOO_LARGE',
      'Serialized device registry JSON exceeds maximum size',
    );
  }
  return json;
}

export function decodeAndVerifyDeviceRegistryBytes(
  envelopeBytes: Uint8Array,
): SignedDeviceRegistrySnapshot {
  const { payloadBytes, signature } = decodePairingEnvelope(
    envelopeBytes,
    PAIRING_ENVELOPE_KIND.REGISTRY,
    MAX_REGISTRY_EXPORT_BYTES,
  );
  const decoded = decodeCanonicalCbor(payloadBytes, 'device registry snapshot');
  const map = assertAllowedIntegerMapKeys(
    decoded,
    ALLOWED_REGISTRY_PAYLOAD_KEYS,
    'device registry snapshot',
  );

  const snapshotId = assertExactBytes(map.get(1), PAIRING_UUID_BYTES, 'snapshotId');
  const ownerPublicKey = assertStrictEd25519PublicKey(
    assertExactBytes(map.get(2), 32, 'ownerPublicKey'),
    'ownerPublicKey',
  );
  const ownerDisplayName = sanitizeRequiredDisplayName(map.get(3), 'ownerDisplayName');
  const exportedAt = assertSafeIntegerInRange(map.get(4), 0, Number.MAX_SAFE_INTEGER, 'exportedAt');
  const sequence = assertSafeIntegerInRange(map.get(5), 1, Number.MAX_SAFE_INTEGER, 'sequence');

  const rawCerts = map.get(6);
  const rawRevs = map.get(7);
  if (!Array.isArray(rawCerts) || !Array.isArray(rawRevs)) {
    throw new ChmExchangeError(
      'INVALID_REGISTRY_SNAPSHOT',
      'Device registry certificates and revocations must be CBOR arrays',
    );
  }

  const signingMsg = buildDeviceRegistrySigningMessage(payloadBytes);
  if (!verifyStrictEd25519Signature(ownerPublicKey, signingMsg, signature)) {
    throw new ChmExchangeError(
      'INVALID_SIGNATURE',
      'Device registry snapshot Ed25519 signature verification failed',
    );
  }

  const certificates: SignedEnrollmentCertificate[] = [];
  for (const item of rawCerts) {
    if (!(item instanceof Uint8Array)) {
      throw new ChmExchangeError('INVALID_REGISTRY_SNAPSHOT', 'Certificate item must be bytes');
    }
    const cert = decodeAndVerifyEnrollmentCertificateBytes(item);
    if (!constantTimeEqual(cert.payload.ownerPublicKey, ownerPublicKey)) {
      throw new ChmExchangeError(
        'OWNER_MISMATCH',
        'Embedded enrollment certificate does not match snapshot Owner public key',
      );
    }
    certificates.push(cert);
  }

  const revocations: SignedDeviceRevocationNotice[] = [];
  for (const item of rawRevs) {
    if (!(item instanceof Uint8Array)) {
      throw new ChmExchangeError('INVALID_REGISTRY_SNAPSHOT', 'Revocation item must be bytes');
    }
    const rev = decodeAndVerifyDeviceRevocationBytes(item);
    if (!constantTimeEqual(rev.payload.ownerPublicKey, ownerPublicKey)) {
      throw new ChmExchangeError(
        'OWNER_MISMATCH',
        'Embedded revocation notice does not match snapshot Owner public key',
      );
    }
    revocations.push(rev);
  }

  const ownerFp = computePublicKeyFingerprintSync(ownerPublicKey);

  return {
    envelopeBytes: new Uint8Array(envelopeBytes),
    payloadBytes,
    signature,
    token: `${DEVICE_REGISTRY_TOKEN_PREFIX}${base64UrlEncode(envelopeBytes)}`,
    payload: {
      version: CHM_DEVICE_PAIRING_VERSION,
      protocol: CHM_DEVICE_PAIRING_PROTOCOL_ID,
      snapshotId,
      snapshotIdHex: formatUuidHex(snapshotId),
      ownerPublicKey,
      ownerPublicKeyBase64Url: base64UrlEncode(ownerPublicKey),
      ownerFingerprintHex: ownerFp.fullHex,
      ownerFingerprintShort: ownerFp.shortDisplay,
      ownerDisplayName,
      exportedAt,
      sequence,
      certificates,
      revocations,
    },
  };
}

export function decodeAndVerifyDeviceRegistryInput(
  input: string | Uint8Array,
): SignedDeviceRegistrySnapshot {
  if (input instanceof Uint8Array) {
    return decodeAndVerifyDeviceRegistryBytes(input);
  }
  if (typeof input !== 'string') {
    throw new ChmExchangeError('INVALID_INPUT', 'Registry import input must be string or Uint8Array');
  }
  const trimmed = input.trim();
  if (!trimmed) {
    throw new ChmExchangeError('EMPTY_INPUT', 'Registry import input is empty');
  }
  if (utf8ByteLength(trimmed) > MAX_REGISTRY_EXPORT_BYTES * 2) {
    throw new ChmExchangeError('PAYLOAD_TOO_LARGE', 'Registry import file exceeds maximum size');
  }

  if (trimmed.startsWith('{')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      throw new ChmExchangeError('MALFORMED_BUNDLE', 'Malformed JSON device registry file');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new ChmExchangeError('MALFORMED_BUNDLE', 'Device registry JSON must be an object');
    }
    assertNoPrivateKeyMaterial(parsed);
    const obj = parsed as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      if (!ALLOWED_REGISTRY_JSON_KEYS.has(key)) {
        throw new ChmExchangeError('UNEXPECTED_FIELD', `Unexpected field "${key}" in device registry JSON`);
      }
    }
    if (obj.format !== CHM_DEVICE_REGISTRY_FORMAT || obj.version !== CHM_DEVICE_PAIRING_VERSION) {
      throw new ChmExchangeError('INVALID_FORMAT', 'Unsupported device registry format or version');
    }
    if (obj.protocol !== CHM_DEVICE_PAIRING_PROTOCOL_ID) {
      throw new ChmExchangeError('UNSUPPORTED_PAIRING_PROTOCOL', 'Unsupported protocol in registry JSON');
    }
    let b64: string;
    if (typeof obj.envelopeBase64Url === 'string' && obj.envelopeBase64Url.trim().length > 0) {
      b64 = obj.envelopeBase64Url.trim();
    } else if (typeof obj.token === 'string' && obj.token.startsWith(DEVICE_REGISTRY_TOKEN_PREFIX)) {
      b64 = obj.token.slice(DEVICE_REGISTRY_TOKEN_PREFIX.length).trim();
    } else {
      throw new ChmExchangeError('MALFORMED_BUNDLE', 'Device registry JSON is missing signed envelopeBase64Url');
    }

    const snapshot = decodeAndVerifyDeviceRegistryBytes(base64UrlDecode(b64));
    if (
      typeof obj.ownerPublicKey === 'string' &&
      !constantTimeEqualAscii(obj.ownerPublicKey.trim(), snapshot.payload.ownerPublicKeyBase64Url)
    ) {
      throw new ChmExchangeError(
        'OWNER_MISMATCH',
        'Registry JSON ownerPublicKey does not match signed CBOR snapshot',
      );
    }
    if (
      typeof obj.ownerFingerprint === 'string' &&
      !constantTimeEqualAscii(
        obj.ownerFingerprint.trim().toLowerCase(),
        snapshot.payload.ownerFingerprintHex,
      )
    ) {
      throw new ChmExchangeError(
        'FINGERPRINT_MISMATCH',
        'Registry JSON ownerFingerprint does not match signed CBOR snapshot',
      );
    }
    return snapshot;
  }

  const token = trimmed.startsWith(DEVICE_REGISTRY_TOKEN_PREFIX)
    ? trimmed.slice(DEVICE_REGISTRY_TOKEN_PREFIX.length).trim()
    : trimmed;
  return decodeAndVerifyDeviceRegistryBytes(base64UrlDecode(token));
}

/**
 * Reconciles an imported signed device registry snapshot with local device entries
 * while strictly enforcing monotonic revocation:
 * - A device already marked revoked locally can NEVER be un-revoked by importing
 *   an older or conflicting signed registry snapshot.
 * - Conflicting revocations or public key collisions for the same deviceId fail safe
 *   to `conflict-revoked`.
 * - Unknown Owner IDs remain `unverified` (`active-unverified-owner`) and are never
 *   auto-promoted to trusted.
 */
export function reconcileRegistrySnapshotImport(params: {
  input: string | Uint8Array;
  existingEntries: PairedDeviceRegistryEntry[];
  trustedOwnerPublicKeys?: ReadonlyArray<Uint8Array | string>;
  expectedOwnerPublicKey?: Uint8Array | string;
}): VerifiedRegistryReconciliationResult {
  const snapshot = decodeAndVerifyDeviceRegistryInput(params.input);
  const errors: string[] = [];
  const warnings: string[] = [];
  const rejectedStaleOrConflicting: string[] = [];

  if (params.expectedOwnerPublicKey !== undefined) {
    const expected = assertStrictEd25519PublicKey(
      params.expectedOwnerPublicKey,
      'expectedOwnerPublicKey',
    );
    if (!constantTimeEqual(snapshot.payload.ownerPublicKey, expected)) {
      throw new ChmExchangeError(
        'OWNER_MISMATCH',
        'Imported device registry belongs to a different Owner public key',
      );
    }
  }

  let ownerTrustStatus: OwnerTrustStatus = 'unverified';
  if (params.trustedOwnerPublicKeys) {
    for (const candidate of params.trustedOwnerPublicKeys) {
      try {
        const pk = assertStrictEd25519PublicKey(candidate);
        if (constantTimeEqual(pk, snapshot.payload.ownerPublicKey)) {
          ownerTrustStatus = 'trusted';
          break;
        }
      } catch {
        // Ignore
      }
    }
  }

  if (ownerTrustStatus === 'unverified') {
    warnings.push(
      'Snapshot signer is not in this device’s local Trusted Owners list; imported entries stay marked unverified-owner.',
    );
  }

  const existingByKey = new Map<string, PairedDeviceRegistryEntry>();
  for (const e of params.existingEntries) {
    existingByKey.set(`${e.ownerFingerprintHex}:${e.deviceIdHex}`, { ...e });
  }

  const revByDevice = new Map<string, SignedDeviceRevocationNotice>();
  for (const rev of snapshot.payload.revocations) {
    const prev = revByDevice.get(rev.payload.deviceIdHex);
    if (!prev || rev.payload.sequence >= prev.payload.sequence) {
      revByDevice.set(rev.payload.deviceIdHex, rev);
    }
  }

  let preservedLocalRevocations = 0;
  let newlyAppliedRevocations = 0;

  // Apply certificates from snapshot without rolling back local revocations or creating key conflicts
  for (const cert of snapshot.payload.certificates) {
    const mapKey = `${cert.payload.ownerFingerprintHex}:${cert.payload.deviceIdHex}`;
    const existing = existingByKey.get(mapKey);
    const snapRev = revByDevice.get(cert.payload.deviceIdHex);

    if (existing) {
      const publicKeyChanged = existing.devicePublicKeyBase64Url !== cert.payload.devicePublicKeyBase64Url;
      const isLocallyRevoked =
        existing.localVerificationStatus === 'revoked' ||
        existing.localVerificationStatus === 'conflict-revoked' ||
        Boolean(existing.revocationNoticeToken);

      if (publicKeyChanged) {
        existing.localVerificationStatus = 'conflict-revoked';
        rejectedStaleOrConflicting.push(
          `Conflicting public key for device ${cert.payload.deviceIdHex}; marked conflict-revoked.`,
        );
        existingByKey.set(mapKey, existing);
        continue;
      }

      if (isLocallyRevoked) {
        preservedLocalRevocations++;
        if (snapRev && (snapRev.payload.sequence > (existing.revocationSequence ?? 0))) {
          existing.revocationNoticeToken = snapRev.token;
          existing.revokedAt = snapRev.payload.revokedAt;
          existing.revocationReason = snapRev.payload.reason;
          existing.revocationSequence = snapRev.payload.sequence;
        } else if (!snapRev) {
          rejectedStaleOrConflicting.push(
            `Ignored stale unrevoked entry for locally revoked device ${cert.payload.deviceDisplayName} (${cert.payload.deviceFingerprintShort}).`,
          );
        }
        existingByKey.set(mapKey, existing);
        continue;
      }
    }

    const baseStatus: DeviceLocalVerificationStatus = snapRev
      ? 'revoked'
      : ownerTrustStatus === 'trusted'
        ? 'active-trusted'
        : 'active-unverified-owner';

    if (snapRev && (!existing || existing.localVerificationStatus !== 'revoked')) {
      newlyAppliedRevocations++;
    }

    existingByKey.set(mapKey, {
      ownerFingerprintHex: cert.payload.ownerFingerprintHex,
      ownerFingerprintShort: cert.payload.ownerFingerprintShort,
      ownerPublicKeyBase64Url: cert.payload.ownerPublicKeyBase64Url,
      ownerDisplayName: cert.payload.ownerDisplayName,
      deviceIdHex: cert.payload.deviceIdHex,
      devicePublicKeyBase64Url: cert.payload.devicePublicKeyBase64Url,
      deviceFingerprintHex: cert.payload.deviceFingerprintHex,
      deviceFingerprintShort: cert.payload.deviceFingerprintShort,
      deviceName: cert.payload.deviceDisplayName,
      permissions: [...cert.payload.permissions],
      issuedAt: cert.payload.issuedAt,
      enrollmentToken: cert.token,
      revocationNoticeToken: snapRev?.token,
      revokedAt: snapRev?.payload.revokedAt,
      revocationReason: snapRev?.payload.reason,
      revocationSequence: snapRev?.payload.sequence,
      localVerificationStatus: baseStatus,
    });
  }

  // Also apply revocation-only entries (even if snapshot omitted certificate)
  for (const rev of revByDevice.values()) {
    const mapKey = `${rev.payload.ownerFingerprintHex}:${rev.payload.deviceIdHex}`;
    const existing = existingByKey.get(mapKey);
    if (existing) {
      if (existing.devicePublicKeyBase64Url !== rev.payload.devicePublicKeyBase64Url) {
        existing.localVerificationStatus = 'conflict-revoked';
        rejectedStaleOrConflicting.push(
          `Conflicting public key on revocation notice for ${rev.payload.deviceIdHex}; marked conflict-revoked.`,
        );
      } else {
        if (existing.localVerificationStatus !== 'revoked') {
          newlyAppliedRevocations++;
        } else {
          preservedLocalRevocations++;
        }
        if (rev.payload.sequence >= (existing.revocationSequence ?? 0)) {
          existing.revocationNoticeToken = rev.token;
          existing.revokedAt = rev.payload.revokedAt;
          existing.revocationReason = rev.payload.reason;
          existing.revocationSequence = rev.payload.sequence;
        }
        if (existing.localVerificationStatus !== 'conflict-revoked') {
          existing.localVerificationStatus = 'revoked';
        }
      }
      existingByKey.set(mapKey, existing);
    } else {
      newlyAppliedRevocations++;
      existingByKey.set(mapKey, {
        ownerFingerprintHex: rev.payload.ownerFingerprintHex,
        ownerFingerprintShort: rev.payload.ownerFingerprintShort,
        ownerPublicKeyBase64Url: rev.payload.ownerPublicKeyBase64Url,
        ownerDisplayName: snapshot.payload.ownerDisplayName,
        deviceIdHex: rev.payload.deviceIdHex,
        devicePublicKeyBase64Url: rev.payload.devicePublicKeyBase64Url,
        deviceFingerprintHex: rev.payload.deviceFingerprintHex,
        deviceFingerprintShort: rev.payload.deviceFingerprintShort,
        deviceName: `Revoked Device (${rev.payload.deviceFingerprintShort})`,
        permissions: ['device-identity'],
        issuedAt: rev.payload.revokedAt,
        enrollmentToken: '',
        revocationNoticeToken: rev.token,
        revokedAt: rev.payload.revokedAt,
        revocationReason: rev.payload.reason,
        revocationSequence: rev.payload.sequence,
        localVerificationStatus: 'revoked',
      });
    }
  }

  if (rejectedStaleOrConflicting.length > 0) {
    warnings.push(...rejectedStaleOrConflicting);
  }

  return {
    valid: errors.length === 0,
    snapshot,
    ownerTrustStatus,
    entries: Array.from(existingByKey.values()).sort((a, b) => b.issuedAt - a.issuedAt),
    preservedLocalRevocations,
    newlyAppliedRevocations,
    rejectedStaleOrConflicting,
    errors,
    warnings,
  };
}
