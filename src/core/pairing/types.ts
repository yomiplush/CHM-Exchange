import { ChmExchangeError } from '../types.js';
import type {
  ALLOWED_PAIRING_PERMISSIONS_V1,
  CHM_DEVICE_PAIRING_PROTOCOL_ID,
  CHM_DEVICE_PAIRING_VERSION,
  CHM_DEVICE_REGISTRY_FORMAT,
} from './constants.js';

export type DevicePermission = (typeof ALLOWED_PAIRING_PERMISSIONS_V1)[number];

export type DeviceRevocationReason =
  | 'lost-device'
  | 'device-compromised'
  | 'retired'
  | 'other';

export type OwnerTrustStatus = 'trusted' | 'unverified';

export type DeviceLocalVerificationStatus =
  | 'active-trusted'
  | 'active-unverified-owner'
  | 'revoked'
  | 'conflict-revoked';

export type OwnerTarget =
  | {
      kind: 'pinned-public-key';
      ownerPublicKey: Uint8Array;
      ownerFingerprint: Uint8Array;
    }
  | {
      kind: 'pinned-fingerprint';
      ownerFingerprint: Uint8Array;
    }
  | {
      kind: 'open-owner-binding';
    };

export interface PairingRequestPayload {
  version: typeof CHM_DEVICE_PAIRING_VERSION;
  protocol: typeof CHM_DEVICE_PAIRING_PROTOCOL_ID;
  requestId: Uint8Array; // 16 bytes UUIDv4
  requestIdHex: string;
  deviceId: Uint8Array; // 16 bytes UUIDv4
  deviceIdHex: string;
  devicePublicKey: Uint8Array; // 32 bytes
  devicePublicKeyBase64Url: string;
  deviceFingerprintHex: string;
  deviceFingerprintShort: string;
  deviceDisplayName: string;
  ownerTarget: OwnerTarget;
  ownerLabelHint?: string;
  nonce: Uint8Array; // 32 bytes
  nonceHex: string;
  issuedAt: number; // Unix seconds
  expiresAt: number; // Unix seconds
  permissions: DevicePermission[];
}

export interface SignedPairingRequest {
  envelopeBytes: Uint8Array;
  payloadBytes: Uint8Array;
  signature: Uint8Array; // 64 bytes
  requestHash: Uint8Array; // 32 bytes SHA-256(envelopeBytes)
  requestHashHex: string;
  token: string;
  payload: PairingRequestPayload;
}

export interface EnrollmentCertificatePayload {
  version: typeof CHM_DEVICE_PAIRING_VERSION;
  protocol: typeof CHM_DEVICE_PAIRING_PROTOCOL_ID;
  certId: Uint8Array; // 16 bytes
  certIdHex: string;
  requestId: Uint8Array; // 16 bytes
  requestIdHex: string;
  requestHash: Uint8Array; // 32 bytes SHA-256(canonical request envelope)
  requestHashHex: string;
  nonce: Uint8Array; // 32 bytes
  nonceHex: string;
  ownerPublicKey: Uint8Array; // 32 bytes
  ownerPublicKeyBase64Url: string;
  ownerFingerprintHex: string;
  ownerFingerprintShort: string;
  ownerDisplayName: string;
  deviceId: Uint8Array; // 16 bytes
  deviceIdHex: string;
  devicePublicKey: Uint8Array; // 32 bytes
  devicePublicKeyBase64Url: string;
  deviceFingerprintHex: string;
  deviceFingerprintShort: string;
  deviceDisplayName: string;
  permissions: DevicePermission[];
  issuedAt: number;
  requestExpiresAt: number;
}

export interface SignedEnrollmentCertificate {
  envelopeBytes: Uint8Array;
  payloadBytes: Uint8Array;
  signature: Uint8Array; // 64 bytes
  token: string;
  payload: EnrollmentCertificatePayload;
}

export interface DeviceRevocationNoticePayload {
  version: typeof CHM_DEVICE_PAIRING_VERSION;
  protocol: typeof CHM_DEVICE_PAIRING_PROTOCOL_ID;
  noticeId: Uint8Array; // 16 bytes
  noticeIdHex: string;
  ownerPublicKey: Uint8Array; // 32 bytes
  ownerPublicKeyBase64Url: string;
  ownerFingerprintHex: string;
  ownerFingerprintShort: string;
  deviceId: Uint8Array; // 16 bytes
  deviceIdHex: string;
  devicePublicKey: Uint8Array; // 32 bytes
  devicePublicKeyBase64Url: string;
  deviceFingerprintHex: string;
  deviceFingerprintShort: string;
  revokedAt: number;
  sequence: number;
  reason: DeviceRevocationReason;
  note?: string;
}

export interface SignedDeviceRevocationNotice {
  envelopeBytes: Uint8Array;
  payloadBytes: Uint8Array;
  signature: Uint8Array; // 64 bytes
  token: string;
  payload: DeviceRevocationNoticePayload;
}

export interface DeviceRegistrySnapshotPayload {
  version: typeof CHM_DEVICE_PAIRING_VERSION;
  protocol: typeof CHM_DEVICE_PAIRING_PROTOCOL_ID;
  snapshotId: Uint8Array; // 16 bytes
  snapshotIdHex: string;
  ownerPublicKey: Uint8Array;
  ownerPublicKeyBase64Url: string;
  ownerFingerprintHex: string;
  ownerFingerprintShort: string;
  ownerDisplayName: string;
  exportedAt: number;
  sequence: number;
  certificates: SignedEnrollmentCertificate[];
  revocations: SignedDeviceRevocationNotice[];
}

export interface SignedDeviceRegistrySnapshot {
  envelopeBytes: Uint8Array;
  payloadBytes: Uint8Array;
  signature: Uint8Array;
  token: string;
  payload: DeviceRegistrySnapshotPayload;
}

export interface PortableDeviceRegistryJson {
  format: typeof CHM_DEVICE_REGISTRY_FORMAT;
  version: typeof CHM_DEVICE_PAIRING_VERSION;
  protocol: typeof CHM_DEVICE_PAIRING_PROTOCOL_ID;
  ownerPublicKey: string;
  ownerFingerprint: string;
  ownerDisplayName: string;
  exportedAt: string;
  sequence: number;
  envelopeBase64Url: string;
  token: string;
}

export type PairingSignerFn = (message: Uint8Array) => Promise<Uint8Array> | Uint8Array;

export interface PairingVerificationChecks {
  requestSignatureValid?: boolean;
  certificateSignatureValid: boolean;
  requestBindingValid?: boolean;
  ownerMatchValid: boolean;
  deviceMatchValid: boolean;
  permissionsValid: boolean;
  notExpired: boolean;
  replayCheckPassed: boolean;
  ownerTrustStatus: OwnerTrustStatus;
}

export interface VerifiedPairingBindingResult {
  valid: boolean;
  checks: PairingVerificationChecks;
  errors: string[];
  warnings: string[];
  certificate: SignedEnrollmentCertificate;
  request?: SignedPairingRequest;
}

export interface PairedDeviceRegistryEntry {
  ownerFingerprintHex: string;
  ownerFingerprintShort: string;
  ownerPublicKeyBase64Url: string;
  ownerDisplayName: string;
  deviceIdHex: string;
  devicePublicKeyBase64Url: string;
  deviceFingerprintHex: string;
  deviceFingerprintShort: string;
  deviceName: string;
  permissions: DevicePermission[];
  issuedAt: number;
  enrollmentToken: string;
  revocationNoticeToken?: string;
  revokedAt?: number;
  revocationReason?: DeviceRevocationReason;
  revocationSequence?: number;
  localVerificationStatus: DeviceLocalVerificationStatus;
}

export interface VerifiedRegistryReconciliationResult {
  valid: boolean;
  snapshot: SignedDeviceRegistrySnapshot;
  ownerTrustStatus: OwnerTrustStatus;
  entries: PairedDeviceRegistryEntry[];
  preservedLocalRevocations: number;
  newlyAppliedRevocations: number;
  rejectedStaleOrConflicting: string[];
  errors: string[];
  warnings: string[];
}

export type ParsedPairingQrArtifact =
  | { kind: 'pairing-request'; request: SignedPairingRequest }
  | { kind: 'enrollment-certificate'; certificate: SignedEnrollmentCertificate }
  | { kind: 'device-revocation'; revocation: SignedDeviceRevocationNotice }
  | { kind: 'device-registry'; envelopeBytes: Uint8Array };

export class UnsupportedPairingVersionError extends ChmExchangeError {
  readonly version: unknown;

  constructor(version: unknown) {
    super(
      'UNSUPPORTED_PAIRING_VERSION',
      `Unsupported CHM device pairing protocol version: ${String(version)}`,
    );
    this.name = 'UnsupportedPairingVersionError';
    this.version = version;
  }
}
