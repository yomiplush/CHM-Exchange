export const CHM_DEVICE_PAIRING_PROTOCOL_ID = 'CHM-DEVICE-PAIRING-v1' as const;
export const CHM_DEVICE_PAIRING_VERSION = 1 as const;
export const CHM_DEVICE_REGISTRY_FORMAT = 'chm-device-registry' as const;

export const PAIRING_ENVELOPE_KIND = {
  REQUEST: 1,
  CERTIFICATE: 2,
  REVOCATION: 3,
  REGISTRY: 4,
} as const;

export const OWNER_TARGET_KIND = {
  PINNED_PUBLIC_KEY: 1,
  PINNED_FINGERPRINT: 2,
  OPEN_OWNER_BINDING: 3,
} as const;

// Domain-separated Ed25519 signing prefixes (null-terminated ASCII)
export const PAIRING_REQUEST_DOMAIN_PREFIX = new Uint8Array([
  // "CHM-DEVICE-PAIRING-v1:REQ\0"
  0x43, 0x48, 0x4d, 0x2d, 0x44, 0x45, 0x56, 0x49, 0x43, 0x45, 0x2d, 0x50, 0x41,
  0x49, 0x52, 0x49, 0x4e, 0x47, 0x2d, 0x76, 0x31, 0x3a, 0x52, 0x45, 0x51, 0x00,
]);

export const ENROLLMENT_CERT_DOMAIN_PREFIX = new Uint8Array([
  // "CHM-DEVICE-PAIRING-v1:CERT\0"
  0x43, 0x48, 0x4d, 0x2d, 0x44, 0x45, 0x56, 0x49, 0x43, 0x45, 0x2d, 0x50, 0x41,
  0x49, 0x52, 0x49, 0x4e, 0x47, 0x2d, 0x76, 0x31, 0x3a, 0x43, 0x45, 0x52, 0x54,
  0x00,
]);

export const DEVICE_REVOCATION_DOMAIN_PREFIX = new Uint8Array([
  // "CHM-DEVICE-PAIRING-v1:REVOKE\0"
  0x43, 0x48, 0x4d, 0x2d, 0x44, 0x45, 0x56, 0x49, 0x43, 0x45, 0x2d, 0x50, 0x41,
  0x49, 0x52, 0x49, 0x4e, 0x47, 0x2d, 0x76, 0x31, 0x3a, 0x52, 0x45, 0x56, 0x4f,
  0x4b, 0x45, 0x00,
]);

export const DEVICE_REGISTRY_DOMAIN_PREFIX = new Uint8Array([
  // "CHM-DEVICE-PAIRING-v1:REGISTRY\0"
  0x43, 0x48, 0x4d, 0x2d, 0x44, 0x45, 0x56, 0x49, 0x43, 0x45, 0x2d, 0x50, 0x41,
  0x49, 0x52, 0x49, 0x4e, 0x47, 0x2d, 0x76, 0x31, 0x3a, 0x52, 0x45, 0x47, 0x49,
  0x53, 0x54, 0x52, 0x59, 0x00,
]);

export const PAIRING_UUID_BYTES = 16;
export const PAIRING_NONCE_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;

export const DEFAULT_PAIRING_TTL_SECONDS = 300; // 5 minutes
export const MAX_PAIRING_TTL_SECONDS = 3600; // 1 hour hard upper bound
export const DEFAULT_CLOCK_SKEW_SECONDS = 120; // 2 minutes clock skew tolerance

export const MAX_DEVICE_DISPLAY_NAME_UTF8_BYTES = 64;
export const MAX_PAIRING_NOTE_UTF8_BYTES = 160;
export const MAX_PAIRING_CBOR_BYTES = 2048;
export const MAX_PAIRING_TOKEN_CHARS = 3072;
export const MAX_PAIRING_QR_URL_CHARS = 4096;
export const MAX_REGISTRY_EXPORT_BYTES = 262_144; // 256 KiB

export const PAIRING_REQUEST_TOKEN_PREFIX = 'chm-pair-req:' as const;
export const ENROLLMENT_CERT_TOKEN_PREFIX = 'chm-pair-cert:' as const;
export const DEVICE_REVOCATION_TOKEN_PREFIX = 'chm-pair-rev:' as const;
export const DEVICE_REGISTRY_TOKEN_PREFIX = 'chm-pair-reg:' as const;

export const DEFAULT_DEVICES_BASE_URL = 'https://certified-handmade.com/devices';

/**
 * In CHM-DEVICE-PAIRING-v1, paired devices only receive non-privileged
 * `device-identity` capability. Root signing, artwork signing delegation,
 * and delegated device approval are intentionally disabled in v1.
 */
export const ALLOWED_PAIRING_PERMISSIONS_V1 = ['device-identity'] as const;
export const RESERVED_PRIVILEGED_PERMISSIONS = new Set<string>([
  'root-signing',
  'artwork-signing',
  'device-approval',
  'key-revocation',
  'admin',
  '*',
]);
