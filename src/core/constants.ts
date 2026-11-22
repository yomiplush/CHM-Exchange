export const CHM_EXCHANGE_PROTOCOL_VERSION = 1 as const;
export const CHM_EXCHANGE_FORMAT = 'chm-exchange-public-key' as const;
export const CHM_HOST_EXPORT_FORMAT = 'certified-handmade-public-key' as const;
export const CHM_EXCHANGE_ALGORITHM = 'Ed25519' as const;

export const DEFAULT_EXCHANGE_BASE_URL = 'https://certified-handmade.com/exchange';

export const ED25519_PUBLIC_KEY_BYTES = 32;
export const SHA256_DIGEST_BYTES = 32;
export const SHA256_HEX_CHARS = 64;

export const MAX_DISPLAY_NAME_UTF8_BYTES = 64;
export const MAX_TRUST_NOTE_UTF8_BYTES = 200;
export const MAX_EXCHANGE_BUNDLE_BYTES = 1024;
export const MAX_EXCHANGE_TOKEN_CHARS = 2048;
export const MAX_EXCHANGE_URL_CHARS = 4096;
export const MAX_EXCHANGE_JSON_BYTES = 4096;

export const MAX_QR_IMAGE_FILE_BYTES = 25 * 1024 * 1024; // 25 MB
export const MAX_QR_IMAGE_DIMENSION = 8192;
export const MAX_QR_IMAGE_PIXELS = 33_554_432; // 32 MP

export const FORBIDDEN_PRIVATE_KEYS = new Set<string>([
  'privateKey',
  'private_key',
  'secretKey',
  'secret_key',
  'seed',
  'seed32',
  'seedHex',
  'pkcs8',
  'jwk',
  'webCryptoPrivateKey',
  'encryptedBackup',
  'encrypted_backup',
  'passphrase',
  'ciphertext',
  'salt',
  'iv',
  'd',
  'private',
  'secret',
]);
