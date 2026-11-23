import type {
  CHM_EXCHANGE_ALGORITHM,
  CHM_EXCHANGE_FORMAT,
  CHM_EXCHANGE_PROTOCOL_VERSION,
  CHM_HOST_EXPORT_FORMAT,
} from './constants.js';
import type { PairedDeviceRegistryEntry } from './pairing/types.js';

export type ExchangeBundleFormat = typeof CHM_EXCHANGE_FORMAT | typeof CHM_HOST_EXPORT_FORMAT;

/**
 * Canonical CHM-Exchange public-key bundle (v1).
 * Contains ONLY public metadata — never private key material.
 */
export interface ChmPublicKeyBundle {
  format: typeof CHM_EXCHANGE_FORMAT;
  version: typeof CHM_EXCHANGE_PROTOCOL_VERSION;
  algorithm: typeof CHM_EXCHANGE_ALGORITHM;
  publicKey: string;
  fingerprint: string;
  displayName?: string;
  exportedAt?: string;
}

/**
 * Certified Handmade host-compatible public-key export JSON (v1).
 */
export interface CertifiedHandmadePublicKeyJson {
  format: typeof CHM_HOST_EXPORT_FORMAT;
  version: typeof CHM_EXCHANGE_PROTOCOL_VERSION;
  algorithm: typeof CHM_EXCHANGE_ALGORITHM;
  publicKey: string;
  fingerprint: string;
  label: string;
  exportedAt: string;
}

export type PublicKeyImportSource =
  | 'exchange-url'
  | 'exchange-token'
  | 'exchange-json'
  | 'host-json'
  | 'raw-public-key';

/**
 * Result of strictly parsing, validating, and locally recomputing
 * the fingerprint of any imported public-key input.
 */
export interface VerifiedPublicKeyImport {
  publicKeyBytes: Uint8Array;
  publicKeyBase64Url: string;
  fingerprintHex: string;
  fingerprintShort: string;
  displayName?: string;
  exportedAt?: string;
  sourceKind: PublicKeyImportSource;
  sourceVersion: number | null;
  bundle: ChmPublicKeyBundle;
}

/**
 * Public-only signing identity descriptor provided by the host adapter.
 * MUST NOT contain private keys, CryptoKey handles, or encrypted seeds.
 */
export interface HostSigningIdentity {
  id: string;
  displayName: string;
  publicKeyBase64Url: string;
  fingerprintHex: string;
  fingerprintShort: string;
  createdAt?: string;
}

/**
 * Public-only descriptor of the local device identity (never root private key).
 */
export interface HostDeviceIdentity {
  deviceIdHex: string;
  deviceName: string;
  publicKeyBase64Url: string;
  fingerprintHex: string;
  fingerprintShort: string;
  storageMode: 'webcrypto-non-extractable' | 'noble-encrypted-seed';
  createdAt?: string;
}

/**
 * Locally trusted artist key record managed by the host application.
 */
export interface HostTrustedKey {
  publicKeyBase64Url: string;
  fingerprintHex: string;
  fingerprintShort: string;
  displayName: string;
  note?: string;
  addedAt: string;
}

export interface AddTrustedKeyRequest {
  publicKeyBase64Url: string;
  fingerprintHex: string;
  displayName: string;
  note?: string;
}

export interface TrustStatusResult {
  trusted: boolean;
  record?: HostTrustedKey;
}

/**
 * Framework-independent adapter boundary between CHM-Exchange and its host application.
 * All private-key generation, signing, and encrypted backups remain strictly on the host side.
 */
export interface ChmExchangeHostAdapter {
  listPublicIdentities(): Promise<HostSigningIdentity[]>;
  getPublicIdentity?(id: string): Promise<HostSigningIdentity | null>;
  listTrustedKeys(): Promise<HostTrustedKey[]>;
  getTrustStatus(publicKeyBase64Url: string): Promise<TrustStatusResult>;
  addTrustedKey(request: AddTrustedKeyRequest): Promise<HostTrustedKey>;
  removeTrustedKey(publicKeyBase64Url: string): Promise<void>;
  getLocalDeviceIdentity?(): Promise<HostDeviceIdentity | null>;
  listPairedDevices?(ownerFingerprintHex?: string): Promise<PairedDeviceRegistryEntry[]>;
}

export class ChmExchangeError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'ChmExchangeError';
    this.code = code;
  }
}

export class UnsupportedExchangeVersionError extends ChmExchangeError {
  readonly version: unknown;

  constructor(version: unknown) {
    super(
      'UNSUPPORTED_VERSION',
      `Unsupported CHM-Exchange protocol version: ${String(version)}`,
    );
    this.name = 'UnsupportedExchangeVersionError';
    this.version = version;
  }
}
