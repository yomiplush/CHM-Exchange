import { base64UrlEncode } from './encoding.js';
import { computePublicKeyFingerprintSync } from './fingerprint.js';
import type {
  AddTrustedKeyRequest,
  ChmExchangeHostAdapter,
  HostSigningIdentity,
  HostTrustedKey,
  TrustStatusResult,
} from './types.js';
import {
  decodeAndValidateEd25519PublicKey,
  sanitizeDisplayName,
  sanitizeTrustNote,
  stripToPublicHostIdentity,
} from './validation.js';

export interface MemoryAdapterOptions {
  identities?: HostSigningIdentity[];
  trustedKeys?: HostTrustedKey[];
}

/**
 * In-memory reference ChmExchangeHostAdapter for standalone demos and tests.
 * Enforces duplicate prevention, strict validation, and public-only boundaries.
 */
export function createMemoryExchangeAdapter(
  initial: MemoryAdapterOptions = {},
): ChmExchangeHostAdapter {
  const identities = new Map<string, HostSigningIdentity>();
  const trusted = new Map<string, HostTrustedKey>();

  for (const id of initial.identities ?? []) {
    const clean = stripToPublicHostIdentity(id);
    identities.set(clean.id, clean);
  }

  for (const tk of initial.trustedKeys ?? []) {
    const bytes = decodeAndValidateEd25519PublicKey(tk.publicKeyBase64Url);
    const canonicalKey = base64UrlEncode(bytes);
    const fp = computePublicKeyFingerprintSync(bytes);
    trusted.set(canonicalKey, {
      publicKeyBase64Url: canonicalKey,
      fingerprintHex: fp.fullHex,
      fingerprintShort: fp.shortDisplay,
      displayName: sanitizeDisplayName(tk.displayName, 'displayName') ?? 'Trusted Artist',
      note: sanitizeTrustNote(tk.note),
      addedAt: tk.addedAt,
    });
  }

  return {
    async listPublicIdentities(): Promise<HostSigningIdentity[]> {
      return Array.from(identities.values());
    },

    async getPublicIdentity(id: string): Promise<HostSigningIdentity | null> {
      return identities.get(id) ?? null;
    },

    async listTrustedKeys(): Promise<HostTrustedKey[]> {
      return Array.from(trusted.values()).sort((a, b) => b.addedAt.localeCompare(a.addedAt));
    },

    async getTrustStatus(publicKeyBase64Url: string): Promise<TrustStatusResult> {
      const bytes = decodeAndValidateEd25519PublicKey(publicKeyBase64Url);
      const canonical = base64UrlEncode(bytes);
      const record = trusted.get(canonical);
      return record ? { trusted: true, record } : { trusted: false };
    },

    async addTrustedKey(request: AddTrustedKeyRequest): Promise<HostTrustedKey> {
      const bytes = decodeAndValidateEd25519PublicKey(request.publicKeyBase64Url);
      const canonical = base64UrlEncode(bytes);
      const fp = computePublicKeyFingerprintSync(bytes);
      const record: HostTrustedKey = {
        publicKeyBase64Url: canonical,
        fingerprintHex: fp.fullHex,
        fingerprintShort: fp.shortDisplay,
        displayName:
          sanitizeDisplayName(request.displayName, 'displayName') ?? 'Trusted Artist',
        note: sanitizeTrustNote(request.note),
        addedAt: new Date().toISOString(),
      };
      trusted.set(canonical, record);
      return record;
    },

    async removeTrustedKey(publicKeyBase64Url: string): Promise<void> {
      const bytes = decodeAndValidateEd25519PublicKey(publicKeyBase64Url);
      const canonical = base64UrlEncode(bytes);
      trusted.delete(canonical);
    },
  };
}
