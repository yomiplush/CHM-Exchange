import { encode as cborEncode } from 'cborg';
import { describe, expect, it } from 'vitest';
import {
  ALLOWED_PAIRING_PERMISSIONS_V1,
  CHM_DEVICE_PAIRING_PROTOCOL_ID,
  CHM_DEVICE_PAIRING_VERSION,
  ChmExchangeError,
  MAX_PAIRING_QR_URL_CHARS,
  MAX_PAIRING_TTL_SECONDS,
  PAIRING_ENVELOPE_KIND,
  UnsupportedPairingVersionError,
  assertStrictEd25519PublicKey,
  base64UrlDecode,
  base64UrlEncode,
  createSignedDeviceRegistrySnapshot,
  createSignedDeviceRevocationNotice,
  createSignedEnrollmentCertificate,
  createSignedPairingRequest,
  decodeAndVerifyDeviceRegistryInput,
  decodeAndVerifyEnrollmentCertificateBytes,
  decodeAndVerifyPairingRequestBytes,
  encodeDeviceRevocationUrl,
  encodeEnrollmentCertificateUrl,
  encodePairingRequestUrl,
  generateEd25519TestKeypairSync,
  parsePairingQrInput,
  reconcileRegistrySnapshotImport,
  serializeDeviceRegistryJson,
  signEd25519WithSeedSync,
  verifyEnrollmentCertificateBinding,
  verifyStrictEd25519Signature,
} from '../../src/core.js';

describe('CHM-DEVICE-PAIRING-v1 Cryptographic Protocol & Security', () => {
  const fixedNow = 1_800_000_000;

  it('rejects all-zero, small-order, and invalid Ed25519 public keys', () => {
    const zero = new Uint8Array(32);
    const smallOrderOne = new Uint8Array(32);
    smallOrderOne[0] = 1; // Ed25519 torsion point of order 1/8

    expect(() => assertStrictEd25519PublicKey(zero)).toThrow(ChmExchangeError);
    expect(() => assertStrictEd25519PublicKey(smallOrderOne)).toThrow(ChmExchangeError);
    expect(() => assertStrictEd25519PublicKey(new Uint8Array(31).fill(5))).toThrow(
      ChmExchangeError,
    );

    const msg = new TextEncoder().encode('test');
    expect(verifyStrictEd25519Signature(zero, msg, new Uint8Array(64))).toBe(false);
    expect(verifyStrictEd25519Signature(smallOrderOne, msg, new Uint8Array(64))).toBe(false);
  });

  it('completes full 2-step QR pairing round-trip for PC (Owner) -> iPhone & iPad', async () => {
    const owner = generateEd25519TestKeypairSync();
    const iphone = generateEd25519TestKeypairSync();
    const ipad = generateEd25519TestKeypairSync();

    // Step 1 (iPhone): create signed pairing request with 256-bit nonce & 5-minute TTL
    const reqIphone = await createSignedPairingRequest({
      devicePublicKey: iphone.publicKey32,
      deviceDisplayName: 'iPhone 16 Pro',
      signWithDeviceKey: (msg) => signEd25519WithSeedSync(iphone.seed32, msg),
      ownerPublicKey: owner.publicKey32,
      issuedAt: fixedNow,
    });

    expect(reqIphone.payload.version).toBe(CHM_DEVICE_PAIRING_VERSION);
    expect(reqIphone.payload.protocol).toBe(CHM_DEVICE_PAIRING_PROTOCOL_ID);
    expect(reqIphone.payload.nonce).toHaveLength(32);
    expect(reqIphone.payload.expiresAt).toBe(fixedNow + 300);
    expect(reqIphone.payload.permissions).toEqual(['device-identity']);

    const reqQrUrl = encodePairingRequestUrl(reqIphone, 'https://certified-handmade.com/devices');
    expect(reqQrUrl).toContain('#pair-req=');
    const parsedReqArtifact = parsePairingQrInput(reqQrUrl);
    expect(parsedReqArtifact.kind).toBe('pairing-request');
    if (parsedReqArtifact.kind !== 'pairing-request') throw new Error('Expected request');

    // Step 2 (Owner PC): verify request, approve after explicit consent, issue Enrollment Certificate
    const certIphone = await createSignedEnrollmentCertificate({
      request: parsedReqArtifact.request,
      ownerPublicKey: owner.publicKey32,
      ownerDisplayName: 'YomiPlush Studio',
      signWithOwnerKey: (msg) => signEd25519WithSeedSync(owner.seed32, msg),
      nowUnix: fixedNow + 15,
      issuedAt: fixedNow + 15,
    });

    const certQrUrl = encodeEnrollmentCertificateUrl(certIphone);
    const parsedCertArtifact = parsePairingQrInput(certQrUrl);
    expect(parsedCertArtifact.kind).toBe('enrollment-certificate');
    if (parsedCertArtifact.kind !== 'enrollment-certificate') {
      throw new Error('Expected certificate');
    }

    // New device (iPhone) verifies binding against its pending request; owner starts unverified unless pre-trusted
    const verifiedUntrustedOwner = verifyEnrollmentCertificateBinding({
      certificate: parsedCertArtifact.certificate,
      expectedRequest: reqIphone,
      expectedDevicePublicKey: iphone.publicKey32,
      nowUnix: fixedNow + 30,
    });
    expect(verifiedUntrustedOwner.valid).toBe(true);
    expect(verifiedUntrustedOwner.checks.ownerTrustStatus).toBe('unverified');

    // When Owner is explicitly trusted locally
    const verifiedTrustedOwner = verifyEnrollmentCertificateBinding({
      certificate: parsedCertArtifact.certificate,
      expectedRequest: reqIphone,
      expectedDevicePublicKey: iphone.publicKey32,
      trustedOwnerPublicKeys: [owner.publicKey32],
      nowUnix: fixedNow + 30,
    });
    expect(verifiedTrustedOwner.valid).toBe(true);
    expect(verifiedTrustedOwner.checks.ownerTrustStatus).toBe('trusted');

    // Second device (iPad) using open-owner-binding mode
    const reqIpad = await createSignedPairingRequest({
      devicePublicKey: ipad.publicKey32,
      deviceDisplayName: 'iPad Air',
      signWithDeviceKey: (msg) => signEd25519WithSeedSync(ipad.seed32, msg),
      issuedAt: fixedNow + 60,
    });
    expect(reqIpad.payload.ownerTarget.kind).toBe('open-owner-binding');
    const certIpad = await createSignedEnrollmentCertificate({
      request: reqIpad,
      ownerPublicKey: owner.publicKey32,
      ownerDisplayName: 'YomiPlush Studio',
      signWithOwnerKey: (msg) => signEd25519WithSeedSync(owner.seed32, msg),
      nowUnix: fixedNow + 70,
    });
    expect(
      verifyEnrollmentCertificateBinding({
        certificate: certIpad,
        expectedRequest: reqIpad,
        expectedDevicePublicKey: ipad.publicKey32,
        nowUnix: fixedNow + 80,
      }).valid,
    ).toBe(true);
  });

  it('rejects tampered pairing requests and tampered enrollment certificates', async () => {
    const owner = generateEd25519TestKeypairSync();
    const device = generateEd25519TestKeypairSync();

    const req = await createSignedPairingRequest({
      devicePublicKey: device.publicKey32,
      deviceDisplayName: 'Studio Tablet',
      signWithDeviceKey: (msg) => signEd25519WithSeedSync(device.seed32, msg),
      issuedAt: fixedNow,
    });

    const tamperedReqBytes = new Uint8Array(req.envelopeBytes);
    tamperedReqBytes[tamperedReqBytes.length - 1] ^= 0xff;
    expect(() => decodeAndVerifyPairingRequestBytes(tamperedReqBytes)).toThrow(/signature/i);

    // Tamper inside payload bytes (flip signature mismatch)
    const cert = await createSignedEnrollmentCertificate({
      request: req,
      ownerPublicKey: owner.publicKey32,
      ownerDisplayName: 'Owner',
      signWithOwnerKey: (msg) => signEd25519WithSeedSync(owner.seed32, msg),
      nowUnix: fixedNow + 10,
    });
    const tamperedCertBytes = new Uint8Array(cert.envelopeBytes);
    tamperedCertBytes[tamperedCertBytes.length - 5] ^= 0x01;
    expect(() => decodeAndVerifyEnrollmentCertificateBytes(tamperedCertBytes)).toThrow(/signature/i);
  });

  it('prevents cross-owner substitution, device=owner confusion, and privilege escalation', async () => {
    const ownerA = generateEd25519TestKeypairSync();
    const ownerB = generateEd25519TestKeypairSync();
    const device = generateEd25519TestKeypairSync();

    const reqForOwnerA = await createSignedPairingRequest({
      devicePublicKey: device.publicKey32,
      deviceDisplayName: 'Artist Phone',
      signWithDeviceKey: (msg) => signEd25519WithSeedSync(device.seed32, msg),
      ownerPublicKey: ownerA.publicKey32,
      issuedAt: fixedNow,
    });

    // Owner B cannot approve a request pinned to Owner A
    await expect(
      createSignedEnrollmentCertificate({
        request: reqForOwnerA,
        ownerPublicKey: ownerB.publicKey32,
        ownerDisplayName: 'Attacker B',
        signWithOwnerKey: (msg) => signEd25519WithSeedSync(ownerB.seed32, msg),
        nowUnix: fixedNow + 5,
      }),
    ).rejects.toThrow(/Owner public key/i);

    // Open request approved by Owner B cannot be accepted when device expects Owner A
    const openReq = await createSignedPairingRequest({
      devicePublicKey: device.publicKey32,
      deviceDisplayName: 'Artist Phone',
      signWithDeviceKey: (msg) => signEd25519WithSeedSync(device.seed32, msg),
      issuedAt: fixedNow,
    });
    const certFromB = await createSignedEnrollmentCertificate({
      request: openReq,
      ownerPublicKey: ownerB.publicKey32,
      ownerDisplayName: 'Owner B',
      signWithOwnerKey: (msg) => signEd25519WithSeedSync(ownerB.seed32, msg),
      nowUnix: fixedNow + 5,
    });
    const crossOwnerCheck = verifyEnrollmentCertificateBinding({
      certificate: certFromB,
      expectedRequest: openReq,
      expectedOwnerPublicKey: ownerA.publicKey32,
      nowUnix: fixedNow + 10,
    });
    expect(crossOwnerCheck.valid).toBe(false);
    expect(crossOwnerCheck.checks.ownerMatchValid).toBe(false);

    // Owner keypair cannot self-enroll as a paired device
    await expect(
      createSignedPairingRequest({
        devicePublicKey: ownerA.publicKey32,
        deviceDisplayName: 'Root Clone',
        signWithDeviceKey: (msg) => signEd25519WithSeedSync(ownerA.seed32, msg),
        ownerPublicKey: ownerA.publicKey32,
      }),
    ).rejects.toThrow(/distinct/i);

    // Privilege escalation blocked
    for (const badPerm of ['root-signing', 'artwork-signing', 'device-approval', 'admin', '*']) {
      await expect(
        createSignedPairingRequest({
          devicePublicKey: device.publicKey32,
          deviceDisplayName: 'Escalated',
          signWithDeviceKey: (msg) => signEd25519WithSeedSync(device.seed32, msg),
          // @ts-expect-error testing runtime rejection of privileged permissions
          permissions: [badPerm],
        }),
      ).rejects.toThrow(/forbidden|unsupported/i);
    }
    expect(ALLOWED_PAIRING_PERMISSIONS_V1).toEqual(['device-identity']);
  });

  it('enforces expiry, future clock skew limits, and replay consumption checks', async () => {
    const owner = generateEd25519TestKeypairSync();
    const device = generateEd25519TestKeypairSync();

    await expect(
      createSignedPairingRequest({
        devicePublicKey: device.publicKey32,
        deviceDisplayName: 'Long TTL',
        signWithDeviceKey: (msg) => signEd25519WithSeedSync(device.seed32, msg),
        ttlSeconds: MAX_PAIRING_TTL_SECONDS + 1,
        issuedAt: fixedNow,
      }),
    ).rejects.toThrow(ChmExchangeError);

    const req = await createSignedPairingRequest({
      devicePublicKey: device.publicKey32,
      deviceDisplayName: 'Expiring Phone',
      signWithDeviceKey: (msg) => signEd25519WithSeedSync(device.seed32, msg),
      ttlSeconds: 300,
      issuedAt: fixedNow,
    });

    // Expired request cannot be approved
    await expect(
      createSignedEnrollmentCertificate({
        request: req,
        ownerPublicKey: owner.publicKey32,
        ownerDisplayName: 'Owner',
        signWithOwnerKey: (msg) => signEd25519WithSeedSync(owner.seed32, msg),
        nowUnix: fixedNow + 301,
      }),
    ).rejects.toThrow(/expired/i);

    const cert = await createSignedEnrollmentCertificate({
      request: req,
      ownerPublicKey: owner.publicKey32,
      ownerDisplayName: 'Owner',
      signWithOwnerKey: (msg) => signEd25519WithSeedSync(owner.seed32, msg),
      nowUnix: fixedNow + 10,
    });

    // Completion rejected once expired
    const expiredCompletion = verifyEnrollmentCertificateBinding({
      certificate: cert,
      expectedRequest: req,
      nowUnix: fixedNow + 301,
    });
    expect(expiredCompletion.valid).toBe(false);
    expect(expiredCompletion.checks.notExpired).toBe(false);

    // Replay check fails even if attacker rolls clock back!
    const consumedNonces = new Set<string>([req.payload.nonceHex]);
    const replayedCheck = verifyEnrollmentCertificateBinding({
      certificate: cert,
      expectedRequest: req,
      nowUnix: fixedNow + 20, // Within expiry window
      isReplayConsumed: ({ nonceHex }) => consumedNonces.has(nonceHex),
    });
    expect(replayedCheck.valid).toBe(false);
    expect(replayedCheck.checks.replayCheckPassed).toBe(false);
  });

  it('rejects non-canonical CBOR, unknown versions, cross-domain swaps, and oversized payloads', async () => {
    const owner = generateEd25519TestKeypairSync();
    const device = generateEd25519TestKeypairSync();

    // Handcrafted non-canonical CBOR (unsorted map keys: {2: 1, 1: 1} -> 0xa2 0x02 0x01 0x01 0x01)
    const nonCanonicalPayload = new Uint8Array([0xa2, 0x02, 0x01, 0x01, 0x01]);
    const sig = signEd25519WithSeedSync(device.seed32, nonCanonicalPayload);
    const badEnvelope = cborEncode([1, CHM_DEVICE_PAIRING_PROTOCOL_ID, PAIRING_ENVELOPE_KIND.REQUEST, nonCanonicalPayload, sig]);
    expect(() => decodeAndVerifyPairingRequestBytes(badEnvelope)).toThrow(/canonical|CBOR/i);

    // Unsupported version
    const futureVersionEnv = cborEncode([
      99,
      CHM_DEVICE_PAIRING_PROTOCOL_ID,
      PAIRING_ENVELOPE_KIND.REQUEST,
      new Uint8Array([0xa0]),
      new Uint8Array(64),
    ]);
    expect(() => decodeAndVerifyPairingRequestBytes(futureVersionEnv)).toThrow(
      UnsupportedPairingVersionError,
    );

    // Cross-domain swap: try passing a request envelope to certificate decoder
    const req = await createSignedPairingRequest({
      devicePublicKey: device.publicKey32,
      deviceDisplayName: 'Phone',
      signWithDeviceKey: (msg) => signEd25519WithSeedSync(device.seed32, msg),
      issuedAt: fixedNow,
    });
    expect(() => decodeAndVerifyEnrollmentCertificateBytes(req.envelopeBytes)).toThrow(
      ChmExchangeError,
    );

    // Oversized URL / unsafe URI schemes / bidi chars
    expect(() =>
      parsePairingQrInput(`https://certified-handmade.com/devices#pair-req=${'A'.repeat(MAX_PAIRING_QR_URL_CHARS)}`),
    ).toThrow(/exceeds maximum/i);
    expect(() => parsePairingQrInput(`javascript:alert(1)#pair-req=${base64UrlEncode(req.envelopeBytes)}`)).toThrow(
      ChmExchangeError,
    );
    await expect(
      createSignedPairingRequest({
        devicePublicKey: device.publicKey32,
        deviceDisplayName: 'iPhone\u202Espoof',
        signWithDeviceKey: (msg) => signEd25519WithSeedSync(device.seed32, msg),
      }),
    ).rejects.toThrow(/control or bidirectional/i);

    // Zero private-key leakage in serialized pairing tokens
    const cert = await createSignedEnrollmentCertificate({
      request: req,
      ownerPublicKey: owner.publicKey32,
      ownerDisplayName: 'Owner',
      signWithOwnerKey: (msg) => signEd25519WithSeedSync(owner.seed32, msg),
      nowUnix: fixedNow + 5,
    });
    expect(req.token).not.toContain(base64UrlEncode(device.seed32));
    expect(cert.token).not.toContain(base64UrlEncode(owner.seed32));
  });

  it('creates/verifies signed revocation notices & enforces monotonic revocation on stale registry imports', async () => {
    const owner = generateEd25519TestKeypairSync();
    const phone = generateEd25519TestKeypairSync();
    const tablet = generateEd25519TestKeypairSync();

    const reqPhone = await createSignedPairingRequest({
      devicePublicKey: phone.publicKey32,
      deviceDisplayName: 'Lost iPhone',
      signWithDeviceKey: (msg) => signEd25519WithSeedSync(phone.seed32, msg),
      issuedAt: fixedNow,
    });
    const certPhone = await createSignedEnrollmentCertificate({
      request: reqPhone,
      ownerPublicKey: owner.publicKey32,
      ownerDisplayName: 'Artist',
      signWithOwnerKey: (msg) => signEd25519WithSeedSync(owner.seed32, msg),
      nowUnix: fixedNow + 5,
    });

    const reqTablet = await createSignedPairingRequest({
      devicePublicKey: tablet.publicKey32,
      deviceDisplayName: 'Studio iPad',
      signWithDeviceKey: (msg) => signEd25519WithSeedSync(tablet.seed32, msg),
      issuedAt: fixedNow + 10,
    });
    const certTablet = await createSignedEnrollmentCertificate({
      request: reqTablet,
      ownerPublicKey: owner.publicKey32,
      ownerDisplayName: 'Artist',
      signWithOwnerKey: (msg) => signEd25519WithSeedSync(owner.seed32, msg),
      nowUnix: fixedNow + 15,
    });

    // Older signed registry export (before phone revocation)
    const staleSnapshot = await createSignedDeviceRegistrySnapshot({
      ownerPublicKey: owner.publicKey32,
      ownerDisplayName: 'Artist',
      signWithOwnerKey: (msg) => signEd25519WithSeedSync(owner.seed32, msg),
      certificates: [certPhone, certTablet],
      revocations: [],
      sequence: 1,
      exportedAt: fixedNow + 20,
    });
    const staleJson = serializeDeviceRegistryJson(staleSnapshot);

    // Owner later revokes Lost iPhone
    const revPhone = await createSignedDeviceRevocationNotice({
      ownerPublicKey: owner.publicKey32,
      signWithOwnerKey: (msg) => signEd25519WithSeedSync(owner.seed32, msg),
      deviceId: certPhone.payload.deviceId,
      devicePublicKey: phone.publicKey32,
      reason: 'lost-device',
      sequence: 2,
      revokedAt: fixedNow + 100,
      note: 'Left on train',
    });

    const parsedRev = parsePairingQrInput(encodeDeviceRevocationUrl(revPhone));
    expect(parsedRev.kind).toBe('device-revocation');

    // Local device registry already has phone marked revoked
    const reconciledAfterStale = reconcileRegistrySnapshotImport({
      input: staleJson,
      existingEntries: [
        {
          ownerFingerprintHex: certPhone.payload.ownerFingerprintHex,
          ownerFingerprintShort: certPhone.payload.ownerFingerprintShort,
          ownerPublicKeyBase64Url: certPhone.payload.ownerPublicKeyBase64Url,
          ownerDisplayName: 'Artist',
          deviceIdHex: certPhone.payload.deviceIdHex,
          devicePublicKeyBase64Url: certPhone.payload.devicePublicKeyBase64Url,
          deviceFingerprintHex: certPhone.payload.deviceFingerprintHex,
          deviceFingerprintShort: certPhone.payload.deviceFingerprintShort,
          deviceName: 'Lost iPhone',
          permissions: ['device-identity'],
          issuedAt: certPhone.payload.issuedAt,
          enrollmentToken: certPhone.token,
          revocationNoticeToken: revPhone.token,
          revokedAt: revPhone.payload.revokedAt,
          revocationReason: revPhone.payload.reason,
          revocationSequence: revPhone.payload.sequence,
          localVerificationStatus: 'revoked',
        },
      ],
      trustedOwnerPublicKeys: [owner.publicKey32],
    });

    const phoneEntry = reconciledAfterStale.entries.find(
      (e) => e.deviceIdHex === certPhone.payload.deviceIdHex,
    );
    const tabletEntry = reconciledAfterStale.entries.find(
      (e) => e.deviceIdHex === certTablet.payload.deviceIdHex,
    );
    expect(phoneEntry?.localVerificationStatus).toBe('revoked');
    expect(reconciledAfterStale.preservedLocalRevocations).toBe(1);
    expect(reconciledAfterStale.rejectedStaleOrConflicting.length).toBeGreaterThan(0);
    expect(tabletEntry?.localVerificationStatus).toBe('active-trusted');

    // Reject private key field injected into JSON registry file
    const maliciousJson = JSON.stringify({
      ...JSON.parse(staleJson),
      privateKey: 'leaked',
    });
    expect(() => decodeAndVerifyDeviceRegistryInput(maliciousJson)).toThrow(/private-key/i);

    // Binary CBOR round-trip
    const decodedBin = decodeAndVerifyDeviceRegistryInput(staleSnapshot.envelopeBytes);
    expect(decodedBin.payload.certificates).toHaveLength(2);
    expect(() => base64UrlDecode(JSON.parse(staleJson).envelopeBase64Url)).not.toThrow();
  });
});
