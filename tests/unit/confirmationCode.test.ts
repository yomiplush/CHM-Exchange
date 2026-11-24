import { describe, expect, it } from 'vitest';
import {
  computePairingConfirmationCode,
  createSignedEnrollmentCertificate,
  createSignedPairingRequest,
  generateEd25519TestKeypairSync,
  signEd25519WithSeedSync,
} from '../../src/core.js';

describe('CHM-DEVICE-PAIRING-v1 Confirmation Code (QR-Swap Defense)', () => {
  it('derives an identical 8-char confirmation code across request, approval cert, and substituted request mismatch', async () => {
    const owner = generateEd25519TestKeypairSync();
    const device = generateEd25519TestKeypairSync();
    const attackerDevice = generateEd25519TestKeypairSync();
    const fixedNow = 1_800_000_000;

    const req = await createSignedPairingRequest({
      devicePublicKey: device.publicKey32,
      deviceDisplayName: 'Studio iPad',
      signWithDeviceKey: (msg) => signEd25519WithSeedSync(device.seed32, msg),
      ownerPublicKey: owner.publicKey32,
      issuedAt: fixedNow,
    });

    const cert = await createSignedEnrollmentCertificate({
      request: req,
      ownerPublicKey: owner.publicKey32,
      ownerDisplayName: 'Artist Studio',
      signWithOwnerKey: (msg) => signEd25519WithSeedSync(owner.seed32, msg),
      nowUnix: fixedNow + 10,
    });

    const reqCode = computePairingConfirmationCode({
      requestHash: req.requestHash,
      nonce: req.payload.nonce,
      devicePublicKey: req.payload.devicePublicKey,
    });
    const certCode = computePairingConfirmationCode({
      requestHash: cert.payload.requestHash,
      nonce: cert.payload.nonce,
      devicePublicKey: cert.payload.devicePublicKey,
    });

    expect(reqCode).toMatch(/^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}$/);
    expect(certCode).toBe(reqCode);

    // Attacker swapping QR with a different request produces a different confirmation code
    const swappedReq = await createSignedPairingRequest({
      devicePublicKey: attackerDevice.publicKey32,
      deviceDisplayName: 'Studio iPad',
      signWithDeviceKey: (msg) => signEd25519WithSeedSync(attackerDevice.seed32, msg),
      ownerPublicKey: owner.publicKey32,
      issuedAt: fixedNow,
    });
    const swappedCode = computePairingConfirmationCode({
      requestHash: swappedReq.requestHash,
      nonce: swappedReq.payload.nonce,
      devicePublicKey: swappedReq.payload.devicePublicKey,
    });

    expect(swappedCode).not.toBe(reqCode);
  });
});
