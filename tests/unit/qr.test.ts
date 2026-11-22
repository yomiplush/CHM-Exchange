import { describe, expect, it } from 'vitest';
import {
  ChmExchangeError,
  createPublicKeyBundle,
  decodeExchangeUrl,
  decodeQrFromImageBytes,
  encodeExchangeUrl,
  generateExchangeQrMatrix,
  hexToBytes,
  renderExchangeQrPng,
} from '../../src/core.js';

const PUB_A = hexToBytes('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');

describe('CHM-Exchange QR Generation & Decoding', () => {
  it('generates a deterministic QR matrix and PNG with quiet zone that round-trips cleanly', async () => {
    const bundle = createPublicKeyBundle({
      publicKey: PUB_A,
      displayName: 'QR Artist',
    });
    const url = encodeExchangeUrl(bundle);

    const matrix = generateExchangeQrMatrix(url);
    expect(matrix.size).toBeGreaterThanOrEqual(21);
    expect(matrix.data.length).toBe(matrix.size * matrix.size);

    const rendered = renderExchangeQrPng(url, { moduleScale: 6, quietZoneModules: 4 });
    expect(rendered.width).toBe((matrix.size + 8) * 6);
    expect(rendered.height).toBe(rendered.width);
    // PNG magic header check
    expect(Array.from(rendered.pngBytes.slice(0, 4))).toEqual([0x89, 0x50, 0x4e, 0x47]);

    const decodedQrText = await decodeQrFromImageBytes(rendered.pngBytes);
    expect(decodedQrText).toBe(url);

    const imported = decodeExchangeUrl(decodedQrText);
    expect(imported.publicKeyBase64Url).toBe(bundle.publicKey);
    expect(imported.fingerprintHex).toBe(bundle.fingerprint);
    expect(imported.displayName).toBe('QR Artist');
  });

  it('rejects empty, corrupted, or oversized PNG headers safely', async () => {
    await expect(decodeQrFromImageBytes(new Uint8Array(0))).rejects.toThrow(ChmExchangeError);

    // Valid PNG signature + IHDR claiming 99999x99999 pixels
    const fakeHugePng = new Uint8Array(33);
    fakeHugePng.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 0);
    // Length + IHDR
    fakeHugePng.set([0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52], 8);
    // Width = 50000, Height = 50000
    fakeHugePng.set([0x00, 0x00, 0xc3, 0x50, 0x00, 0x00, 0xc3, 0x50], 16);

    await expect(decodeQrFromImageBytes(fakeHugePng)).rejects.toThrow(/exceed safe processing limits/);
  });
});
