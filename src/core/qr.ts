import { decode as decodePng, encode as encodePng } from 'fast-png';
import jsQR from 'jsqr';
import QRCode from 'qrcode';
import {
  MAX_QR_IMAGE_DIMENSION,
  MAX_QR_IMAGE_FILE_BYTES,
  MAX_QR_IMAGE_PIXELS,
} from './constants.js';
import { ChmExchangeError } from './types.js';

export type QrErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H';

export interface QrMatrix {
  size: number;
  version: number;
  errorCorrectionLevel: QrErrorCorrectionLevel;
  data: Uint8Array;
}

export interface QrPngOptions {
  moduleScale?: number;
  quietZoneModules?: number;
  errorCorrectionLevel?: QrErrorCorrectionLevel;
}

const PNG_MAGIC = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function isPngBytes(bytes: Uint8Array): boolean {
  if (bytes.length < 24) return false;
  for (let i = 0; i < PNG_MAGIC.length; i++) {
    if (bytes[i] !== PNG_MAGIC[i]) return false;
  }
  return true;
}

function readUInt32BE(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>>
    0
  );
}

function preflightPngIhdr(bytes: Uint8Array): { width: number; height: number } {
  if (bytes.length < 33) {
    throw new ChmExchangeError('INVALID_IMAGE', 'PNG file is too small to contain an IHDR header');
  }
  const chunkType = String.fromCharCode(bytes[12], bytes[13], bytes[14], bytes[15]);
  if (chunkType !== 'IHDR') {
    throw new ChmExchangeError('INVALID_IMAGE', 'Invalid PNG structure: missing IHDR chunk');
  }
  const width = readUInt32BE(bytes, 16);
  const height = readUInt32BE(bytes, 20);
  if (
    width === 0 ||
    height === 0 ||
    width > MAX_QR_IMAGE_DIMENSION ||
    height > MAX_QR_IMAGE_DIMENSION ||
    width * height > MAX_QR_IMAGE_PIXELS
  ) {
    throw new ChmExchangeError(
      'IMAGE_TOO_LARGE',
      `Image dimensions (${width}x${height}) exceed safe processing limits`,
    );
  }
  return { width, height };
}

export function generateExchangeQrMatrix(
  text: string,
  errorCorrectionLevel: QrErrorCorrectionLevel = 'M',
): QrMatrix {
  if (typeof text !== 'string' || text.length === 0) {
    throw new ChmExchangeError('INVALID_QR_PAYLOAD', 'QR payload text must be non-empty');
  }
  const qr = QRCode.create(text, { errorCorrectionLevel });
  return {
    size: qr.modules.size,
    version: qr.version,
    errorCorrectionLevel,
    data: new Uint8Array(qr.modules.data),
  };
}

export function renderExchangeQrPng(
  text: string,
  options: QrPngOptions = {},
): { pngBytes: Uint8Array; width: number; height: number; matrix: QrMatrix } {
  const errorCorrectionLevel = options.errorCorrectionLevel ?? 'M';
  const matrix = generateExchangeQrMatrix(text, errorCorrectionLevel);
  const quietZone = Math.max(4, Math.floor(options.quietZoneModules ?? 4));
  const totalModules = matrix.size + quietZone * 2;
  const scale = Math.max(
    1,
    Math.min(20, Math.floor(options.moduleScale ?? Math.max(4, Math.floor(360 / totalModules)))),
  );
  const width = totalModules * scale;
  const height = totalModules * scale;

  const rgba = new Uint8Array(width * height * 4);
  rgba.fill(255); // Pure white background + quiet zone

  for (let my = 0; my < matrix.size; my++) {
    for (let mx = 0; mx < matrix.size; mx++) {
      if (!matrix.data[my * matrix.size + mx]) continue;
      const startX = (mx + quietZone) * scale;
      const startY = (my + quietZone) * scale;
      for (let py = 0; py < scale; py++) {
        const rowOffset = (startY + py) * width;
        for (let px = 0; px < scale; px++) {
          const i = (rowOffset + startX + px) * 4;
          rgba[i] = 10;
          rgba[i + 1] = 15;
          rgba[i + 2] = 28;
          rgba[i + 3] = 255;
        }
      }
    }
  }

  const encoded = encodePng({ width, height, data: rgba, depth: 8, channels: 4 });
  return {
    pngBytes: encoded instanceof Uint8Array ? encoded : new Uint8Array(encoded),
    width,
    height,
    matrix,
  };
}

function pngDecodedToRgba8Clamped(decoded: ReturnType<typeof decodePng>): Uint8ClampedArray {
  const { width, height, data, channels, depth, palette } = decoded;
  const out = new Uint8ClampedArray(width * height * 4);
  const pixelCount = width * height;
  const shift = depth === 16 ? 8 : 0;

  if (palette && channels === 1) {
    for (let i = 0; i < pixelCount; i++) {
      const idx = data[i];
      const entry = palette[idx];
      const di = i * 4;
      if (entry) {
        const a = entry.length >= 4 ? entry[3] : 255;
        const inv = 255 - a;
        out[di] = a === 255 ? entry[0] : Math.round((entry[0] * a + 255 * inv) / 255);
        out[di + 1] = a === 255 ? entry[1] : Math.round((entry[1] * a + 255 * inv) / 255);
        out[di + 2] = a === 255 ? entry[2] : Math.round((entry[2] * a + 255 * inv) / 255);
      } else {
        out[di] = 255;
        out[di + 1] = 255;
        out[di + 2] = 255;
      }
      out[di + 3] = 255;
    }
    return out;
  }

  for (let i = 0; i < pixelCount; i++) {
    const di = i * 4;
    if (channels === 4) {
      const r = data[i * 4] >> shift;
      const g = data[i * 4 + 1] >> shift;
      const b = data[i * 4 + 2] >> shift;
      const a = data[i * 4 + 3] >> shift;
      const inv = 255 - a;
      out[di] = a === 255 ? r : Math.round((r * a + 255 * inv) / 255);
      out[di + 1] = a === 255 ? g : Math.round((g * a + 255 * inv) / 255);
      out[di + 2] = a === 255 ? b : Math.round((b * a + 255 * inv) / 255);
      out[di + 3] = 255;
    } else if (channels === 3) {
      out[di] = data[i * 3] >> shift;
      out[di + 1] = data[i * 3 + 1] >> shift;
      out[di + 2] = data[i * 3 + 2] >> shift;
      out[di + 3] = 255;
    } else if (channels === 2) {
      const g = data[i * 2] >> shift;
      const a = data[i * 2 + 1] >> shift;
      const inv = 255 - a;
      const v = a === 255 ? g : Math.round((g * a + 255 * inv) / 255);
      out[di] = v;
      out[di + 1] = v;
      out[di + 2] = v;
      out[di + 3] = 255;
    } else {
      const g = data[i] >> shift;
      out[di] = g;
      out[di + 1] = g;
      out[di + 2] = g;
      out[di + 3] = 255;
    }
  }
  return out;
}

export function decodeQrFromRgba(
  rgba: Uint8ClampedArray | Uint8Array,
  width: number,
  height: number,
): string | null {
  const clamped = rgba instanceof Uint8ClampedArray ? rgba : new Uint8ClampedArray(rgba);
  const direct = jsQR(clamped, width, height, { inversionAttempts: 'attemptBoth' });
  if (direct?.data) {
    return direct.data;
  }
  return null;
}

export async function decodeQrFromImageBytes(
  fileOrBytes: File | Blob | Uint8Array,
): Promise<string> {
  const bytes =
    fileOrBytes instanceof Uint8Array
      ? fileOrBytes
      : new Uint8Array(await fileOrBytes.arrayBuffer());

  if (bytes.byteLength === 0) {
    throw new ChmExchangeError('INVALID_IMAGE', 'Image file is empty');
  }
  if (bytes.byteLength > MAX_QR_IMAGE_FILE_BYTES) {
    throw new ChmExchangeError(
      'IMAGE_TOO_LARGE',
      `Image file exceeds maximum ${MAX_QR_IMAGE_FILE_BYTES} bytes`,
    );
  }

  if (isPngBytes(bytes)) {
    preflightPngIhdr(bytes);
    const decoded = decodePng(bytes);
    const rgba = pngDecodedToRgba8Clamped(decoded);
    const text = decodeQrFromRgba(rgba, decoded.width, decoded.height);
    if (!text) {
      throw new ChmExchangeError('QR_NOT_FOUND', 'No readable QR code found in this PNG image');
    }
    return text;
  }

  // Browser fallback for JPEG / WebP / GIF
  if (typeof createImageBitmap !== 'function' || typeof document === 'undefined') {
    throw new ChmExchangeError(
      'UNSUPPORTED_IMAGE_FORMAT',
      'Only PNG decoding is available in non-browser environments',
    );
  }

  const blob =
    fileOrBytes instanceof Blob
      ? fileOrBytes
      : new Blob([new Uint8Array(bytes)]);
  const bitmap = await createImageBitmap(blob);
  try {
    if (
      bitmap.width <= 0 ||
      bitmap.height <= 0 ||
      bitmap.width > MAX_QR_IMAGE_DIMENSION ||
      bitmap.height > MAX_QR_IMAGE_DIMENSION ||
      bitmap.width * bitmap.height > MAX_QR_IMAGE_PIXELS
    ) {
      throw new ChmExchangeError(
        'IMAGE_TOO_LARGE',
        `Image dimensions (${bitmap.width}x${bitmap.height}) exceed safe processing limits`,
      );
    }
    const canvas = document.createElement('canvas');
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) {
      throw new ChmExchangeError('CANVAS_UNAVAILABLE', 'Unable to create 2D canvas context');
    }
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(bitmap, 0, 0);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const text = decodeQrFromRgba(imageData.data, imageData.width, imageData.height);
    if (!text) {
      throw new ChmExchangeError('QR_NOT_FOUND', 'No readable QR code found in this image');
    }
    return text;
  } finally {
    bitmap.close();
  }
}
