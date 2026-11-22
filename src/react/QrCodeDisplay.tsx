import { useMemo } from 'react';
import { generateExchangeQrMatrix } from '../core/qr.js';

export interface QrCodeDisplayProps {
  value: string;
  alt: string;
  caption?: string;
}

export function QrCodeDisplay({ value, alt, caption }: QrCodeDisplayProps) {
  const { viewBox, pathData } = useMemo(() => {
    const matrix = generateExchangeQrMatrix(value, 'M');
    const quiet = 4;
    const total = matrix.size + quiet * 2;
    const parts: string[] = [];
    for (let y = 0; y < matrix.size; y++) {
      for (let x = 0; x < matrix.size; x++) {
        if (matrix.data[y * matrix.size + x]) {
          parts.push(`M${x + quiet},${y + quiet}h1v1h-1z`);
        }
      }
    }
    return {
      viewBox: `0 0 ${total} ${total}`,
      pathData: parts.join(''),
    };
  }, [value]);

  return (
    <div className="chmx-qr-box">
      <div className="chmx-qr-frame">
        <svg
          role="img"
          aria-label={alt}
          viewBox={viewBox}
          className="chmx-qr-svg"
        >
          <rect width="100%" height="100%" fill="#ffffff" />
          <path d={pathData} fill="#0a0f1c" />
        </svg>
      </div>
      {caption && <p className="chmx-hint">{caption}</p>}
    </div>
  );
}
