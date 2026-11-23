import { useCallback, useEffect, useRef, useState } from 'react';
import { decodeQrFromRgba } from '../core/qr.js';
import { CameraIcon } from './icons.js';

interface BarcodeDetectorLike {
  detect(source: CanvasImageSource): Promise<Array<{ rawValue?: string }>>;
}

export interface QrCameraScannerProps {
  startLabel: string;
  stopLabel: string;
  hint: string;
  errorText: string;
  onDetected: (rawText: string) => void;
}

export function QrCameraScanner({
  startLabel,
  stopLabel,
  hint,
  errorText,
  onDetected,
}: QrCameraScannerProps) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [active, setActive] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const stopCamera = useCallback(() => {
    if (streamRef.current) {
      for (const track of streamRef.current.getTracks()) {
        track.stop();
      }
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setActive(false);
  }, []);

  useEffect(() => {
    return () => {
      stopCamera();
    };
  }, [stopCamera]);

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    let timerId: number | null = null;

    const DetectorCtor =
      typeof window !== 'undefined'
        ? (window as unknown as {
            BarcodeDetector?: new (opts?: { formats?: string[] }) => BarcodeDetectorLike;
          }).BarcodeDetector
        : undefined;
    const detector = typeof DetectorCtor === 'function' ? new DetectorCtor({ formats: ['qr_code'] }) : null;

    const tick = async () => {
      if (cancelled) return;
      const video = videoRef.current;
      if (video && video.readyState >= 2 && video.videoWidth > 0 && video.videoHeight > 0) {
        if (detector) {
          try {
            const found = await detector.detect(video);
            if (found.length > 0 && found[0].rawValue) {
              stopCamera();
              onDetected(found[0].rawValue);
              return;
            }
          } catch {
            // Fall back to jsQR below
          }
        }
        const canvas = canvasRef.current;
        if (canvas) {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          const ctx = canvas.getContext('2d', { willReadFrequently: true });
          if (ctx) {
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const decoded = decodeQrFromRgba(imgData.data, imgData.width, imgData.height);
            if (decoded) {
              stopCamera();
              onDetected(decoded);
              return;
            }
          }
        }
      }
      if (!cancelled) {
        timerId = window.setTimeout(tick, 180);
      }
    };

    timerId = window.setTimeout(tick, 200);
    return () => {
      cancelled = true;
      if (timerId !== null) window.clearTimeout(timerId);
    };
  }, [active, onDetected, stopCamera]);

  const startCamera = async () => {
    setErrorMsg(null);
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setErrorMsg(errorText);
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' } },
        audio: false,
      });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
      }
      setActive(true);
    } catch {
      setErrorMsg(errorText);
    }
  };

  return (
    <div className="chmx-stack">
      <div className="chmx-actions">
        {!active ? (
          <button
            type="button"
            onClick={() => void startCamera()}
            data-testid="chmx-camera-start"
            className="chmx-btn chmx-btn-accent"
          >
            <CameraIcon />
            <span>{startLabel}</span>
          </button>
        ) : (
          <button
            type="button"
            onClick={stopCamera}
            data-testid="chmx-camera-stop"
            className="chmx-btn chmx-btn-danger"
          >
            <span>{stopLabel}</span>
          </button>
        )}
      </div>
      <p className="chmx-hint">{hint}</p>

      {errorMsg && (
        <div role="alert" className="chmx-banner chmx-banner-error">
          {errorMsg}
        </div>
      )}

      <div className={active ? 'chmx-video-wrap' : 'chmx-sr-only'}>
        <video ref={videoRef} playsInline muted className="chmx-video" />
        <canvas ref={canvasRef} className="chmx-sr-only" />
      </div>
    </div>
  );
}
