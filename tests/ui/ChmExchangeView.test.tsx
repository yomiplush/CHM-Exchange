import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  base64UrlEncode,
  computePublicKeyFingerprintSync,
  createMemoryExchangeAdapter,
  createPublicKeyBundle,
  encodeExchangeUrl,
  hexToBytes,
} from '../../src/core.js';
import { ChmExchangeView } from '../../src/react.js';

const PUB_SELF = hexToBytes('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
const PUB_PEER = hexToBytes('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c');

const PUB_SELF_B64 = base64UrlEncode(PUB_SELF);
const FP_SELF = computePublicKeyFingerprintSync(PUB_SELF);
const FP_PEER = computePublicKeyFingerprintSync(PUB_PEER);

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.history.replaceState({}, '', '/');
});

describe('ChmExchangeView React UI', () => {
  it('renders Share tab with fingerprint, exchange URL, QR SVG, and zero private-key fields', async () => {
    const adapter = createMemoryExchangeAdapter({
      identities: [
        {
          id: 'self-1',
          displayName: 'YomiPlush',
          publicKeyBase64Url: PUB_SELF_B64,
          fingerprintHex: FP_SELF.fullHex,
          fingerprintShort: FP_SELF.shortDisplay,
        },
      ],
    });

    const { container } = render(<ChmExchangeView adapter={adapter} />);

    await waitFor(() => {
      expect(screen.getByTestId('chmx-share-fp-short')).toHaveTextContent(FP_SELF.shortDisplay);
    });

    const urlTextarea = screen.getByTestId('chmx-share-url') as HTMLTextAreaElement;
    expect(urlTextarea.value).toMatch(/^https:\/\/certified-handmade\.com\/exchange#key=/);
    expect(urlTextarea.value).not.toContain('privateKey');
    expect(urlTextarea.value).not.toContain('webCryptoPrivateKey');

    const qrSvg = container.querySelector('svg[role="img"]');
    expect(qrSvg).toBeInTheDocument();
  });

  it('inspects incoming key safely (XSS-proof), keeps it unverified until explicit confirmation, and manages trusted list', async () => {
    const adapter = createMemoryExchangeAdapter();
    const xssName = '<img src=x onerror=alert(1)>';
    const peerBundle = createPublicKeyBundle({
      publicKey: PUB_PEER,
      displayName: xssName,
    });
    const peerUrl = encodeExchangeUrl(peerBundle);
    vi.spyOn(window, 'confirm').mockReturnValue(true);

    const { container } = render(<ChmExchangeView adapter={adapter} initialTab="receive" />);

    const textarea = await screen.findByTestId('chmx-receive-textarea');
    fireEvent.change(textarea, { target: { value: peerUrl } });
    fireEvent.click(screen.getByTestId('chmx-receive-inspect-btn'));

    await waitFor(() => {
      expect(screen.getByTestId('chmx-receive-trust-status')).toHaveTextContent(
        'Unverified / Not Locally Trusted',
      );
    });

    // XSS payload must be rendered strictly as text, never parsed into <img>
    expect(container.querySelector('img[src="x"]')).toBeNull();
    expect(screen.getByTestId('chmx-inspected-name')).toHaveTextContent(xssName);
    expect(screen.getByTestId('chmx-inspected-fp-short')).toHaveTextContent(FP_PEER.shortDisplay);

    // Confirm button stays disabled until explicit checkbox is checked
    const trustBtn = screen.getByTestId('chmx-confirm-trust-btn');
    expect(trustBtn).toBeDisabled();

    const checkbox = screen.getByTestId('chmx-confirm-checkbox');
    fireEvent.click(checkbox);
    expect(trustBtn).not.toBeDisabled();

    fireEvent.click(trustBtn);

    await waitFor(() => {
      expect(screen.getByTestId('chmx-receive-trust-status')).toHaveTextContent(
        'Locally Trusted Key',
      );
    });

    expect(await adapter.listTrustedKeys()).toHaveLength(1);

    // Switch to Trusted Artists tab and verify removal
    fireEvent.click(screen.getByTestId('chmx-tab-trusted'));
    await waitFor(() => {
      expect(screen.getByTestId('chmx-trusted-list')).toHaveTextContent(FP_PEER.shortDisplay);
    });

    fireEvent.click(screen.getByTestId('chmx-remove-trusted-btn'));
    await waitFor(() => {
      expect(screen.getByTestId('chmx-trusted-empty')).toBeInTheDocument();
    });
    expect(await adapter.listTrustedKeys()).toHaveLength(0);
  });

  it('supports Japanese localization (ja)', async () => {
    const adapter = createMemoryExchangeAdapter();
    render(<ChmExchangeView adapter={adapter} locale="ja" />);

    await waitFor(() => {
      expect(screen.getByText('CHM 公開鍵エクスチェンジ')).toBeInTheDocument();
      expect(screen.getByRole('tab', { name: /自分の公開鍵を共有/ })).toBeInTheDocument();
      expect(screen.getByRole('tab', { name: /公開鍵を受け取る/ })).toBeInTheDocument();
      expect(screen.getByRole('tab', { name: /信頼済みアーティスト/ })).toBeInTheDocument();
    });
  });
});
