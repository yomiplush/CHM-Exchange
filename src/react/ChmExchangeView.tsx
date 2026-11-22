import type { CSSProperties, FormEvent, ReactNode } from 'react';
import { useCallback, useEffect, useId, useMemo, useState } from 'react';
import {
  DEFAULT_EXCHANGE_BASE_URL,
  MAX_DISPLAY_NAME_UTF8_BYTES,
  MAX_EXCHANGE_JSON_BYTES,
  MAX_TRUST_NOTE_UTF8_BYTES,
} from '../core/constants.js';
import { createPublicKeyBundle, serializeExchangeBundleJson } from '../core/bundle.js';
import { utf8ByteLength } from '../core/encoding.js';
import { encodeExchangeUrl, parsePublicKeyExchangeInput } from '../core/exchangeUrl.js';
import { decodeQrFromImageBytes, renderExchangeQrPng } from '../core/qr.js';
import type {
  ChmExchangeHostAdapter,
  HostSigningIdentity,
  HostTrustedKey,
  VerifiedPublicKeyImport,
} from '../core/types.js';
import { stripToPublicHostIdentity } from '../core/validation.js';
import { getExchangeMessages } from '../i18n/index.js';
import type { ChmExchangeLocale, DeepPartialMessages } from '../i18n/index.js';
import { QrCameraScanner } from './QrCameraScanner.js';
import { QrCodeDisplay } from './QrCodeDisplay.js';
import {
  CameraIcon,
  CheckIcon,
  CopyIcon,
  DownloadIcon,
  KeyIcon,
  QrIcon,
  ShareIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  TrashIcon,
  UploadIcon,
  UsersIcon,
} from './icons.js';

export type ExchangeTab = 'share' | 'receive' | 'trusted';
type ReceiveInputMode = 'paste' | 'qr-image' | 'camera' | 'json-file';

export interface ChmExchangeTheme {
  panelBg?: string;
  cardBg?: string;
  inputBg?: string;
  border?: string;
  borderStrong?: string;
  text?: string;
  textMuted?: string;
  accent?: string;
  sky?: string;
  emerald?: string;
  amber?: string;
  rose?: string;
  radiusLg?: string;
  radiusMd?: string;
  fontMono?: string;
}

export interface ChmExchangeViewProps {
  adapter: ChmExchangeHostAdapter;
  exchangeBaseUrl?: string;
  locale?: ChmExchangeLocale;
  messages?: DeepPartialMessages;
  theme?: ChmExchangeTheme;
  className?: string;
  initialTab?: ExchangeTab;
  initialIdentityId?: string;
  initialInspectInput?: string;
  emptyIdentitiesAction?: ReactNode;
  onTrustChanged?: (trustedKeys: HostTrustedKey[]) => void;
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function safeFileSlug(value: string | undefined, fallback: string): string {
  const cleaned = (value ?? '')
    .replace(/[^a-zA-Z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase();
  return cleaned || fallback;
}

function extractHashKeyFragment(): string | null {
  if (typeof window === 'undefined') return null;
  const hash = window.location.hash;
  if (!hash || !hash.includes('key=')) return null;
  return hash;
}

function tryInspectInitial(raw: string | null): {
  inspected: VerifiedPublicKeyImport | null;
  error: string | null;
} {
  if (!raw) return { inspected: null, error: null };
  try {
    return { inspected: parsePublicKeyExchangeInput(raw), error: null };
  } catch (err) {
    return {
      inspected: null,
      error: err instanceof Error ? err.message : 'Invalid public-key exchange input',
    };
  }
}

export function ChmExchangeView({
  adapter,
  exchangeBaseUrl = DEFAULT_EXCHANGE_BASE_URL,
  locale = 'en',
  messages: messageOverrides,
  theme,
  className = '',
  initialTab,
  initialIdentityId,
  initialInspectInput,
  emptyIdentitiesAction,
  onTrustChanged,
}: ChmExchangeViewProps) {
  const t = useMemo(
    () => getExchangeMessages(locale, messageOverrides),
    [locale, messageOverrides],
  );

  const identitySelectId = useId();
  const shareNameInputId = useId();
  const pasteInputId = useId();
  const qrFileInputId = useId();
  const jsonFileInputId = useId();
  const confirmLabelInputId = useId();
  const confirmNoteInputId = useId();
  const confirmCheckboxId = useId();

  const [identities, setIdentities] = useState<HostSigningIdentity[]>([]);
  const [trustedKeys, setTrustedKeys] = useState<HostTrustedKey[]>([]);
  const [selectedIdentityId, setSelectedIdentityId] = useState<string>(initialIdentityId ?? '');
  const [displayNameOverrides, setDisplayNameOverrides] = useState<Record<string, string>>({});
  const [shareError, setShareError] = useState<string | null>(null);

  const initialRawCandidate = useMemo(() => {
    if (initialInspectInput && initialInspectInput.trim().length > 0) {
      return initialInspectInput.trim();
    }
    return extractHashKeyFragment();
  }, [initialInspectInput]);

  const initialInspectedState = useMemo(
    () => tryInspectInitial(initialRawCandidate),
    [initialRawCandidate],
  );

  const [activeTab, setActiveTab] = useState<ExchangeTab>(() => {
    if (initialTab) return initialTab;
    if (initialRawCandidate) return 'receive';
    return 'share';
  });

  const [receiveMode, setReceiveMode] = useState<ReceiveInputMode>('paste');
  const [receiveText, setReceiveText] = useState<string>(() => initialRawCandidate ?? '');
  const [inspected, setInspected] = useState<VerifiedPublicKeyImport | null>(
    () => initialInspectedState.inspected,
  );
  const [receiveError, setReceiveError] = useState<string | null>(
    () => initialInspectedState.error,
  );
  const [confirmLabel, setConfirmLabel] = useState<string>(
    () => initialInspectedState.inspected?.displayName ?? '',
  );
  const [confirmNote, setConfirmNote] = useState<string>('');
  const [confirmChecked, setConfirmChecked] = useState<boolean>(false);
  const [trustSavedBanner, setTrustSavedBanner] = useState<string | null>(null);

  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const markCopied = useCallback((key: string) => {
    setCopiedKey(key);
    window.setTimeout(() => {
      setCopiedKey((prev) => (prev === key ? null : prev));
    }, 2000);
  }, []);

  const copyText = useCallback(
    async (key: string, value: string) => {
      try {
        await navigator.clipboard.writeText(value);
        markCopied(key);
      } catch {
        // Clipboard API unavailable in restricted contexts
      }
    },
    [markCopied],
  );

  useEffect(() => {
    let active = true;
    Promise.all([adapter.listPublicIdentities(), adapter.listTrustedKeys()])
      .then(([rawIds, tk]) => {
        if (!active) return;
        const cleanIds = rawIds.map((id) => stripToPublicHostIdentity(id));
        setIdentities(cleanIds);
        setTrustedKeys(tk);
        setSelectedIdentityId((prev) => {
          if (initialIdentityId && cleanIds.some((id) => id.id === initialIdentityId)) {
            return initialIdentityId;
          }
          if (prev && cleanIds.some((id) => id.id === prev)) {
            return prev;
          }
          return cleanIds[0]?.id ?? '';
        });
      })
      .catch((err) => {
        if (active) {
          setShareError(err instanceof Error ? err.message : 'Failed to load host keys');
        }
      });
    return () => {
      active = false;
    };
  }, [adapter, initialIdentityId]);

  const selectedIdentity = useMemo(
    () => identities.find((id) => id.id === selectedIdentityId) ?? identities[0] ?? null,
    [identities, selectedIdentityId],
  );

  const customDisplayName = selectedIdentity
    ? (displayNameOverrides[selectedIdentity.id] ?? selectedIdentity.displayName)
    : '';

  const shareArtifact = useMemo(() => {
    if (!selectedIdentity) return null;
    try {
      const bundle = createPublicKeyBundle({
        publicKey: selectedIdentity.publicKeyBase64Url,
        displayName: customDisplayName || undefined,
      });
      const exchangeUrl = encodeExchangeUrl(bundle, exchangeBaseUrl);
      return { bundle, exchangeUrl, error: null as string | null };
    } catch (err) {
      return {
        bundle: null,
        exchangeUrl: '',
        error: err instanceof Error ? err.message : 'Failed to build exchange bundle',
      };
    }
  }, [selectedIdentity, customDisplayName, exchangeBaseUrl]);

  const inspectRawInput = useCallback((raw: string) => {
    setReceiveError(null);
    setTrustSavedBanner(null);
    setConfirmChecked(false);
    try {
      const parsed = parsePublicKeyExchangeInput(raw);
      setInspected(parsed);
      setConfirmLabel(parsed.displayName ?? '');
      setConfirmNote('');
    } catch (err) {
      setInspected(null);
      setReceiveError(err instanceof Error ? err.message : 'Invalid public-key exchange input');
    }
  }, []);

  // Listen to browser hashchange for live #key=... navigation
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const onHashChange = () => {
      const fragment = extractHashKeyFragment();
      if (fragment) {
        setReceiveText(fragment);
        setActiveTab('receive');
        inspectRawInput(fragment);
      }
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, [inspectRawInput]);

  const inspectedTrustMatch = useMemo(() => {
    if (!inspected) return null;
    return (
      trustedKeys.find((tk) => tk.publicKeyBase64Url === inspected.publicKeyBase64Url) ?? null
    );
  }, [inspected, trustedKeys]);

  const inspectedIsOwnIdentity = useMemo(() => {
    if (!inspected) return false;
    return identities.some((id) => id.publicKeyBase64Url === inspected.publicKeyBase64Url);
  }, [inspected, identities]);

  const handleDownloadQrPng = () => {
    if (!shareArtifact?.exchangeUrl || !selectedIdentity) return;
    try {
      const { pngBytes } = renderExchangeQrPng(shareArtifact.exchangeUrl);
      const slug = safeFileSlug(customDisplayName || selectedIdentity.displayName, 'artist');
      const fpPrefix = selectedIdentity.fingerprintHex.slice(0, 8);
      downloadBlob(
        new Blob([new Uint8Array(pngBytes)], { type: 'image/png' }),
        `chm-exchange-${slug}-${fpPrefix}.png`,
      );
    } catch (err) {
      setShareError(err instanceof Error ? err.message : 'Failed to generate QR PNG');
    }
  };

  const handleExportJson = () => {
    if (!shareArtifact?.bundle || !selectedIdentity) return;
    const json = serializeExchangeBundleJson(shareArtifact.bundle, { pretty: true });
    const slug = safeFileSlug(customDisplayName || selectedIdentity.displayName, 'artist');
    const fpPrefix = selectedIdentity.fingerprintHex.slice(0, 8);
    downloadBlob(
      new Blob([json], { type: 'application/json' }),
      `chm-exchange-${slug}-${fpPrefix}.json`,
    );
  };

  const canNativeShare =
    typeof navigator !== 'undefined' && typeof navigator.share === 'function';

  const handleNativeShare = async () => {
    if (!shareArtifact?.exchangeUrl || !canNativeShare) return;
    try {
      await navigator.share({
        title: t.share.nativeShareText,
        text: `${customDisplayName || selectedIdentity?.displayName || 'Artist'} (${selectedIdentity?.fingerprintShort ?? ''})`,
        url: shareArtifact.exchangeUrl,
      });
    } catch {
      // User cancelled share sheet
    }
  };

  const handlePasteSubmit = (e: FormEvent) => {
    e.preventDefault();
    inspectRawInput(receiveText);
  };

  const handleQrImageUpload = async (file: File | undefined) => {
    if (!file) return;
    setReceiveError(null);
    setTrustSavedBanner(null);
    try {
      const decodedText = await decodeQrFromImageBytes(file);
      setReceiveText(decodedText);
      inspectRawInput(decodedText);
    } catch (err) {
      setInspected(null);
      setReceiveError(err instanceof Error ? err.message : 'Failed to decode QR image');
    }
  };

  const handleJsonFileUpload = async (file: File | undefined) => {
    if (!file) return;
    setReceiveError(null);
    setTrustSavedBanner(null);
    if (file.size > MAX_EXCHANGE_JSON_BYTES) {
      setInspected(null);
      setReceiveError(`JSON file exceeds maximum ${MAX_EXCHANGE_JSON_BYTES} bytes`);
      return;
    }
    try {
      const text = await file.text();
      setReceiveText(text);
      inspectRawInput(text);
    } catch (err) {
      setInspected(null);
      setReceiveError(err instanceof Error ? err.message : 'Failed to read JSON file');
    }
  };

  const handleCameraDetected = useCallback(
    (rawText: string) => {
      setReceiveText(rawText);
      inspectRawInput(rawText);
    },
    [inspectRawInput],
  );

  const handleConfirmTrust = async (e: FormEvent) => {
    e.preventDefault();
    if (!inspected || !confirmChecked) return;
    setReceiveError(null);
    try {
      await adapter.addTrustedKey({
        publicKeyBase64Url: inspected.publicKeyBase64Url,
        fingerprintHex: inspected.fingerprintHex,
        displayName: confirmLabel.trim() || inspected.displayName || 'Trusted Artist',
        note: confirmNote.trim() || undefined,
      });
      const updated = await adapter.listTrustedKeys();
      setTrustedKeys(updated);
      onTrustChanged?.(updated);
      setTrustSavedBanner(t.receive.trustSavedBanner);
      setConfirmChecked(false);
    } catch (err) {
      setReceiveError(err instanceof Error ? err.message : 'Failed to save trusted key');
    }
  };

  const handleRemoveTrusted = async (publicKeyBase64Url: string) => {
    if (typeof window !== 'undefined' && typeof window.confirm === 'function') {
      if (!window.confirm(t.trusted.removeConfirm)) return;
    }
    await adapter.removeTrustedKey(publicKeyBase64Url);
    const updated = await adapter.listTrustedKeys();
    setTrustedKeys(updated);
    onTrustChanged?.(updated);
  };

  const rootStyle = useMemo(() => {
    if (!theme) return undefined;
    const vars: Record<string, string> = {};
    if (theme.panelBg) vars['--chmx-panel-bg'] = theme.panelBg;
    if (theme.cardBg) vars['--chmx-card-bg'] = theme.cardBg;
    if (theme.inputBg) vars['--chmx-input-bg'] = theme.inputBg;
    if (theme.border) vars['--chmx-border'] = theme.border;
    if (theme.borderStrong) vars['--chmx-border-strong'] = theme.borderStrong;
    if (theme.text) vars['--chmx-text'] = theme.text;
    if (theme.textMuted) vars['--chmx-text-muted'] = theme.textMuted;
    if (theme.accent) vars['--chmx-accent'] = theme.accent;
    if (theme.sky) vars['--chmx-sky'] = theme.sky;
    if (theme.emerald) vars['--chmx-emerald'] = theme.emerald;
    if (theme.amber) vars['--chmx-amber'] = theme.amber;
    if (theme.rose) vars['--chmx-rose'] = theme.rose;
    if (theme.radiusLg) vars['--chmx-radius-lg'] = theme.radiusLg;
    if (theme.radiusMd) vars['--chmx-radius-md'] = theme.radiusMd;
    if (theme.fontMono) vars['--chmx-font-mono'] = theme.fontMono;
    return vars as CSSProperties;
  }, [theme]);

  return (
    <div
      className={`chmx-root ${className}`.trim()}
      style={rootStyle}
      data-testid="chm-exchange-root"
    >
      <header className="chmx-header">
        <h1 className="chmx-title">{t.headerTitle}</h1>
        <p className="chmx-subtitle">{t.headerSubtitle}</p>
      </header>

      <div role="note" className="chmx-banner chmx-banner-info">
        <ShieldAlertIcon className="chmx-icon-lg" />
        <div>
          <p className="chmx-banner-title">{t.trustNoticeTitle}</p>
          <p className="chmx-banner-body">{t.trustNoticeBody}</p>
        </div>
      </div>

      <div role="tablist" aria-label={t.headerTitle} className="chmx-tabs">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'share'}
          data-testid="chmx-tab-share"
          onClick={() => setActiveTab('share')}
          className="chmx-tab"
        >
          <ShareIcon />
          <span>{t.tabs.share}</span>
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'receive'}
          data-testid="chmx-tab-receive"
          onClick={() => setActiveTab('receive')}
          className="chmx-tab"
        >
          <QrIcon />
          <span>{t.tabs.receive}</span>
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'trusted'}
          data-testid="chmx-tab-trusted"
          onClick={() => setActiveTab('trusted')}
          className="chmx-tab"
        >
          <UsersIcon />
          <span>{t.tabs.trusted}</span>
          <span className="chmx-badge-count">{trustedKeys.length}</span>
        </button>
      </div>

      {activeTab === 'share' && (
        <section
          role="tabpanel"
          aria-labelledby="chmx-share-heading"
          data-testid="chmx-panel-share"
          className="chmx-panel"
        >
          <div className="chmx-section-head">
            <h2 id="chmx-share-heading" className="chmx-section-title">
              <KeyIcon className="chmx-icon-lg" />
              <span>{t.share.sectionTitle}</span>
            </h2>
            <p className="chmx-section-subtitle">{t.share.sectionSubtitle}</p>
          </div>

          {shareError && (
            <div role="alert" className="chmx-banner chmx-banner-error">
              {shareError}
            </div>
          )}

          {identities.length === 0 ? (
            <div className="chmx-card" data-testid="chmx-no-identities">
              <p className="chmx-banner-title">{t.share.noIdentitiesTitle}</p>
              <p className="chmx-hint">{t.share.noIdentitiesBody}</p>
              {emptyIdentitiesAction && (
                <div className="chmx-actions">{emptyIdentitiesAction}</div>
              )}
            </div>
          ) : (
            selectedIdentity && (
              <div className="chmx-grid-2">
                <div className="chmx-stack">
                  <div className="chmx-field">
                    <label htmlFor={identitySelectId} className="chmx-label">
                      {t.share.selectIdentityLabel}
                    </label>
                    <select
                      id={identitySelectId}
                      data-testid="chmx-identity-select"
                      value={selectedIdentity.id}
                      onChange={(e) => setSelectedIdentityId(e.target.value)}
                      className="chmx-select"
                    >
                      {identities.map((id) => (
                        <option key={id.id} value={id.id}>
                          {id.displayName} ({id.fingerprintShort})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="chmx-field">
                    <label htmlFor={shareNameInputId} className="chmx-label">
                      {t.share.displayNameLabel} ({utf8ByteLength(customDisplayName)}/{MAX_DISPLAY_NAME_UTF8_BYTES})
                    </label>
                    <input
                      id={shareNameInputId}
                      type="text"
                      value={customDisplayName}
                      onChange={(e) =>
                        setDisplayNameOverrides((prev) => ({
                          ...prev,
                          [selectedIdentity.id]: e.target.value,
                        }))
                      }
                      placeholder={t.share.displayNamePlaceholder}
                      maxLength={64}
                      data-testid="chmx-share-displayname"
                      className="chmx-input"
                    />
                    <p className="chmx-hint">{t.share.displayNameHint}</p>
                  </div>

                  <div className="chmx-card">
                    <span className="chmx-kv-label">{t.share.fingerprintShortLabel}</span>
                    <span className="chmx-mono" data-testid="chmx-share-fp-short">
                      {selectedIdentity.fingerprintShort}
                    </span>
                    <span className="chmx-kv-label">{t.share.fingerprintFullLabel}</span>
                    <span className="chmx-mono" data-testid="chmx-share-fp-full">
                      {selectedIdentity.fingerprintHex}
                    </span>
                    <span className="chmx-kv-label">{t.share.publicKeyLabel}</span>
                    <span className="chmx-mono" data-testid="chmx-share-pubkey">
                      {selectedIdentity.publicKeyBase64Url}
                    </span>
                  </div>

                  {shareArtifact?.error && (
                    <div role="alert" className="chmx-banner chmx-banner-error">
                      {shareArtifact.error}
                    </div>
                  )}

                  {shareArtifact?.exchangeUrl && (
                    <div className="chmx-field">
                      <label htmlFor="chmx-share-url-out" className="chmx-label">
                        {t.share.exchangeUrlLabel}
                      </label>
                      <textarea
                        id="chmx-share-url-out"
                        readOnly
                        value={shareArtifact.exchangeUrl}
                        data-testid="chmx-share-url"
                        className="chmx-textarea"
                      />
                    </div>
                  )}

                  <div className="chmx-actions">
                    <button
                      type="button"
                      disabled={!shareArtifact?.exchangeUrl}
                      onClick={() =>
                        shareArtifact?.exchangeUrl &&
                        void copyText('share-url', shareArtifact.exchangeUrl)
                      }
                      data-testid="chmx-copy-url-btn"
                      className="chmx-btn chmx-btn-primary"
                    >
                      {copiedKey === 'share-url' ? <CheckIcon /> : <CopyIcon />}
                      <span>
                        {copiedKey === 'share-url' ? t.share.copiedBtn : t.share.copyUrlBtn}
                      </span>
                    </button>

                    <button
                      type="button"
                      onClick={() =>
                        void copyText('share-pk', selectedIdentity.publicKeyBase64Url)
                      }
                      data-testid="chmx-copy-pubkey-btn"
                      className="chmx-btn chmx-btn-secondary"
                    >
                      {copiedKey === 'share-pk' ? <CheckIcon /> : <CopyIcon />}
                      <span>
                        {copiedKey === 'share-pk' ? t.share.copiedBtn : t.share.copyPublicKeyBtn}
                      </span>
                    </button>

                    <button
                      type="button"
                      disabled={!shareArtifact?.exchangeUrl}
                      onClick={handleDownloadQrPng}
                      data-testid="chmx-download-qr-btn"
                      className="chmx-btn chmx-btn-accent"
                    >
                      <DownloadIcon />
                      <span>{t.share.downloadQrPngBtn}</span>
                    </button>

                    <button
                      type="button"
                      disabled={!shareArtifact?.bundle}
                      onClick={handleExportJson}
                      data-testid="chmx-export-json-btn"
                      className="chmx-btn chmx-btn-secondary"
                    >
                      <DownloadIcon />
                      <span>{t.share.exportJsonBtn}</span>
                    </button>

                    {canNativeShare && (
                      <button
                        type="button"
                        disabled={!shareArtifact?.exchangeUrl}
                        onClick={() => void handleNativeShare()}
                        data-testid="chmx-native-share-btn"
                        className="chmx-btn chmx-btn-secondary"
                      >
                        <ShareIcon />
                        <span>{t.share.nativeShareBtn}</span>
                      </button>
                    )}
                  </div>

                  <p className="chmx-hint">{t.share.privateKeyBoundaryNote}</p>
                </div>

                {shareArtifact?.exchangeUrl && (
                  <div data-testid="chmx-share-qr-preview">
                    <QrCodeDisplay
                      value={shareArtifact.exchangeUrl}
                      alt={t.share.qrAlt}
                      caption={t.share.qrCaption}
                    />
                  </div>
                )}
              </div>
            )
          )}
        </section>
      )}

      {activeTab === 'receive' && (
        <section
          role="tabpanel"
          aria-labelledby="chmx-receive-heading"
          data-testid="chmx-panel-receive"
          className="chmx-panel"
        >
          <div className="chmx-section-head">
            <h2 id="chmx-receive-heading" className="chmx-section-title">
              <QrIcon className="chmx-icon-lg" />
              <span>{t.receive.sectionTitle}</span>
            </h2>
            <p className="chmx-section-subtitle">{t.receive.sectionSubtitle}</p>
          </div>

          <div role="tablist" className="chmx-subtabs">
            <button
              type="button"
              role="tab"
              aria-selected={receiveMode === 'paste'}
              onClick={() => setReceiveMode('paste')}
              data-testid="chmx-receive-mode-paste"
              className="chmx-subtab"
            >
              <span>{t.receive.inputModePaste}</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={receiveMode === 'qr-image'}
              onClick={() => setReceiveMode('qr-image')}
              data-testid="chmx-receive-mode-qr"
              className="chmx-subtab"
            >
              <UploadIcon />
              <span>{t.receive.inputModeQrImage}</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={receiveMode === 'camera'}
              onClick={() => setReceiveMode('camera')}
              data-testid="chmx-receive-mode-camera"
              className="chmx-subtab"
            >
              <CameraIcon />
              <span>{t.receive.inputModeCamera}</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={receiveMode === 'json-file'}
              onClick={() => setReceiveMode('json-file')}
              data-testid="chmx-receive-mode-json"
              className="chmx-subtab"
            >
              <UploadIcon />
              <span>{t.receive.inputModeJsonFile}</span>
            </button>
          </div>

          {receiveMode === 'paste' && (
            <form onSubmit={handlePasteSubmit} className="chmx-stack">
              <div className="chmx-field">
                <label htmlFor={pasteInputId} className="chmx-label">
                  {t.receive.pasteLabel}
                </label>
                <textarea
                  id={pasteInputId}
                  value={receiveText}
                  onChange={(e) => setReceiveText(e.target.value)}
                  placeholder={t.receive.pastePlaceholder}
                  data-testid="chmx-receive-textarea"
                  className="chmx-textarea"
                />
              </div>
              <div className="chmx-actions">
                <button
                  type="submit"
                  data-testid="chmx-receive-inspect-btn"
                  className="chmx-btn chmx-btn-primary"
                >
                  <span>{t.receive.inspectBtn}</span>
                </button>
                {receiveText && (
                  <button
                    type="button"
                    onClick={() => {
                      setReceiveText('');
                      setInspected(null);
                      setReceiveError(null);
                      setTrustSavedBanner(null);
                    }}
                    className="chmx-btn chmx-btn-secondary"
                  >
                    <span>{t.receive.clearBtn}</span>
                  </button>
                )}
              </div>
            </form>
          )}

          {receiveMode === 'qr-image' && (
            <label htmlFor={qrFileInputId} className="chmx-dropzone">
              <input
                id={qrFileInputId}
                type="file"
                accept="image/png,image/jpeg,image/webp,image/*"
                data-testid="chmx-qr-file-input"
                onChange={(e) => {
                  void handleQrImageUpload(e.target.files?.[0]);
                  e.target.value = '';
                }}
                className="chmx-sr-only"
              />
              <UploadIcon className="chmx-icon-lg" />
              <span className="chmx-kv-value">{t.receive.qrImageDropLabel}</span>
              <span className="chmx-hint">{t.receive.qrImageDropHint}</span>
            </label>
          )}

          {receiveMode === 'camera' && (
            <QrCameraScanner
              startLabel={t.receive.cameraStartBtn}
              stopLabel={t.receive.cameraStopBtn}
              hint={t.receive.cameraHint}
              errorText={t.receive.cameraError}
              onDetected={handleCameraDetected}
            />
          )}

          {receiveMode === 'json-file' && (
            <label htmlFor={jsonFileInputId} className="chmx-dropzone">
              <input
                id={jsonFileInputId}
                type="file"
                accept=".json,application/json"
                data-testid="chmx-json-file-input"
                onChange={(e) => {
                  void handleJsonFileUpload(e.target.files?.[0]);
                  e.target.value = '';
                }}
                className="chmx-sr-only"
              />
              <UploadIcon className="chmx-icon-lg" />
              <span className="chmx-kv-value">{t.receive.jsonFileLabel}</span>
              <span className="chmx-hint">{t.receive.jsonFileHint}</span>
            </label>
          )}

          {receiveError && (
            <div role="alert" data-testid="chmx-receive-error" className="chmx-banner chmx-banner-error">
              {receiveError}
            </div>
          )}

          {trustSavedBanner && (
            <div role="status" data-testid="chmx-trust-saved" className="chmx-banner chmx-banner-trusted">
              <ShieldCheckIcon className="chmx-icon-lg" />
              <span>{trustSavedBanner}</span>
            </div>
          )}

          {inspected && (
            <div className="chmx-stack" data-testid="chmx-inspected-result">
              <div className="chmx-card chmx-stack">
                <div
                  className="chmx-actions"
                  style={{ justifyContent: 'space-between', alignItems: 'center' }}
                >
                  <strong className="chmx-kv-value">{t.receive.resultTitle}</strong>
                  <span
                    data-testid="chmx-receive-trust-status"
                    className={`chmx-status-pill ${
                      inspectedTrustMatch ? 'chmx-status-pill-trusted' : 'chmx-status-pill-unverified'
                    }`}
                  >
                    {inspectedTrustMatch ? <ShieldCheckIcon /> : <ShieldAlertIcon />}
                    <span>
                      {inspectedTrustMatch
                        ? `${t.receive.statusTrusted} (${inspectedTrustMatch.displayName})`
                        : t.receive.statusUnverified}
                    </span>
                  </span>
                </div>

                {!inspectedTrustMatch && (
                  <div className="chmx-banner chmx-banner-warning" role="status">
                    <ShieldAlertIcon className="chmx-icon-lg" />
                    <span>{t.receive.unverifiedWarning}</span>
                  </div>
                )}

                {inspectedTrustMatch && (
                  <p className="chmx-hint" data-testid="chmx-duplicate-notice">
                    {t.receive.statusDuplicateNote}
                  </p>
                )}

                {inspectedIsOwnIdentity && (
                  <p className="chmx-hint" data-testid="chmx-own-identity-notice">
                    {t.receive.statusOwnKeyNote}
                  </p>
                )}

                <div className="chmx-field">
                  <span className="chmx-kv-label">{t.receive.declaredNameLabel}</span>
                  <span className="chmx-kv-value" data-testid="chmx-inspected-name">
                    {inspected.displayName || t.receive.noDeclaredName}
                  </span>
                </div>

                <div className="chmx-field">
                  <span className="chmx-kv-label">{t.receive.recomputedFingerprintShortLabel}</span>
                  <span className="chmx-mono" data-testid="chmx-inspected-fp-short">
                    {inspected.fingerprintShort}
                  </span>
                </div>

                <div className="chmx-field">
                  <span className="chmx-kv-label">{t.receive.recomputedFingerprintFullLabel}</span>
                  <span className="chmx-mono" data-testid="chmx-inspected-fp-full">
                    {inspected.fingerprintHex}
                  </span>
                </div>

                <div className="chmx-field">
                  <span className="chmx-kv-label">{t.receive.publicKeyLabel}</span>
                  <span className="chmx-mono" data-testid="chmx-inspected-pubkey">
                    {inspected.publicKeyBase64Url}
                  </span>
                </div>

                <div className="chmx-field">
                  <span className="chmx-kv-label">{t.receive.sourceKindLabel}</span>
                  <span className="chmx-kv-value">
                    {t.receive.sourceKinds[inspected.sourceKind]}
                  </span>
                </div>
              </div>

              {!inspectedTrustMatch ? (
                <form
                  onSubmit={(e) => void handleConfirmTrust(e)}
                  data-testid="chmx-confirm-trust-form"
                  className="chmx-card chmx-stack"
                >
                  <h3 className="chmx-section-title">{t.receive.confirmTrustTitle}</h3>

                  <div className="chmx-field">
                    <label htmlFor={confirmLabelInputId} className="chmx-label">
                      {t.receive.confirmLabelInput}
                    </label>
                    <input
                      id={confirmLabelInputId}
                      type="text"
                      required
                      maxLength={64}
                      value={confirmLabel}
                      onChange={(e) => setConfirmLabel(e.target.value)}
                      placeholder={t.receive.confirmLabelPlaceholder}
                      data-testid="chmx-confirm-label-input"
                      className="chmx-input"
                    />
                  </div>

                  <div className="chmx-field">
                    <label htmlFor={confirmNoteInputId} className="chmx-label">
                      {t.receive.confirmNoteInput} ({utf8ByteLength(confirmNote)}/{MAX_TRUST_NOTE_UTF8_BYTES})
                    </label>
                    <input
                      id={confirmNoteInputId}
                      type="text"
                      maxLength={200}
                      value={confirmNote}
                      onChange={(e) => setConfirmNote(e.target.value)}
                      placeholder={t.receive.confirmNotePlaceholder}
                      data-testid="chmx-confirm-note-input"
                      className="chmx-input"
                    />
                  </div>

                  <label htmlFor={confirmCheckboxId} className="chmx-checkbox-row">
                    <input
                      id={confirmCheckboxId}
                      type="checkbox"
                      checked={confirmChecked}
                      onChange={(e) => setConfirmChecked(e.target.checked)}
                      data-testid="chmx-confirm-checkbox"
                    />
                    <span>{t.receive.confirmCheckboxLabel}</span>
                  </label>

                  <div className="chmx-actions">
                    <button
                      type="submit"
                      disabled={!confirmChecked || !confirmLabel.trim()}
                      data-testid="chmx-confirm-trust-btn"
                      className="chmx-btn chmx-btn-trust"
                    >
                      <ShieldCheckIcon />
                      <span>{t.receive.confirmTrustBtn}</span>
                    </button>
                  </div>
                </form>
              ) : (
                <p className="chmx-hint">{t.receive.alreadyTrustedNote}</p>
              )}
            </div>
          )}
        </section>
      )}

      {activeTab === 'trusted' && (
        <section
          role="tabpanel"
          aria-labelledby="chmx-trusted-heading"
          data-testid="chmx-panel-trusted"
          className="chmx-panel"
        >
          <div className="chmx-section-head">
            <h2 id="chmx-trusted-heading" className="chmx-section-title">
              <ShieldCheckIcon className="chmx-icon-lg" />
              <span>{t.trusted.sectionTitle}</span>
              <span className="chmx-badge-count">
                {trustedKeys.length} {t.trusted.countLabel}
              </span>
            </h2>
            <p className="chmx-section-subtitle">{t.trusted.sectionSubtitle}</p>
          </div>

          {trustedKeys.length === 0 ? (
            <p className="chmx-hint" data-testid="chmx-trusted-empty">
              {t.trusted.emptyState}
            </p>
          ) : (
            <div className="chmx-stack" data-testid="chmx-trusted-list">
              {trustedKeys.map((tk) => (
                <article
                  key={tk.publicKeyBase64Url}
                  data-testid="chmx-trusted-item"
                  className="chmx-trusted-item"
                >
                  <div className="chmx-stack" style={{ gap: '0.35rem', minWidth: 0 }}>
                    <strong className="chmx-kv-value" style={{ color: 'var(--chmx-emerald)' }}>
                      {tk.displayName}
                    </strong>
                    <div className="chmx-mono">{tk.fingerprintShort}</div>
                    <div className="chmx-hint" style={{ fontFamily: 'var(--chmx-font-mono)' }}>
                      {tk.fingerprintHex}
                    </div>
                    <div
                      className="chmx-hint"
                      style={{ fontFamily: 'var(--chmx-font-mono)', wordBreak: 'break-all' }}
                    >
                      {tk.publicKeyBase64Url}
                    </div>
                    {tk.note && (
                      <div className="chmx-hint">
                        {t.trusted.noteLabel}: {tk.note}
                      </div>
                    )}
                    <div className="chmx-hint">
                      {t.trusted.addedAtLabel}: {tk.addedAt}
                    </div>
                  </div>

                  <div className="chmx-actions" style={{ flexShrink: 0 }}>
                    <button
                      type="button"
                      onClick={() =>
                        void copyText(`trusted-pk-${tk.publicKeyBase64Url}`, tk.publicKeyBase64Url)
                      }
                      className="chmx-btn chmx-btn-secondary"
                    >
                      {copiedKey === `trusted-pk-${tk.publicKeyBase64Url}` ? (
                        <CheckIcon />
                      ) : (
                        <CopyIcon />
                      )}
                      <span>
                        {copiedKey === `trusted-pk-${tk.publicKeyBase64Url}`
                          ? t.trusted.copiedBtn
                          : t.trusted.copyKeyBtn}
                      </span>
                    </button>

                    <button
                      type="button"
                      onClick={() =>
                        void copyText(`trusted-fp-${tk.publicKeyBase64Url}`, tk.fingerprintShort)
                      }
                      className="chmx-btn chmx-btn-secondary"
                    >
                      {copiedKey === `trusted-fp-${tk.publicKeyBase64Url}` ? (
                        <CheckIcon />
                      ) : (
                        <CopyIcon />
                      )}
                      <span>
                        {copiedKey === `trusted-fp-${tk.publicKeyBase64Url}`
                          ? t.trusted.copiedBtn
                          : t.trusted.copyFingerprintBtn}
                      </span>
                    </button>

                    <button
                      type="button"
                      data-testid="chmx-remove-trusted-btn"
                      onClick={() => void handleRemoveTrusted(tk.publicKeyBase64Url)}
                      className="chmx-btn chmx-btn-danger"
                    >
                      <TrashIcon />
                      <span>{t.trusted.removeBtn}</span>
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
