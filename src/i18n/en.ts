import type { ChmExchangeMessages } from './types.js';

export const enMessages: ChmExchangeMessages = {
  headerTitle: 'CHM Public-Key Exchange',
  headerSubtitle:
    'Share your Ed25519 artist public key via portable URLs, QR codes, or JSON, and verify contacts locally without servers.',
  trustNoticeTitle: 'No Central Authority — Public Keys Only',
  trustNoticeBody:
    'A valid Ed25519 key or signature only proves control of the matching private key — never real-world identity or human-made authorship. Received keys always start Unverified until you confirm their fingerprint out-of-band and explicitly trust them locally.',
  tabs: {
    share: 'Share My Public Key',
    receive: 'Receive Public Key',
    trusted: 'Trusted Artists',
  },
  share: {
    sectionTitle: 'Share My Public Key',
    sectionSubtitle:
      'Generate a portable #key= exchange link, scannable QR code, or JSON bundle containing ONLY your public key and display name.',
    noIdentitiesTitle: 'No Signing Identity Found',
    noIdentitiesBody:
      'Create or restore an Ed25519 artist signing key in your host application first, then return here to share its public key.',
    selectIdentityLabel: 'Select Artist Identity',
    displayNameLabel: 'Public Display Name (optional, max 64 UTF-8 bytes)',
    displayNamePlaceholder: 'e.g., YomiPlush',
    displayNameHint:
      'Included only as self-declared public metadata in the shared link or JSON.',
    fingerprintShortLabel: 'Short Fingerprint',
    fingerprintFullLabel: 'SHA-256 Fingerprint',
    publicKeyLabel: 'Ed25519 Public Key (Base64url)',
    algorithmLabel: 'Algorithm',
    exchangeUrlLabel: 'Portable Exchange URL',
    copyUrlBtn: 'Copy Exchange Link',
    copiedBtn: 'Copied!',
    copyPublicKeyBtn: 'Copy Public Key',
    downloadQrPngBtn: 'Download QR PNG',
    exportJsonBtn: 'Export JSON',
    nativeShareBtn: 'Share…',
    nativeShareText: 'Certified Handmade Ed25519 Public Key',
    qrCaption: 'Scan to inspect & verify fingerprint locally',
    qrAlt: 'QR code encoding the CHM-Exchange public-key URL',
    privateKeyBoundaryNote:
      'Private keys, non-extractable CryptoKey handles, and encrypted backups never leave your host storage or enter exchange payloads.',
  },
  receive: {
    sectionTitle: 'Receive & Inspect Public Key',
    sectionSubtitle:
      'Paste an exchange URL, scan a QR code, or load a public-key JSON file. Fingerprints are always recomputed locally.',
    inputModePaste: 'Paste URL / Key / JSON',
    inputModeQrImage: 'Upload QR Image',
    inputModeCamera: 'Scan QR Camera',
    inputModeJsonFile: 'Upload JSON File',
    pasteLabel: 'Exchange URL (#key=...), Raw Base64url Public Key, or JSON Bundle',
    pastePlaceholder: 'https://certified-handmade.com/exchange#key=...',
    inspectBtn: 'Validate & Inspect Key',
    clearBtn: 'Clear',
    qrImageDropLabel: 'Select or drop a QR code image (PNG, JPEG, WebP)',
    qrImageDropHint: 'Decoded locally in your browser. Nothing is uploaded.',
    jsonFileLabel: 'Select a public-key JSON file (.json)',
    jsonFileHint:
      'Supports both CHM-Exchange v1 and Certified Handmade public-key JSON exports.',
    cameraStartBtn: 'Start Camera Scan',
    cameraStopBtn: 'Stop Camera',
    cameraHint: 'Camera video stays strictly on your device. Center the QR code in frame.',
    cameraError:
      'Unable to access camera. Check browser permissions or upload a QR image instead.',
    resultTitle: 'Inspected Public Key',
    statusTrusted: 'Locally Trusted Key',
    statusUnverified: 'Unverified / Not Locally Trusted',
    statusOwnKeyNote: 'Note: This public key matches one of your own local signing identities.',
    statusDuplicateNote:
      'Duplicate check: This exact public key is already in your Trusted Artists list.',
    unverifiedWarning:
      'Unknown / Unverified: Confirm this fingerprint directly with the artist (e.g., via their official website or direct message) before trusting it.',
    declaredNameLabel: 'Self-Declared Display Name',
    noDeclaredName: 'None specified',
    recomputedFingerprintShortLabel: 'Locally Computed Short Fingerprint',
    recomputedFingerprintFullLabel: 'Locally Computed SHA-256 Fingerprint',
    publicKeyLabel: 'Ed25519 Public Key (Base64url)',
    sourceKindLabel: 'Import Source',
    sourceKinds: {
      'exchange-url': 'Exchange URL (#key=...)',
      'exchange-token': 'Encoded Exchange Token',
      'exchange-json': 'CHM-Exchange JSON Bundle',
      'host-json': 'Certified Handmade Public-Key JSON',
      'raw-public-key': 'Raw Ed25519 Public Key',
    },
    confirmTrustTitle: 'Explicit Local Trust Confirmation',
    confirmLabelInput: 'Local Artist Name / Label',
    confirmLabelPlaceholder: 'e.g., YomiPlush (Verified on website)',
    confirmNoteInput: 'Verification Note (optional)',
    confirmNotePlaceholder: 'e.g., Fingerprint confirmed via artist website on 2026-11-23',
    confirmCheckboxLabel:
      'I have independently verified this fingerprint and understand that a valid key proves control of a private key, not real-world identity.',
    confirmTrustBtn: 'Trust This Artist Key Locally',
    alreadyTrustedNote: 'Already saved in your local Trusted Artists list.',
    trustSavedBanner: 'Artist public key added to your local Trusted Artists list.',
  },
  trusted: {
    sectionTitle: 'Trusted Artists',
    sectionSubtitle:
      'Public keys you have explicitly confirmed and stored locally. Removing trust does not invalidate past cryptographic signatures.',
    emptyState:
      'No trusted artists added yet. Inspect a key in "Receive Public Key" to add one after confirming its fingerprint.',
    fingerprintLabel: 'Fingerprint',
    publicKeyLabel: 'Ed25519 Public Key',
    noteLabel: 'Verification Note',
    addedAtLabel: 'Trusted At',
    copyKeyBtn: 'Copy Public Key',
    copyFingerprintBtn: 'Copy Fingerprint',
    copiedBtn: 'Copied!',
    removeBtn: 'Remove Trust',
    removeConfirm:
      'Remove this artist key from your local Trusted Artists list? Artwork signatures using this key will appear as Unknown until re-trusted.',
    countLabel: 'trusted',
  },
};
