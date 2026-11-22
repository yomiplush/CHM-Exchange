# Contributing to CHM-Exchange

Thank you for helping improve `@yomiplush/chm-exchange`.

## Architectural Rules

1. **Public Keys Only:** Never introduce private-key generation, signing, or backup decryption into this repository. Keep custody strictly inside host adapters.
2. **Zero Backend & Zero Telemetry:** Do not add network fetches, remote APIs, analytics, or external font/script URLs.
3. **Strict Input Validation:** Any new field or input parser must validate UTF-8 strictness, canonical Base64url, payload sizes, and recomputed fingerprints.
4. **Scoped CSS Only:** All styling in `src/react/styles.css` must stay scoped under `.chmx-*` classes and `--chmx-*` CSS custom properties so host apps are never disrupted.

## Local Setup

```bash
npm install
npm run typecheck
npm run lint
npm test
npm run build
npm run example
```

## Pull Request Checklist

- All unit, security, QR, and React UI tests pass (`npm test`).
- Typecheck (`npm run typecheck`), ESLint (`npm run lint`), and ESM build (`npm run build`) pass cleanly.
- New protocol behaviors or constraints are reflected in `SPEC.md` and `SECURITY.md`.
