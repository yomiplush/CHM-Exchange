import { enMessages } from './en.js';
import { jaMessages } from './ja.js';
import type { ChmExchangeLocale, ChmExchangeMessages } from './types.js';

export type { ChmExchangeLocale, ChmExchangeMessages } from './types.js';
export { enMessages, jaMessages };

export interface DeepPartialMessages {
  headerTitle?: string;
  headerSubtitle?: string;
  trustNoticeTitle?: string;
  trustNoticeBody?: string;
  tabs?: Partial<ChmExchangeMessages['tabs']>;
  share?: Partial<ChmExchangeMessages['share']>;
  receive?: Partial<Omit<ChmExchangeMessages['receive'], 'sourceKinds'>> & {
    sourceKinds?: Partial<ChmExchangeMessages['receive']['sourceKinds']>;
  };
  trusted?: Partial<ChmExchangeMessages['trusted']>;
}

export function getExchangeMessages(
  locale?: ChmExchangeLocale,
  overrides?: DeepPartialMessages,
): ChmExchangeMessages {
  const normalized = (locale ?? 'en').toLowerCase();
  const base = normalized.startsWith('ja') ? jaMessages : enMessages;
  if (!overrides) return base;

  return {
    ...base,
    ...overrides,
    tabs: { ...base.tabs, ...overrides.tabs },
    share: { ...base.share, ...overrides.share },
    receive: {
      ...base.receive,
      ...overrides.receive,
      sourceKinds: {
        ...base.receive.sourceKinds,
        ...overrides.receive?.sourceKinds,
      },
    },
    trusted: { ...base.trusted, ...overrides.trusted },
  };
}
