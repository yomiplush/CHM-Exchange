import type { ChmExchangeMessages } from './types.js';

export const jaMessages: ChmExchangeMessages = {
  headerTitle: 'CHM 公開鍵エクスチェンジ',
  headerSubtitle:
    'Ed25519作者公開鍵をURL・QRコード・JSONで安全に共有し、サーバーなしでローカル検証・信頼登録できます。',
  trustNoticeTitle: '中央認証局なし — 公開鍵のみを共有',
  trustNoticeBody:
    '有効なEd25519鍵や署名は「対応する秘密鍵の保有」を示すのみであり、現実世界の本人性や手描き制作を直接証明するものではありません。受け取った公開鍵は必ず「未検証」から始まり、別経路でフィンガープリントを確認した上で明示的にローカル信頼登録する必要があります。',
  tabs: {
    share: '自分の公開鍵を共有',
    receive: '公開鍵を受け取る',
    trusted: '信頼済みアーティスト',
  },
  share: {
    sectionTitle: '自分の公開鍵を共有',
    sectionSubtitle:
      '公開鍵と表示名のみを含む #key= 共有URL、QRコード、またはJSONバンドルを生成します。',
    noIdentitiesTitle: 'ローカル署名鍵が見つかりません',
    noIdentitiesBody:
      '先にホストアプリ側でEd25519アーティスト鍵を作成または復元してから、この画面で公開鍵を共有してください。',
    selectIdentityLabel: '共有するアーティスト鍵を選択',
    displayNameLabel: '公開表示名（任意・最大64 UTF-8バイト）',
    displayNamePlaceholder: '例：YomiPlush',
    displayNameHint: '共有URLやJSONに自己申告の公開メタデータとして含まれます。',
    fingerprintShortLabel: '短縮フィンガープリント',
    fingerprintFullLabel: 'SHA-256 フィンガープリント',
    publicKeyLabel: 'Ed25519 公開鍵 (Base64url)',
    algorithmLabel: 'アルゴリズム',
    exchangeUrlLabel: '共有エクスチェンジURL',
    copyUrlBtn: '共有リンクをコピー',
    copiedBtn: 'コピーしました',
    copyPublicKeyBtn: '公開鍵をコピー',
    downloadQrPngBtn: 'QR PNGを保存',
    exportJsonBtn: 'JSONを書き出し',
    nativeShareBtn: '共有…',
    nativeShareText: 'Certified Handmade Ed25519 公開鍵',
    qrCaption: 'スキャンしてローカルでフィンガープリントを確認',
    qrAlt: 'CHM-Exchange 公開鍵URLを格納したQRコード',
    privateKeyBoundaryNote:
      '秘密鍵、非抽出可能なCryptoKeyハンドル、暗号化バックアップは共有データに一切含まれません。',
  },
  receive: {
    sectionTitle: '公開鍵の受け取りと検証',
    sectionSubtitle:
      '共有URLの貼り付け、QRコードの読み取り、またはJSONファイル読み込みで公開鍵を検査します。フィンガープリントは常に端末内で再計算されます。',
    inputModePaste: 'URL / 公開鍵 / JSONを貼り付け',
    inputModeQrImage: 'QR画像を読み込む',
    inputModeCamera: 'カメラでQRスキャン',
    inputModeJsonFile: 'JSONファイルを読み込む',
    pasteLabel: '共有URL (#key=...)、Base64url公開鍵、またはJSONバンドル',
    pastePlaceholder: 'https://certified-handmade.com/exchange#key=...',
    inspectBtn: '公開鍵を検証・表示',
    clearBtn: 'クリア',
    qrImageDropLabel: 'QRコード画像（PNG / JPEG / WebP）を選択またはドロップ',
    qrImageDropHint: 'ブラウザ内でローカル解析され、外部へ送信されません。',
    jsonFileLabel: '公開鍵JSONファイル（.json）を選択',
    jsonFileHint:
      'CHM-Exchange v1 形式および Certified Handmade 公開鍵JSONの両方に対応しています。',
    cameraStartBtn: 'カメラスキャン開始',
    cameraStopBtn: 'カメラ停止',
    cameraHint: 'カメラ映像は端末内のみで処理されます。QRコードを枠内に収めてください。',
    cameraError:
      'カメラにアクセスできませんでした。ブラウザ権限を確認するか、QR画像をアップロードしてください。',
    resultTitle: '検査結果',
    statusTrusted: 'ローカル信頼済みの鍵',
    statusUnverified: '未検証 / ローカル未信頼の鍵',
    statusOwnKeyNote: 'メモ：この公開鍵はあなた自身のローカル署名鍵と一致しています。',
    statusDuplicateNote:
      '重複チェック：この公開鍵はすでに「信頼済みアーティスト」に登録されています。',
    unverifiedWarning:
      '未確認の公開鍵です。信頼登録する前に、必ず作者の公式サイトや公式SNSなどの別経路でフィンガープリントが一致することを確認してください。',
    declaredNameLabel: '自己申告の表示名',
    noDeclaredName: '指定なし',
    recomputedFingerprintShortLabel: 'ローカル再計算 短縮フィンガープリント',
    recomputedFingerprintFullLabel: 'ローカル再計算 SHA-256 フィンガープリント',
    publicKeyLabel: 'Ed25519 公開鍵 (Base64url)',
    sourceKindLabel: '入力形式',
    sourceKinds: {
      'exchange-url': '共有URL (#key=...)',
      'exchange-token': 'エンコード済みトークン',
      'exchange-json': 'CHM-Exchange JSONバンドル',
      'host-json': 'Certified Handmade 公開鍵JSON',
      'raw-public-key': '生Ed25519公開鍵',
    },
    confirmTrustTitle: 'ローカル信頼の明示的確認',
    confirmLabelInput: 'ローカル表示名（アーティスト名など）',
    confirmLabelPlaceholder: '例：YomiPlush（公式サイトで確認済み）',
    confirmNoteInput: '確認メモ（任意）',
    confirmNotePlaceholder: '例：2026-11-23 公式サイトにてフィンガープリント一致を確認',
    confirmCheckboxLabel:
      '別経路でこのフィンガープリントを本人確認し、公開鍵が秘密鍵の保有のみを示すこと（現実の本人確認ではないこと）を理解しました。',
    confirmTrustBtn: 'このアーティスト鍵をローカル信頼登録する',
    alreadyTrustedNote: 'この鍵はすでにローカルの信頼済みアーティストに登録されています。',
    trustSavedBanner: 'アーティスト公開鍵をローカルの信頼済みリストに追加しました。',
  },
  trusted: {
    sectionTitle: '信頼済みアーティスト',
    sectionSubtitle:
      'あなたが明示的に確認してローカル保存した公開鍵一覧です。信頼を削除しても、過去の暗号署名の数学的有効性自体は失われません。',
    emptyState:
      '信頼済みアーティストはまだありません。「公開鍵を受け取る」からフィンガープリントを確認して登録できます。',
    fingerprintLabel: 'フィンガープリント',
    publicKeyLabel: 'Ed25519 公開鍵',
    noteLabel: '確認メモ',
    addedAtLabel: '信頼登録日時',
    copyKeyBtn: '公開鍵をコピー',
    copyFingerprintBtn: 'フィンガープリントをコピー',
    copiedBtn: 'コピーしました',
    removeBtn: '信頼を削除',
    removeConfirm:
      'このアーティスト鍵をローカルの信頼済みリストから削除しますか？削除後は再登録するまで署名検証時に「未確認の鍵」として表示されます。',
    countLabel: '件信頼済み',
  },
};
