# Cloud Cat v1

Node.js + Express + Socket.IO + PostgreSQL で動くCloud Catスターターです。

機能: ログイン/新規登録、DM、フレンド、通知、グループ作成、コミュニティ作成、画像送信、リアルタイムDM。

## Render
GitHubへこのフォルダの「中身」をリポジトリ直下にアップロードしてください。
Web ServiceのEnvironment Variables:
- DATABASE_URL = Render PostgresのInternal Database URL
- SESSION_SECRET = 長いランダム文字列
- NODE_ENV = production

注意: 画像は初期版ではuploadsへ保存するため、Render本番運用ではCloudflare R2等の永続ストレージへ移行してください。
