# Cloud Cat

Cat Hub と独立したチャットサービスです。PostgreSQL に利用者、フレンド、DM、ルーム、通知、ログを保存します。登録・ログインはアカウント名と bcrypt でハッシュ化したパスワードを使用します。登録時の利用規約同意は必須です。

## 設定

`DATABASE_URL` と十分に長い `SESSION_SECRET` が必須です。`ADMIN_USERS` はカンマ区切りの管理者アカウント名です。`.env.example` にはキー名のみ記載しています。

```sh
npm ci
npm start
```

起動時に `schema.sql` の追加型スキーマ変更を適用します。既存データを削除しません。`/healthz` で DB 接続を確認できます。

## API

`/api/auth`、`/api/me`、`/api/friends`、`/api/dm`、`/api/rooms`、`/api/notifications`、`/api/admin` を提供します。画像は MIME とファイル内容を検証し PostgreSQL に保存します。ルーム管理者は Kick、BAN、BAN解除、メッセージ削除、ルーム削除ができます。管理者はルーム BAN の対象外です。

## 配置

Cat Hub とデータベースを直接共有しない構成を推奨します。Render のサービス環境変数に Cloud Cat 専用の PostgreSQL 接続を設定してください。
