# umbra

Umbra is the Ruby client for crystal-p2p-server: it verifies passkey-issued access tokens in your app and seals personal data, without a round trip per request.

crystal-p2p-server のパスキー認証を、AS（認証サーバを利用するアプリケーションサーバ）から使うためのクライアントです。

## インストール

```ruby
gem "umbra", git: "..."   # または path: "../umbra"
```

依存は `jwt`（2.10 以降、4 未満）だけです。

## 使い方

```ruby
require "umbra"

auth = Umbra::Client.new(
  server_url: "https://an.umr.biz",
  issuer: "https://an.umr.biz",
  audience: "umr"
  # base_path: "/auth", cache_seconds: 300, leeway: 30, timeout: 10
)

claims = auth.authenticate(request)   # 認証サーバへの通信なし。無効なら Umbra::InvalidToken
claims["sub"]                         # 認証サーバのユーザーID
claims["name"]                        # ニックネーム

sealed = auth.seal(request, { "email" => "user@example.com" })
data   = auth.unseal(request, sealed) # 復号できなければ nil
```

`request` は Rack::Request（Rails / Sinatra の `request`）です。トークンは `Authorization: Bearer` ヘッダーから読みます。ヘッダーの Hash を直接渡す場合は `auth.verify(token, headers)` を使います。

### トークンの検証

`authenticate` / `verify` は、署名（ES256）、`iss`、`aud`、`exp`、端末との紐づけ（`bnd`）を確認して、クレームを返します。

- JWKS と `<base_path>/configuration` は `cache_seconds` の間キャッシュします。知らない `kid` のトークンが来たら JWKS を取り直します。
- 失効（ログアウト）は認証サーバでしか分からないため、有効期限までは有効として扱います。

### 個人情報の暗号化

`seal` / `unseal` は認証サーバの `/seal` / `/unseal` を呼びます。利用者のトークンと、紐づけに使うヘッダー（`User-Agent` など）を、受け取った値のまま付けます。暗号文は利用者に返して保存してもらい、AS も認証サーバも保存しません。

- 401 のときは `Umbra::InvalidToken` になります。
- それ以外のエラーのとき、`seal` は `Umbra::Error` になり、`unseal` は `nil` を返します。

## テスト用ヘルパー

`umbra/testing` を読み込むと、認証サーバの代わりにテスト用の鍵でトークンを発行できます。

```ruby
require "umbra/testing"

issuer = Umbra::Testing::Issuer.new(issuer: "https://an.umr.biz", audience: "umr")
issuer.attach(auth)   # 既存のクライアントを、認証サーバへ通信しないようにする
# client = issuer.client でも作れます

token = issuer.token(sub: "user-1", headers: { "User-Agent" => "test" }, name: "Nick")
get "/v1/user/me", headers: { "Authorization" => "Bearer #{token}", "User-Agent" => "test" }
```

- `token` には、認証サーバと同じクレームが入ります。キーワード引数でクレームを上書き・追加できます（`aud:`、`ttl: -60` など）。
- `binding_headers: []` にすると、端末との紐づけなしになります。
- 通信しないクライアントでは、`seal` は `Umbra::Error` になり、`unseal` は `nil` を返します。

## 開発

```sh
bundle install
bundle exec rake
```

jwt 2.x で確認する場合は `JWT_VERSION="~> 2.10" bundle update jwt` を実行します。
