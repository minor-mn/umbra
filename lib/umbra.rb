require "umbra/version"
require "umbra/token_binding"
require "umbra/client"

# crystal-p2p-server の認証を使う AS（アプリケーションサーバ）向けのクライアントです。
#
#   auth = Umbra::Client.new(server_url: "https://an.umr.biz", issuer: "https://an.umr.biz", audience: "umr")
#   claims = auth.authenticate(request)        # 毎回のリクエスト。認証サーバへの通信なし
#   sealed = auth.seal(request, { "email" => "..." })
#   data   = auth.unseal(request, sealed)      # 復号できなければ nil
module Umbra
  class InvalidToken < StandardError; end
  class Error < StandardError; end
end
