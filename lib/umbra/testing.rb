require "securerandom"
require "umbra"

module Umbra
  # AS のテスト用に、認証サーバの代わりにトークンを発行します。
  #
  #   require "umbra/testing"
  #   issuer = Umbra::Testing::Issuer.new(issuer: "https://an.umr.biz", audience: "umr")
  #   client = issuer.client                    # 認証サーバへ通信しない Umbra::Client
  #   issuer.attach(existing_client)            # 既存のクライアントを通信しないようにする
  #   token  = issuer.token(sub: "user-1", headers: { "User-Agent" => "test" })
  #
  # seal / unseal は認証サーバの鍵が必要なので、通信しないクライアントでは Umbra::Error になります。
  module Testing
    class Issuer
      attr_reader :issuer, :audience, :base_path, :binding_headers

      # binding_headers を空にすると、端末との紐づけ（bnd）なしのトークンになります。
      def initialize(issuer: "https://auth.test", audience: "test", base_path: "/auth", binding_headers: ["User-Agent"])
        @issuer = issuer
        @audience = audience
        @base_path = base_path
        @binding_headers = binding_headers
        @key = OpenSSL::PKey::EC.generate("prime256v1")
        @kid = "umbra-testing-#{SecureRandom.hex(4)}"
      end

      # 認証サーバが発行するものと同じクレームのトークンです。claims で上書き・追加できます。
      def token(sub:, headers: {}, ttl: 3600, **claims)
        now = Time.now.to_i
        payload = {
          "iss" => issuer,
          "sub" => sub,
          "aud" => audience,
          "iat" => now,
          "nbf" => now,
          "exp" => now + ttl,
          "jti" => SecureRandom.hex(16),
          "preferred_username" => sub,
          "name" => sub,
          "gen" => 0
        }
        payload["bnd"] = TokenBinding.compute(binding_headers, headers) unless binding_headers.empty?
        payload.merge!(claims.transform_keys(&:to_s))
        JWT.encode(payload, @key, "ES256", { kid: @kid })
      end

      def client(**options)
        attach(Client.new(server_url: issuer, issuer: issuer, audience: audience, base_path: base_path, **options))
      end

      def attach(client)
        client.instance_variable_set(:@umbra_testing_issuer, self)
        client.extend(Offline)
      end

      # 認証サーバの GET <base_path>/configuration と同じ形です。
      def configuration
        {
          "issuer" => issuer,
          "jwks_path" => "#{base_path}/jwks.json",
          "audiences" => [audience],
          "token_binding" => {
            "enabled" => !binding_headers.empty?,
            "claim" => "bnd",
            "headers" => binding_headers.map(&:downcase)
          }
        }
      end

      def jwks
        { "keys" => [JWT::JWK.new(@key, { kid: @kid }).export] }
      end

      def response_for(path)
        case path
        when "#{base_path}/configuration" then configuration
        when "#{base_path}/jwks.json" then jwks
        else raise Error, "GET #{path} failed: 404"
        end
      end
    end

    module Offline
      private

      def get_json(path, symbolize_names: false)
        JSON.parse(JSON.generate(@umbra_testing_issuer.response_for(path)), symbolize_names: symbolize_names)
      end

      def post(path, _body, _headers)
        raise Error, "POST #{path} is not available in Umbra::Testing"
      end
    end
  end
end
