require "jwt"
require "json"
require "net/http"
require "openssl"

module Umbra
  # request は Rack::Request（Sinatra / Rails の request）です。トークンは Authorization ヘッダーから読みます。
  # seal / unseal では、利用者のトークンと、端末との紐づけに使うヘッダー（User-Agent など）を
  # そのまま HTTP ヘッダーに付けて認証サーバを呼びます。
  class Client
    def initialize(server_url:, issuer:, audience:, base_path: "/auth", cache_seconds: 300, leeway: 30, timeout: 10)
      @server = URI(server_url)
      @base_path = base_path
      @issuer = issuer
      @audience = audience
      @cache_seconds = cache_seconds
      @leeway = leeway
      @timeout = timeout
      @cache = {}
      @mutex = Mutex.new
    end

    # 署名、iss、aud、exp、端末との紐づけ（bnd）を確認して、クレームを返します。
    # 失効（ログアウト）は認証サーバでしか確認できないため、ここでは有効期限まで有効として扱います。
    def authenticate(request)
      verify(bearer_token(request), request.env)
    end

    def verify(token, headers)
      raise InvalidToken, "missing token" if token.nil? || token.empty?

      claims, = JWT.decode(
        token, nil, true,
        algorithms: ["ES256"], jwks: method(:jwks),
        iss: @issuer, verify_iss: true, aud: @audience, verify_aud: true, leeway: @leeway
      )
      binding = configuration.fetch("token_binding")
      if binding["enabled"] && !OpenSSL.secure_compare(claims["bnd"].to_s, TokenBinding.compute(binding["headers"], headers))
        raise InvalidToken, "token is bound to another device"
      end
      claims
    rescue JWT::DecodeError => e
      raise InvalidToken, e.message
    end

    def seal(request, data)
      call_sealing("/seal", request, data: data).fetch("sealed")
    end

    def unseal(request, sealed)
      call_sealing("/unseal", request, sealed: sealed).fetch("data")
    rescue Error
      nil
    end

    private

    def call_sealing(path, request, body)
      headers = configuration.dig("token_binding", "headers").to_h { |name| [name, TokenBinding.header_value(request.env, name)] }
      headers["Authorization"] = "Bearer #{bearer_token(request)}"
      response = post(path, body, headers)
      body = JSON.parse(response.body)
      raise InvalidToken, body["error"] if response.code == "401"
      raise Error, body["error"] unless response.code == "200"

      body
    end

    def bearer_token(request)
      request.env["HTTP_AUTHORIZATION"].to_s[/\ABearer\s+(.+)\z/i, 1]
    end

    def configuration
      cached(:configuration) { get_json("#{@base_path}/configuration") }
    end

    # ruby-jwt は未知の kid を見つけると kid_not_found: true で呼び直すので、その時は取り直します。
    def jwks(options)
      @mutex.synchronize { @cache.delete(:jwks) } if options[:kid_not_found]
      cached(:jwks) { get_json(configuration.fetch("jwks_path"), symbolize_names: true) }
    end

    def cached(key)
      @mutex.synchronize do
        entry = @cache[key]
        return entry[:value] if entry && Time.now - entry[:at] < @cache_seconds
      end
      value = yield
      @mutex.synchronize { @cache[key] = { value: value, at: Time.now } }
      value
    end

    def get_json(path, symbolize_names: false)
      response = http { |connection| connection.get(path) }
      raise Error, "GET #{path} failed: #{response.code}" unless response.code == "200"

      JSON.parse(response.body, symbolize_names: symbolize_names)
    end

    def post(path, body, headers)
      request = Net::HTTP::Post.new("#{@base_path}#{path}")
      headers.each { |name, value| request[name] = value }
      request["Content-Type"] = "application/json"
      request.body = body.to_json
      http { |connection| connection.request(request) }
    end

    def http(&block)
      Net::HTTP.start(@server.host, @server.port, use_ssl: @server.scheme == "https", open_timeout: @timeout, read_timeout: @timeout, &block)
    end
  end
end
