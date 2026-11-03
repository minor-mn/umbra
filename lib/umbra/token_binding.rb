require "openssl"

module Umbra
  # トークンと端末の紐づけ（bnd クレーム）です。
  module TokenBinding
    module_function

    # 認証サーバと同じ手順です: base64url(sha256("小文字のヘッダー名:値\n" を設定順に連結))
    def compute(names, headers)
      material = names.map { |name| "#{name.downcase}:#{header_value(headers, name)}\n" }.join
      [OpenSSL::Digest::SHA256.digest(material)].pack("m0").tr("+/", "-_").delete("=")
    end

    # Rack の env（HTTP_USER_AGENT）と、通常のヘッダーの Hash の両方を受け付けます。
    def header_value(headers, name)
      rack_key = name.casecmp?("Content-Type") ? "CONTENT_TYPE" : "HTTP_#{name.upcase.tr("-", "_")}"
      headers[rack_key] || headers.find { |key, _| key.to_s.casecmp?(name) }&.last || ""
    end
  end
end
