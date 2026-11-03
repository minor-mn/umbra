require "test_helper"

class ClientTest < Minitest::Test
  def setup
    @issuer = Umbra::Testing::Issuer.new(issuer: "https://an.umr.biz", audience: "umr")
    @client = @issuer.client
  end

  def test_authenticate_returns_claims
    token = @issuer.token(sub: "user-1", headers: { "User-Agent" => "test-agent" }, name: "Nick")
    claims = @client.authenticate(rack_request(token))

    assert_equal "user-1", claims["sub"]
    assert_equal "Nick", claims["name"]
  end

  def test_verify_accepts_plain_headers
    token = @issuer.token(sub: "user-1", headers: { "user-agent" => "test-agent" })

    assert_equal "user-1", @client.verify(token, { "User-Agent" => "test-agent" })["sub"]
  end

  def test_missing_token
    assert_raises(Umbra::InvalidToken) { @client.authenticate(rack_request(nil)) }
  end

  def test_other_device
    token = @issuer.token(sub: "user-1", headers: { "User-Agent" => "test-agent" })

    error = assert_raises(Umbra::InvalidToken) { @client.authenticate(rack_request(token, user_agent: "other")) }
    assert_match(/another device/, error.message)
  end

  def test_binding_disabled
    issuer = Umbra::Testing::Issuer.new(audience: "umr", binding_headers: [])
    token = issuer.token(sub: "user-1")

    assert_equal "user-1", issuer.client.authenticate(rack_request(token, user_agent: "any"))["sub"]
  end

  def test_wrong_audience
    token = @issuer.token(sub: "user-1", headers: { "User-Agent" => "test-agent" }, aud: "p2p")

    assert_raises(Umbra::InvalidToken) { @client.authenticate(rack_request(token)) }
  end

  def test_audience_list
    token = @issuer.token(sub: "user-1", headers: { "User-Agent" => "test-agent" }, aud: ["p2p", "umr"])

    assert_equal "user-1", @client.authenticate(rack_request(token))["sub"]
  end

  def test_wrong_issuer
    token = @issuer.token(sub: "user-1", headers: { "User-Agent" => "test-agent" }, iss: "https://evil.test")

    assert_raises(Umbra::InvalidToken) { @client.authenticate(rack_request(token)) }
  end

  def test_expired
    token = @issuer.token(sub: "user-1", headers: { "User-Agent" => "test-agent" }, ttl: -60)

    assert_raises(Umbra::InvalidToken) { @client.authenticate(rack_request(token)) }
  end

  def test_within_leeway
    token = @issuer.token(sub: "user-1", headers: { "User-Agent" => "test-agent" }, ttl: -10)

    assert_equal "user-1", @client.authenticate(rack_request(token))["sub"]
  end

  def test_signed_by_another_key
    other = Umbra::Testing::Issuer.new(issuer: "https://an.umr.biz", audience: "umr")
    token = other.token(sub: "user-1", headers: { "User-Agent" => "test-agent" })

    assert_raises(Umbra::InvalidToken) { @client.authenticate(rack_request(token)) }
  end

  def test_tampered_payload
    header, payload, signature = @issuer.token(sub: "user-1", headers: { "User-Agent" => "test-agent" }).split(".")
    claims = JSON.parse((payload + "=" * (-payload.size % 4)).tr("-_", "+/").unpack1("m0"))
    claims["sub"] = "admin"
    forged = [header, [claims.to_json].pack("m0").tr("+/", "-_").delete("="), signature].join(".")

    assert_raises(Umbra::InvalidToken) { @client.authenticate(rack_request(forged)) }
  end

  def test_refetches_jwks_for_unknown_kid
    first = Umbra::Testing::Issuer.new(issuer: "https://an.umr.biz", audience: "umr")
    rotated = Umbra::Testing::Issuer.new(issuer: "https://an.umr.biz", audience: "umr")
    client = first.client
    client.verify(first.token(sub: "user-1", headers: { "User-Agent" => "a" }), { "User-Agent" => "a" })

    rotated.attach(client)
    token = rotated.token(sub: "user-2", headers: { "User-Agent" => "a" })

    assert_equal "user-2", client.verify(token, { "User-Agent" => "a" })["sub"]
  end
end
