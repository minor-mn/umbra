require "test_helper"

class SealingTest < Minitest::Test
  def setup
    @issuer = Umbra::Testing::Issuer.new(issuer: "https://an.umr.biz", audience: "umr")
    @client = @issuer.client
    @token = @issuer.token(sub: "user-1", headers: { "User-Agent" => "test-agent" })
  end

  def stub_post(code, body)
    calls = []
    @client.define_singleton_method(:post) do |path, payload, headers|
      calls << { path: path, payload: payload, headers: headers }
      FakeResponse.new(code, body.to_json)
    end
    calls
  end

  def test_seal_forwards_token_and_binding_headers
    calls = stub_post("200", { sealed: "ciphertext" })

    assert_equal "ciphertext", @client.seal(rack_request(@token), { "email" => "a@example.com" })
    assert_equal "/seal", calls[0][:path]
    assert_equal({ data: { "email" => "a@example.com" } }, calls[0][:payload])
    assert_equal({ "user-agent" => "test-agent", "Authorization" => "Bearer #{@token}" }, calls[0][:headers])
  end

  def test_unseal
    stub_post("200", { data: { "email" => "a@example.com" } })

    assert_equal({ "email" => "a@example.com" }, @client.unseal(rack_request(@token), "ciphertext"))
  end

  def test_unseal_returns_nil_when_unsealable
    stub_post("422", { error: "unsealable" })

    assert_nil @client.unseal(rack_request(@token), "broken")
  end

  def test_invalid_token_on_401
    stub_post("401", { error: "invalid_token" })

    assert_raises(Umbra::InvalidToken) { @client.unseal(rack_request(@token), "ciphertext") }
  end

  def test_offline_client_cannot_seal
    assert_raises(Umbra::Error) { @client.seal(rack_request(@token), {}) }
  end
end
