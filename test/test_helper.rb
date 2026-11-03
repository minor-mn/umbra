$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "umbra"
require "umbra/testing"
require "minitest/autorun"

FakeRequest = Struct.new(:env)
FakeResponse = Struct.new(:code, :body)

def rack_request(token, user_agent: "test-agent")
  env = { "HTTP_USER_AGENT" => user_agent }
  env["HTTP_AUTHORIZATION"] = "Bearer #{token}" if token
  FakeRequest.new(env)
end
