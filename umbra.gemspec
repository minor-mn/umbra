require_relative "lib/umbra/version"

Gem::Specification.new do |spec|
  spec.name        = "umbra"
  spec.version     = Umbra::VERSION
  spec.authors     = ["LightningDAISY"]
  spec.summary     = "Ruby client for crystal-p2p-server's passkey authentication."
  spec.description = <<~TEXT
    Umbra lets a Rack or Rails application rely on crystal-p2p-server for
    passkey (WebAuthn) authentication. It verifies the ES256 access tokens
    locally against the server's JWKS, checking the signature, issuer,
    audience, expiry and device binding without contacting the server on
    each request. It also wraps the sealing API, which encrypts personal
    data to the token's user so that neither the application nor the
    server has to store it.
  TEXT

  spec.required_ruby_version = ">= 3.2"
  spec.files = Dir["lib/**/*.rb", "README.md"]
  spec.require_paths = ["lib"]

  spec.add_dependency "jwt", ">= 2.10", "< 4"
end
