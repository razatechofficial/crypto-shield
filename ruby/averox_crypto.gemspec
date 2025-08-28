Gem::Specification.new do |spec|
  spec.name          = "salman-40-crypto-sdk"
  spec.version       = "2.0.0"
  spec.authors       = ["Averox"]
  spec.email         = ["support@averox.com"]
  spec.summary       = "Production-grade cryptographic SDK for salman 40"
  spec.description   = "Enterprise encryption SDK with AES-256-GCM implementation"
  spec.homepage      = "https://averox.com"
  spec.license       = "MIT"
  
  spec.files         = Dir["lib/**/*"]
  spec.require_paths = ["lib"]
  
  spec.required_ruby_version = ">= 2.7.0"
end