Pod::Spec.new do |spec|
  spec.name          = "AveroxCryptoSDK"
  spec.version       = "1.0.0" 
  spec.summary       = "Enterprise cryptographic SDK for iOS/macOS"
  spec.homepage      = "https://github.com/averox/crypto-sdk"
  spec.license       = { :type => "MIT", :file => "LICENSE" }
  spec.author        = "Averox Security"
  
  spec.ios.deployment_target = "12.0"
  spec.osx.deployment_target = "10.14"
  
  spec.source        = { :git => "https://github.com/averox/crypto-sdk.git", :tag => spec.version }
  spec.source_files  = "src/**/*.{h,c,swift}"
  spec.public_header_files = "include/**/*.h"
  
  spec.dependency "OpenSSL-Universal", "~> 1.1.180"
  
  spec.pod_target_xcconfig = {
    'CLANG_CXX_LANGUAGE_STANDARD' => 'c++17',
    'CLANG_CXX_LIBRARY' => 'libc++',
    'OTHER_CFLAGS' => '-fstack-protector-strong'
  }
end