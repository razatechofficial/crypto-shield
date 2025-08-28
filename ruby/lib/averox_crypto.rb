##
# salman 40 - Enterprise Cryptographic SDK for Ruby
# Generated: 2025-08-28T10:26:18.966Z

require 'openssl'
require 'base64'
require 'securerandom'

class AveroxCrypto
  def initialize(master_key)
    raise ArgumentError, 'Master key must be at least 32 bytes' if master_key.length < 32
    @master_key = master_key
  end
  
  def encrypt(plaintext, aad = nil)
    key = derive_key
    iv = SecureRandom.random_bytes(12)
    
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv
    cipher.auth_data = aad if aad
    
    ciphertext = cipher.update(plaintext) + cipher.final
    tag = cipher.auth_tag
    
    {
      iv: Base64.encode64(iv).strip,
      ciphertext: Base64.encode64(ciphertext).strip,
      tag: Base64.encode64(tag).strip
    }
  end
  
  def decrypt(encrypted, aad = nil)
    key = derive_key
    iv = Base64.decode64(encrypted[:iv])
    ciphertext = Base64.decode64(encrypted[:ciphertext])
    tag = Base64.decode64(encrypted[:tag])
    
    decipher = OpenSSL::Cipher.new('aes-256-gcm')
    decipher.decrypt
    decipher.key = key
    decipher.iv = iv
    decipher.auth_tag = tag
    decipher.auth_data = aad if aad
    
    decipher.update(ciphertext) + decipher.final
  end
  
  private
  
  def derive_key
    OpenSSL::PKCS5.pbkdf2_hmac(@master_key, 'averox-salt', 100000, 32, OpenSSL::Digest::SHA256.new)
  end
end