/**
 * salman 40 - Enterprise Cryptographic SDK for .NET
 * Generated: 2025-08-28T10:28:26.241Z
 */

using System;
using System.Security.Cryptography;
using System.Text;

namespace Averox.Crypto
{
    public class AveroxCrypto : IDisposable
    {
        private readonly byte[] masterKey;
        private bool disposed = false;
        
        public AveroxCrypto(byte[] masterKey)
        {
            if (masterKey == null || masterKey.Length < 32)
                throw new ArgumentException("Master key must be at least 32 bytes");
            
            this.masterKey = new byte[masterKey.Length];
            Array.Copy(masterKey, this.masterKey, masterKey.Length);
        }
        
        public EncryptedData Encrypt(string plaintext, byte[] aad = null)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = DeriveKey();
                aes.Mode = CipherMode.GCM;
                
                var iv = new byte[12];
                RandomNumberGenerator.Fill(iv);
                aes.IV = iv;
                
                var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                var ciphertext = new byte[plaintextBytes.Length];
                var tag = new byte[16];
                
                using (var encryptor = aes.CreateEncryptor())
                {
                    ((AesGcm)encryptor).Encrypt(iv, plaintextBytes, ciphertext, tag, aad);
                }
                
                return new EncryptedData
                {
                    IV = Convert.ToBase64String(iv),
                    Ciphertext = Convert.ToBase64String(ciphertext),
                    Tag = Convert.ToBase64String(tag)
                };
            }
        }
        
        private byte[] DeriveKey()
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(masterKey, Encoding.UTF8.GetBytes("averox-salt"), 100000, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(32);
            }
        }
        
        public void Dispose()
        {
            if (!disposed)
            {
                Array.Clear(masterKey, 0, masterKey.Length);
                disposed = true;
            }
        }
    }
    
    public class EncryptedData
    {
        public string IV { get; set; }
        public string Ciphertext { get; set; }
        public string Tag { get; set; }
    }
}