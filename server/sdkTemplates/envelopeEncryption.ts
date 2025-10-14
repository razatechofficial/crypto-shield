/**
 * Envelope Encryption SDK Template
 * Generates SDK code with Vault KMS integration for envelope encryption
 */

export interface VaultConfig {
  vaultEndpoint: string;
  vaultToken: string;
  kekName: string;
  transitMount: string;
}

/**
 * Generate JavaScript/TypeScript envelope encryption code
 */
export function generateEnvelopeEncryptionJS(config: VaultConfig): string {
  return `/**
 * Envelope Encryption with HashiCorp Vault KMS
 * 
 * Architecture:
 * 1. Generate DEK (Data Encryption Key) locally - 32 bytes random
 * 2. Encrypt data with DEK using AES-256-GCM
 * 3. Encrypt DEK with KEK (Key Encryption Key) via Vault
 * 4. Store encrypted DEK with ciphertext
 * 5. For decryption: decrypt DEK with Vault, then decrypt data
 */

const crypto = require('crypto');

class VaultKmsClient {
  constructor(config) {
    this.vaultEndpoint = config.vaultEndpoint || '${config.vaultEndpoint}';
    this.vaultToken = config.vaultToken || '${config.vaultToken}';
    this.kekName = config.kekName || '${config.kekName}';
    this.transitMount = config.transitMount || '${config.transitMount}';
  }

  /**
   * Encrypt DEK with KEK via Vault
   */
  async encryptDEK(dekPlaintext, context = {}) {
    const url = \`\${this.vaultEndpoint}/v1/\${this.transitMount}/encrypt/\${this.kekName}\`;
    
    const payload = {
      plaintext: Buffer.from(dekPlaintext).toString('base64'),
      context: context ? Buffer.from(JSON.stringify(context)).toString('base64') : undefined
    };

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'X-Vault-Token': this.vaultToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(\`Vault encrypt failed: \${response.statusText}\`);
    }

    const result = await response.json();
    return result.data.ciphertext;
  }

  /**
   * Decrypt DEK with KEK via Vault
   */
  async decryptDEK(dekCiphertext, context = {}) {
    const url = \`\${this.vaultEndpoint}/v1/\${this.transitMount}/decrypt/\${this.kekName}\`;
    
    const payload = {
      ciphertext: dekCiphertext,
      context: context ? Buffer.from(JSON.stringify(context)).toString('base64') : undefined
    };

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'X-Vault-Token': this.vaultToken,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(\`Vault decrypt failed: \${response.statusText}\`);
    }

    const result = await response.json();
    return Buffer.from(result.data.plaintext, 'base64').toString('utf8');
  }
}

class EnvelopeEncryption {
  constructor(vaultConfig) {
    this.vaultClient = new VaultKmsClient(vaultConfig);
  }

  /**
   * Generate a random DEK (Data Encryption Key)
   */
  generateDEK() {
    return crypto.randomBytes(32); // 256-bit key for AES-256
  }

  /**
   * Encrypt data using envelope encryption
   * Returns: { encryptedData, encryptedDEK, iv, tag, context }
   */
  async encrypt(plaintext, context = {}) {
    try {
      // Step 1: Generate DEK locally
      const dek = this.generateDEK();
      
      // Step 2: Encrypt data with DEK using AES-256-GCM
      const iv = crypto.randomBytes(12); // 96-bit IV for GCM
      const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
      
      let encryptedData = cipher.update(plaintext, 'utf8');
      encryptedData = Buffer.concat([encryptedData, cipher.final()]);
      const tag = cipher.getAuthTag();
      
      // Step 3: Encrypt DEK with KEK via Vault
      const encryptedDEK = await this.vaultClient.encryptDEK(
        dek.toString('base64'),
        context
      );
      
      // Step 4: Return envelope with encrypted DEK and data
      return {
        encryptedData: encryptedData.toString('base64'),
        encryptedDEK: encryptedDEK,
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        context: context,
        algorithm: 'aes-256-gcm',
        version: '1.0'
      };
    } catch (error) {
      throw new Error(\`Envelope encryption failed: \${error.message}\`);
    }
  }

  /**
   * Decrypt data using envelope encryption
   */
  async decrypt(envelope) {
    try {
      // Step 1: Decrypt DEK with KEK via Vault
      const dekPlaintext = await this.vaultClient.decryptDEK(
        envelope.encryptedDEK,
        envelope.context || {}
      );
      
      const dek = Buffer.from(dekPlaintext, 'base64');
      
      // Step 2: Decrypt data with DEK
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        dek,
        Buffer.from(envelope.iv, 'base64')
      );
      
      decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
      
      let decrypted = decipher.update(Buffer.from(envelope.encryptedData, 'base64'));
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return decrypted.toString('utf8');
    } catch (error) {
      throw new Error(\`Envelope decryption failed: \${error.message}\`);
    }
  }

  /**
   * Rotate KEK in Vault (creates new version)
   */
  async rotateKEK() {
    const url = \`\${this.vaultClient.vaultEndpoint}/v1/\${this.vaultClient.transitMount}/keys/\${this.vaultClient.kekName}/rotate\`;
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'X-Vault-Token': this.vaultClient.vaultToken,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(\`KEK rotation failed: \${response.statusText}\`);
    }

    return { success: true, message: 'KEK rotated successfully' };
  }

  /**
   * Re-encrypt data with new KEK version (after rotation)
   */
  async reEncrypt(envelope) {
    // Vault handles this automatically with versioned keys
    // Old encrypted DEKs can still be decrypted with old KEK versions
    // New encryptions will use the latest KEK version
    const plaintext = await this.decrypt(envelope);
    return await this.encrypt(plaintext, envelope.context);
  }
}

// Export for use
module.exports = { EnvelopeEncryption, VaultKmsClient };

// ES Module support
if (typeof exports !== 'undefined') {
  exports.EnvelopeEncryption = EnvelopeEncryption;
  exports.VaultKmsClient = VaultKmsClient;
}
`;
}

/**
 * Generate Python envelope encryption code
 */
export function generateEnvelopeEncryptionPython(config: VaultConfig): string {
  return `"""
Envelope Encryption with HashiCorp Vault KMS

Architecture:
1. Generate DEK (Data Encryption Key) locally - 32 bytes random
2. Encrypt data with DEK using AES-256-GCM
3. Encrypt DEK with KEK (Key Encryption Key) via Vault
4. Store encrypted DEK with ciphertext
5. For decryption: decrypt DEK with Vault, then decrypt data
"""

import os
import base64
import json
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class VaultKmsClient:
    def __init__(self, config):
        self.vault_endpoint = config.get('vaultEndpoint', '${config.vaultEndpoint}')
        self.vault_token = config.get('vaultToken', '${config.vaultToken}')
        self.kek_name = config.get('kekName', '${config.kekName}')
        self.transit_mount = config.get('transitMount', '${config.transitMount}')

    def encrypt_dek(self, dek_plaintext, context=None):
        """Encrypt DEK with KEK via Vault"""
        url = f"{self.vault_endpoint}/v1/{self.transit_mount}/encrypt/{self.kek_name}"
        
        payload = {
            'plaintext': base64.b64encode(dek_plaintext.encode()).decode()
        }
        
        if context:
            payload['context'] = base64.b64encode(json.dumps(context).encode()).decode()
        
        headers = {
            'X-Vault-Token': self.vault_token,
            'Content-Type': 'application/json'
        }
        
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        
        return response.json()['data']['ciphertext']

    def decrypt_dek(self, dek_ciphertext, context=None):
        """Decrypt DEK with KEK via Vault"""
        url = f"{self.vault_endpoint}/v1/{self.transit_mount}/decrypt/{self.kek_name}"
        
        payload = {
            'ciphertext': dek_ciphertext
        }
        
        if context:
            payload['context'] = base64.b64encode(json.dumps(context).encode()).decode()
        
        headers = {
            'X-Vault-Token': self.vault_token,
            'Content-Type': 'application/json'
        }
        
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        
        return base64.b64decode(response.json()['data']['plaintext']).decode()

class EnvelopeEncryption:
    def __init__(self, vault_config):
        self.vault_client = VaultKmsClient(vault_config)

    def generate_dek(self):
        """Generate a random DEK (Data Encryption Key)"""
        return os.urandom(32)  # 256-bit key for AES-256

    def encrypt(self, plaintext, context=None):
        """Encrypt data using envelope encryption"""
        try:
            # Step 1: Generate DEK locally
            dek = self.generate_dek()
            
            # Step 2: Encrypt data with DEK using AES-256-GCM
            aesgcm = AESGCM(dek)
            nonce = os.urandom(12)  # 96-bit nonce for GCM
            
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
            
            # Step 3: Encrypt DEK with KEK via Vault
            encrypted_dek = self.vault_client.encrypt_dek(
                base64.b64encode(dek).decode(),
                context
            )
            
            # Step 4: Return envelope
            return {
                'encryptedData': base64.b64encode(ciphertext).decode(),
                'encryptedDEK': encrypted_dek,
                'nonce': base64.b64encode(nonce).decode(),
                'context': context,
                'algorithm': 'aes-256-gcm',
                'version': '1.0'
            }
        except Exception as e:
            raise Exception(f"Envelope encryption failed: {str(e)}")

    def decrypt(self, envelope):
        """Decrypt data using envelope encryption"""
        try:
            # Step 1: Decrypt DEK with KEK via Vault
            dek_plaintext = self.vault_client.decrypt_dek(
                envelope['encryptedDEK'],
                envelope.get('context')
            )
            
            dek = base64.b64decode(dek_plaintext)
            
            # Step 2: Decrypt data with DEK
            aesgcm = AESGCM(dek)
            nonce = base64.b64decode(envelope['nonce'])
            ciphertext = base64.b64decode(envelope['encryptedData'])
            
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode()
        except Exception as e:
            raise Exception(f"Envelope decryption failed: {str(e)}")
`;
}

/**
 * Generate usage example
 */
export function generateUsageExample(config: VaultConfig): string {
  return `
// Example Usage:

const { EnvelopeEncryption } = require('./envelope-encryption');

// Initialize with Vault configuration
const encryption = new EnvelopeEncryption({
  vaultEndpoint: '${config.vaultEndpoint}',
  vaultToken: '${config.vaultToken}',
  kekName: '${config.kekName}',
  transitMount: '${config.transitMount}'
});

// Encrypt data
async function encryptData() {
  const plaintext = 'Sensitive data to encrypt';
  const context = { userId: 'user123', purpose: 'storage' };
  
  const envelope = await encryption.encrypt(plaintext, context);
  console.log('Encrypted envelope:', envelope);
  
  // Store envelope in database
  // The envelope contains:
  // - encryptedData: Your data encrypted with DEK
  // - encryptedDEK: DEK encrypted with KEK (via Vault)
  // - iv: Initialization vector
  // - tag: Authentication tag
  // - context: Additional context for encryption
  
  return envelope;
}

// Decrypt data
async function decryptData(envelope) {
  const plaintext = await encryption.decrypt(envelope);
  console.log('Decrypted:', plaintext);
  return plaintext;
}

// Rotate KEK
async function rotateKey() {
  await encryption.rotateKEK();
  console.log('KEK rotated successfully');
}

// Run example
(async () => {
  const envelope = await encryptData();
  const decrypted = await decryptData(envelope);
  console.log('Success!', decrypted);
})();
`;
}
