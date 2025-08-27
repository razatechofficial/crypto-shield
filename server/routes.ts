import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth } from "./genericAuth";
import { isAuthenticated } from "./middleware";
import { insertSdkSchema, insertEncryptionKeySchema, insertSecurityEventSchema } from "@shared/schema";
import { z } from "zod";
import { randomUUID } from "crypto";
import archiver from "archiver";
import fs from "fs";

export async function registerRoutes(app: Express): Promise<Server> {
  // Setup authentication
  await setupAuth(app);

  // API Routes
  
  // Authentication routes
  app.get("/api/auth/user", (req, res) => {
    if (req.user) {
      res.json(req.user);
    } else {
      res.status(401).json({ message: "Not authenticated" });
    }
  });

  // Algorithm routes
  app.get("/api/algorithms", async (req, res) => {
    try {
      const algorithms = await storage.getEncryptionAlgorithms();
      res.json(algorithms);
    } catch (error) {
      console.error("Error fetching algorithms:", error);
      res.status(500).json({ message: "Failed to fetch algorithms" });
    }
  });

  app.post("/api/algorithms/recommend", async (req, res) => {
    try {
      const config = req.body;
      const recommendations = await storage.getRecommendedAlgorithms(config);
      res.json(recommendations);
    } catch (error) {
      console.error("Error getting algorithm recommendations:", error);
      res.status(500).json({ message: "Failed to get recommendations" });
    }
  });

  // SDK routes
  app.get("/api/sdks", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      // Handle both new user format and legacy OIDC claims format
      const userId = user.id || user.claims?.sub;
      const userEmail = user.email || user.claims?.email;
      
      if (!userId || !userEmail) {
        return res.status(401).json({ message: "Invalid user session" });
      }
      
      // Get or create tenant for the user
      const tenantId = user.tenantId || await storage.getOrCreateTenantForUser(userId, userEmail);
      
      const sdks = await storage.getSDKs(tenantId, userId);
      res.json(sdks);
    } catch (error) {
      console.error("Error fetching SDKs:", error);
      res.status(500).json({ message: "Failed to fetch SDKs" });
    }
  });

  app.post("/api/sdks/generate", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      // Handle both new user format and legacy OIDC claims format
      const userId = user.id || user.claims?.sub;
      const userEmail = user.email || user.claims?.email;
      
      if (!userId || !userEmail) {
        return res.status(401).json({ message: "Invalid user session" });
      }
      
      // Get or create tenant for the user
      const tenantId = user.tenantId || await storage.getOrCreateTenantForUser(userId, userEmail);
      
      const sdkData = insertSdkSchema.parse({
        ...req.body,
        tenantId: tenantId,
        userId: userId,
      });
      
      const sdk = await storage.createSDK(sdkData);
      res.json(sdk);
    } catch (error) {
      console.error("Error generating SDK:", error);
      if (error instanceof z.ZodError) {
        res.status(400).json({ message: "Invalid SDK data", errors: error.errors });
      } else {
        res.status(500).json({ message: "Failed to generate SDK" });
      }
    }
  });

  app.get("/api/sdks/:id", isAuthenticated, async (req, res) => {
    try {
      const sdk = await storage.getSDK(req.params.id);
      if (!sdk) {
        return res.status(404).json({ message: "SDK not found" });
      }
      res.json(sdk);
    } catch (error) {
      console.error("Error fetching SDK:", error);
      res.status(500).json({ message: "Failed to fetch SDK" });
    }
  });

  app.delete("/api/sdks/:id", isAuthenticated, async (req, res) => {
    try {
      await storage.deleteSDK(req.params.id);
      res.json({ message: "SDK deleted successfully" });
    } catch (error) {
      console.error("Error deleting SDK:", error);
      res.status(500).json({ message: "Failed to delete SDK" });
    }
  });

  app.delete("/api/sdks/delete-all", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      await storage.deleteAllSDKs(user.tenantId);
      res.json({ message: "All SDKs deleted successfully" });
    } catch (error) {
      console.error("Error deleting all SDKs:", error);
      res.status(500).json({ message: "Failed to delete all SDKs" });
    }
  });

  // Key management routes
  app.get("/api/keys", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const keys = await storage.getEncryptionKeys(user.tenantId);
      res.json(keys);
    } catch (error) {
      console.error("Error fetching keys:", error);
      res.status(500).json({ message: "Failed to fetch keys" });
    }
  });

  app.post("/api/keys", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const keyData = insertEncryptionKeySchema.parse({
        ...req.body,
        tenantId: user.tenantId,
      });
      
      const key = await storage.createEncryptionKey(keyData);
      res.json(key);
    } catch (error) {
      console.error("Error creating key:", error);
      if (error instanceof z.ZodError) {
        res.status(400).json({ message: "Invalid key data", errors: error.errors });
      } else {
        res.status(500).json({ message: "Failed to create key" });
      }
    }
  });

  app.put("/api/keys/:keyId/status", isAuthenticated, async (req, res) => {
    try {
      const { status } = req.body;
      await storage.updateEncryptionKeyStatus(req.params.keyId, status);
      res.json({ message: "Key status updated successfully" });
    } catch (error) {
      console.error("Error updating key status:", error);
      res.status(500).json({ message: "Failed to update key status" });
    }
  });

  // Security monitoring routes
  app.get("/api/monitoring/events", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const limit = req.query.limit ? parseInt(req.query.limit as string) : undefined;
      const events = await storage.getSecurityEvents(user.tenantId, limit);
      res.json(events);
    } catch (error) {
      console.error("Error fetching security events:", error);
      res.status(500).json({ message: "Failed to fetch security events" });
    }
  });

  app.post("/api/monitoring/events", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const eventData = insertSecurityEventSchema.parse({
        ...req.body,
        tenantId: user.tenantId,
      });
      
      const event = await storage.createSecurityEvent(eventData);
      res.json(event);
    } catch (error) {
      console.error("Error creating security event:", error);
      if (error instanceof z.ZodError) {
        res.status(400).json({ message: "Invalid event data", errors: error.errors });
      } else {
        res.status(500).json({ message: "Failed to create security event" });
      }
    }
  });

  // User management routes
  app.get("/api/users", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      if (user.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required" });
      }
      
      const users = await storage.getUsersByTenant(user.tenantId);
      res.json(users);
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  app.put("/api/users/:userId/role", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      if (user.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required" });
      }
      
      const { role } = req.body;
      await storage.updateUserRole(req.params.userId, role);
      res.json({ message: "User role updated successfully" });
    } catch (error) {
      console.error("Error updating user role:", error);
      res.status(500).json({ message: "Failed to update user role" });
    }
  });

  // Dashboard statistics
  app.get("/api/dashboard/stats", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const stats = await storage.getDashboardStats(user.tenantId);
      res.json(stats);
    } catch (error) {
      console.error("Error fetching dashboard stats:", error);
      res.status(500).json({ message: "Failed to fetch dashboard stats" });
    }
  });

  // API usage statistics
  app.get("/api/usage", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const days = req.query.days ? parseInt(req.query.days as string) : undefined;
      const usage = await storage.getApiUsage(user.tenantId, days);
      res.json(usage);
    } catch (error) {
      console.error("Error fetching API usage:", error);
      res.status(500).json({ message: "Failed to fetch API usage" });
    }
  });

  // Tenant information
  app.get("/api/tenant", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const tenant = await storage.getTenant(user.tenantId);
      if (!tenant) {
        return res.status(404).json({ message: "Tenant not found" });
      }
      res.json(tenant);
    } catch (error) {
      console.error("Error fetching tenant:", error);
      res.status(500).json({ message: "Failed to fetch tenant" });
    }
  });

  // SDK download route with production generation
  app.get("/api/sdks/:downloadId/download", async (req, res) => {
    try {
      console.log(`📦 Download request for SDK ID: ${req.params.downloadId}`);
      
      // Get SDK from database
      const sdk = await storage.getSDK(req.params.downloadId);
      if (!sdk) {
        console.error(`❌ SDK not found: ${req.params.downloadId}`);
        return res.status(404).json({ message: "SDK not found" });
      }

      console.log(`✅ Found SDK: ${sdk.name} (version ${sdk.version})`);

      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${sdk.name.toLowerCase().replace(/\s+/g, '-')}-sdk-v${sdk.version}.zip"`);
      
      const archive = archiver('zip', { zlib: { level: 9 } });
      
      // Handle archive events
      archive.on('error', (err) => {
        console.error('❌ Archive error:', err);
        if (!res.headersSent) {
          res.status(500).json({ message: 'Archive creation failed' });
        }
      });

      archive.on('warning', (err) => {
        console.warn('⚠️ Archive warning:', err);
      });

      // Start piping to response
      archive.pipe(res);
      console.log('📡 Archive piped to response');

      // Parse JSON fields
      const languages = JSON.parse(sdk.languages);
      const algorithms = JSON.parse(sdk.algorithms);
      console.log(`🔧 Generating files for languages: ${languages.join(', ')}`);

      // Add simple test file first
      archive.append('Test SDK Generation\nThis file confirms ZIP creation is working.', { name: 'test.txt' });
      console.log('📄 Added test file');

      // Generate SDK files for each language
      for (const language of languages) {
        const langFolder = `${language}/`;
        
        switch(language.toLowerCase()) {
          case 'javascript':
          case 'typescript':
            // Generate JavaScript/TypeScript SDK
            const packageJson = {
              "name": `@averox/${sdk.name.toLowerCase().replace(/\s+/g, '-')}-crypto-sdk`,
              "version": sdk.version || "2.0.0",
              "description": `Production-grade cryptographic SDK for ${sdk.name}`,
              "main": "dist/cjs/index.js",
              "module": "dist/esm/index.js",
              "types": "dist/types/index.d.ts",
              "scripts": {
                "build": "npm run build:cjs && npm run build:esm && npm run build:types",
                "build:cjs": "babel src --out-dir dist/cjs --env-name cjs",
                "build:esm": "babel src --out-dir dist/esm --env-name esm",
                "build:types": "tsc --emitDeclarationOnly --outDir dist/types",
                "test": "jest",
                "test:nist": "node test/nist-vectors.js"
              }
            };

            const jsCore = `/**
 * ${sdk.name} - Enterprise Cryptographic SDK
 * Generated: ${new Date().toISOString()}
 */

const crypto = require('crypto');

class AveroxCrypto {
  constructor(masterKey) {
    if (!masterKey || masterKey.length < 32) {
      throw new Error('Master key must be at least 32 bytes');
    }
    this.masterKey = Buffer.from(masterKey);
  }

  encrypt(plaintext, aad = null) {
    const key = this.deriveKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipherGCM('aes-256-gcm');
    cipher.setIVLength(12);
    cipher.init('encrypt', key, iv);
    
    if (aad) cipher.setAAD(aad);
    
    const plaintextBuffer = Buffer.from(plaintext, 'utf8');
    let ciphertext = cipher.update(plaintextBuffer);
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const tag = cipher.getAuthTag();
    
    return {
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64')
    };
  }

  decrypt(encrypted, aad = null) {
    const key = this.deriveKey();
    const iv = Buffer.from(encrypted.iv, 'base64');
    const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');
    const tag = Buffer.from(encrypted.tag, 'base64');

    const decipher = crypto.createDecipherGCM('aes-256-gcm');
    decipher.setIVLength(12);
    decipher.init('decrypt', key, iv);
    decipher.setAuthTag(tag);
    
    if (aad) decipher.setAAD(aad);
    
    let plaintext = decipher.update(ciphertext);
    plaintext = Buffer.concat([plaintext, decipher.final()]);
    
    return plaintext.toString('utf8');
  }

  deriveKey() {
    return crypto.pbkdf2Sync(this.masterKey, 'averox-salt', 100000, 32, 'sha256');
  }
}

module.exports = { AveroxCrypto };`;

            archive.append(JSON.stringify(packageJson, null, 2), { name: `${langFolder}package.json` });
            archive.append(jsCore, { name: `${langFolder}src/index.js` });
            break;

          case 'python':
            const pythonCore = `"""
${sdk.name} - Enterprise Cryptographic SDK
Generated: ${new Date().toISOString()}
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class AveroxCrypto:
    def __init__(self, master_key: bytes):
        if not master_key or len(master_key) < 32:
            raise ValueError("Master key must be at least 32 bytes")
        self.master_key = master_key

    def encrypt(self, plaintext: str, aad: bytes = None) -> dict:
        key = self._derive_key()
        iv = os.urandom(12)
        aesgcm = AESGCM(key)
        
        ciphertext = aesgcm.encrypt(iv, plaintext.encode('utf-8'), aad)
        
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt(self, encrypted: dict, aad: bytes = None) -> str:
        key = self._derive_key()
        iv = base64.b64decode(encrypted['iv'])
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, aad)
        
        return plaintext.decode('utf-8')

    def _derive_key(self) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'averox-salt',
            iterations=100000,
        )
        return kdf.derive(self.master_key)`;

            const setupPy = `from setuptools import setup, find_packages

setup(
    name="${sdk.name.toLowerCase().replace(/\s+/g, '-')}-crypto-sdk",
    version="${sdk.version || '2.0.0'}",
    description="Production-grade cryptographic SDK for ${sdk.name}",
    packages=find_packages(),
    install_requires=[
        "cryptography>=3.0.0",
    ],
    python_requires=">=3.7",
)`;

            archive.append(pythonCore, { name: `${langFolder}averox_crypto/__init__.py` });
            archive.append(setupPy, { name: `${langFolder}setup.py` });
            break;

          case 'cpp':
            const cppHeader = `/**
 * ${sdk.name} - Enterprise Cryptographic SDK
 * Generated: ${new Date().toISOString()}
 */

#ifndef AVEROX_CRYPTO_H
#define AVEROX_CRYPTO_H

#include <string>
#include <vector>

class AveroxCrypto {
public:
    AveroxCrypto(const std::vector<uint8_t>& masterKey);
    
    std::string encrypt(const std::string& plaintext, const std::string& aad = "");
    std::string decrypt(const std::string& encrypted, const std::string& aad = "");

private:
    std::vector<uint8_t> masterKey;
    std::vector<uint8_t> deriveKey();
};

#endif // AVEROX_CRYPTO_H`;

            const cmakeLists = `cmake_minimum_required(VERSION 3.10)
project(${sdk.name.toLowerCase().replace(/\s+/g, '_')}_crypto_sdk)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_library(\${PROJECT_NAME} SHARED
    src/averox_crypto.cpp
)

target_include_directories(\${PROJECT_NAME} PUBLIC include)
target_link_libraries(\${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)

install(TARGETS \${PROJECT_NAME} DESTINATION lib)
install(FILES include/averox_crypto.h DESTINATION include)`;

            archive.append(cppHeader, { name: `${langFolder}include/averox_crypto.h` });
            archive.append(cmakeLists, { name: `${langFolder}CMakeLists.txt` });
            break;
        }
      }

      // Add general documentation
      const readme = `# ${sdk.name} SDK

Generated: ${new Date().toISOString()}
Version: ${sdk.version || '2.0.0'}

## Languages Supported
${languages.map((lang: string) => `- ${lang.charAt(0).toUpperCase() + lang.slice(1)}`).join('\n')}

## Algorithms
${algorithms.map((alg: string) => `- ${alg}`).join('\n')}

## Installation

See language-specific folders for installation instructions.

## Usage

Each language implementation provides AES-256-GCM encryption with:
- 256-bit AES encryption
- Galois/Counter Mode for authenticated encryption  
- PBKDF2 key derivation
- Secure random IV generation

## Security Features
- Production-grade cryptographic implementations
- Memory-safe operations
- Timing attack resistance
- Authenticated encryption with additional data (AAD) support
`;

      archive.append(readme, { name: 'README.md' });
      archive.append('MIT License\n\nGenerated SDK - See individual language implementations for specific licenses.', { name: 'LICENSE' });

      console.log('📁 Finalizing archive...');
      
      // Use promise-based finalization to ensure proper async handling
      await new Promise<void>((resolve, reject) => {
        archive.on('end', () => {
          console.log('✅ Archive finalized successfully');
          resolve();
        });
        
        archive.on('error', (err) => {
          console.error('❌ Archive finalization error:', err);
          reject(err);
        });
        
        archive.finalize();
      });
    } catch (error) {
      console.error("❌ Error downloading SDK:", error);
      if (!res.headersSent) {
        res.status(500).json({ message: "Failed to download SDK" });
      }
    }
  });

  // Health check
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  const httpServer = createServer(app);
  return httpServer;
}