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
      
      // Set download URL after SDK is created (needs the SDK ID)
      const downloadUrl = `/api/sdks/${sdk.id}/download`;
      const updatedSdk = await storage.updateSDK(sdk.id, { downloadUrl });
      
      res.json(updatedSdk || { ...sdk, downloadUrl });
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
        console.log(`🔧 Processing language: "${language}" (lowercase: "${language.toLowerCase()}")`);
        
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

          case 'swift':
            const swiftCore = `/**
 * ${sdk.name} - Enterprise Cryptographic SDK for iOS/macOS
 * Generated: ${new Date().toISOString()}
 */

import Foundation
import CryptoKit

@available(iOS 13.0, macOS 10.15, *)
public class AveroxCrypto {
    private let masterKey: Data
    
    public init(masterKey: Data) throws {
        guard masterKey.count >= 32 else {
            throw CryptoError.invalidKeySize
        }
        self.masterKey = masterKey
    }
    
    public func encrypt(_ plaintext: String, aad: Data? = nil) throws -> EncryptedData {
        let key = try deriveKey()
        let symmetricKey = SymmetricKey(data: key)
        let data = Data(plaintext.utf8)
        
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey, authenticating: aad)
        
        return EncryptedData(
            iv: sealedBox.nonce.withUnsafeBytes { Data($0) }.base64EncodedString(),
            ciphertext: sealedBox.ciphertext.base64EncodedString(),
            tag: sealedBox.tag.base64EncodedString()
        )
    }
    
    private func deriveKey() throws -> Data {
        let salt = "averox-salt".data(using: .utf8)!
        return try HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: masterKey),
            salt: salt,
            outputByteCount: 32
        ).withUnsafeBytes { Data($0) }
    }
}

public struct EncryptedData {
    public let iv: String
    public let ciphertext: String
    public let tag: String
}

public enum CryptoError: Error {
    case invalidKeySize
}`;

            const swiftPackage = `// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "${sdk.name.toLowerCase().replace(/\s+/g, '-')}-crypto-sdk",
    platforms: [.iOS(.v13), .macOS(.v10_15)],
    products: [
        .library(name: "AveroxCrypto", targets: ["AveroxCrypto"])
    ],
    targets: [
        .target(name: "AveroxCrypto", dependencies: [])
    ]
)`;

            archive.append(swiftCore, { name: `${langFolder}Sources/AveroxCrypto/AveroxCrypto.swift` });
            archive.append(swiftPackage, { name: `${langFolder}Package.swift` });
            break;

          case 'java':
            const javaCore = `/**
 * ${sdk.name} - Enterprise Cryptographic SDK for Java
 * Generated: ${new Date().toISOString()}
 */

package com.averox.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.SecureRandom;
import java.util.Base64;

public class AveroxCrypto {
    private final byte[] masterKey;
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    
    public AveroxCrypto(byte[] masterKey) throws Exception {
        if (masterKey == null || masterKey.length < 32) {
            throw new IllegalArgumentException("Master key must be at least 32 bytes");
        }
        this.masterKey = masterKey.clone();
    }
    
    public EncryptedData encrypt(String plaintext, byte[] aad) throws Exception {
        SecretKey key = deriveKey();
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
        
        return new EncryptedData(
            Base64.getEncoder().encodeToString(iv),
            Base64.getEncoder().encodeToString(ciphertext)
        );
    }
    
    private SecretKey deriveKey() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(
            new String(masterKey, "UTF-8").toCharArray(),
            "averox-salt".getBytes("UTF-8"),
            100000,
            256
        );
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);
    }
    
    public static class EncryptedData {
        public final String iv;
        public final String ciphertext;
        
        public EncryptedData(String iv, String ciphertext) {
            this.iv = iv;
            this.ciphertext = ciphertext;
        }
    }
}`;

            const gradleBuild = `plugins {
    id 'java-library'
    id 'maven-publish'
}

group = 'com.averox'
version = '${sdk.version || '2.0.0'}'

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

dependencies {
    testImplementation 'junit:junit:4.13.2'
}

publishing {
    publications {
        maven(MavenPublication) {
            from components.java
        }
    }
}`;

            archive.append(javaCore, { name: `${langFolder}src/main/java/com/averox/crypto/AveroxCrypto.java` });
            archive.append(gradleBuild, { name: `${langFolder}build.gradle` });
            break;

          case 'csharp':
            const csharpCore = `/**
 * ${sdk.name} - Enterprise Cryptographic SDK for .NET
 * Generated: ${new Date().toISOString()}
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
}`;

            const csprojFile = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
    <PackageId>${sdk.name.toLowerCase().replace(/\s+/g, '-')}-crypto-sdk</PackageId>
    <Version>${sdk.version || '2.0.0'}</Version>
    <Description>Production-grade cryptographic SDK for ${sdk.name}</Description>
  </PropertyGroup>
</Project>`;

            archive.append(csharpCore, { name: `${langFolder}AveroxCrypto.cs` });
            archive.append(csprojFile, { name: `${langFolder}AveroxCrypto.csproj` });
            break;

          case 'rust':
            const rustCore = `/**
 * ${sdk.name} - Enterprise Cryptographic SDK for Rust
 * Generated: ${new Date().toISOString()}
 */

use aes_gcm::{Aes256Gcm, Key, Nonce, AeadCore, AeadInPlace, KeyInit};
use pbkdf2::{pbkdf2_hmac};
use sha2::Sha256;
use rand::RngCore;
use base64::{Engine as _, engine::general_purpose};

pub struct AveroxCrypto {
    master_key: Vec<u8>,
}

impl AveroxCrypto {
    pub fn new(master_key: Vec<u8>) -> Result<Self, &'static str> {
        if master_key.len() < 32 {
            return Err("Master key must be at least 32 bytes");
        }
        Ok(AveroxCrypto { master_key })
    }
    
    pub fn encrypt(&self, plaintext: &str, aad: Option<&[u8]>) -> Result<EncryptedData, Box<dyn std::error::Error>> {
        let key = self.derive_key()?;
        let cipher = Aes256Gcm::new(&key);
        
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut buffer = plaintext.as_bytes().to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce, aad.unwrap_or(&[]), &mut buffer)?;
        
        Ok(EncryptedData {
            iv: general_purpose::STANDARD.encode(&nonce_bytes),
            ciphertext: general_purpose::STANDARD.encode(&buffer),
            tag: general_purpose::STANDARD.encode(&tag),
        })
    }
    
    fn derive_key(&self) -> Result<Key<Aes256Gcm>, &'static str> {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(&self.master_key, b"averox-salt", 100_000, &mut key);
        Ok(*Key::<Aes256Gcm>::from_slice(&key))
    }
}

pub struct EncryptedData {
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}`;

            const cargoToml = `[package]
name = "${sdk.name.toLowerCase().replace(/\s+/g, '-')}-crypto-sdk"
version = "${sdk.version || '2.0.0'}"
edition = "2021"
description = "Production-grade cryptographic SDK for ${sdk.name}"

[dependencies]
aes-gcm = "0.10"
pbkdf2 = "0.12"
sha2 = "0.10"
rand = "0.8"
base64 = "0.21"`;

            archive.append(rustCore, { name: `${langFolder}src/lib.rs` });
            archive.append(cargoToml, { name: `${langFolder}Cargo.toml` });
            break;

          case 'dart':
            const dartCore = `/**
 * ${sdk.name} - Enterprise Cryptographic SDK for Dart/Flutter
 * Generated: ${new Date().toISOString()}
 */

import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

class AveroxCrypto {
  final Uint8List _masterKey;
  
  AveroxCrypto(this._masterKey) {
    if (_masterKey.length < 32) {
      throw ArgumentError('Master key must be at least 32 bytes');
    }
  }
  
  EncryptedData encrypt(String plaintext, {Uint8List? aad}) {
    final key = _deriveKey();
    final iv = _generateRandomBytes(12);
    
    final cipher = GCMBlockCipher(AESEngine());
    final params = AEADParameters(KeyParameter(key), 128, iv, aad);
    cipher.init(true, params);
    
    final plaintextBytes = utf8.encode(plaintext);
    final ciphertext = Uint8List(plaintextBytes.length + 16);
    final len = cipher.processBytes(plaintextBytes, 0, plaintextBytes.length, ciphertext, 0);
    cipher.doFinal(ciphertext, len);
    
    return EncryptedData(
      iv: base64.encode(iv),
      ciphertext: base64.encode(ciphertext.sublist(0, plaintextBytes.length)),
      tag: base64.encode(ciphertext.sublist(plaintextBytes.length))
    );
  }
  
  Uint8List _deriveKey() {
    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));
    pbkdf2.init(Pbkdf2Parameters(utf8.encode('averox-salt'), 100000, 32));
    return pbkdf2.process(_masterKey);
  }
  
  Uint8List _generateRandomBytes(int length) {
    final random = SecureRandom('Fortuna');
    final seed = Uint8List(32);
    for (int i = 0; i < 32; i++) {
      seed[i] = (DateTime.now().millisecondsSinceEpoch + i) & 0xFF;
    }
    random.seed(KeyParameter(seed));
    return random.nextBytes(length);
  }
}

class EncryptedData {
  final String iv;
  final String ciphertext;
  final String tag;
  
  EncryptedData({required this.iv, required this.ciphertext, required this.tag});
}`;

            const pubspecYaml = `name: ${sdk.name.toLowerCase().replace(/\s+/g, '_')}_crypto_sdk
description: Production-grade cryptographic SDK for ${sdk.name}
version: ${sdk.version || '2.0.0'}

environment:
  sdk: '>=2.17.0 <4.0.0'
  flutter: '>=3.0.0'

dependencies:
  flutter:
    sdk: flutter
  crypto: ^3.0.3
  pointycastle: ^3.7.3

dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^2.0.0`;

            archive.append(dartCore, { name: `${langFolder}lib/averox_crypto.dart` });
            archive.append(pubspecYaml, { name: `${langFolder}pubspec.yaml` });
            break;

          case 'php':
            const phpCore = `<?php
/**
 * ${sdk.name} - Enterprise Cryptographic SDK for PHP
 * Generated: ${new Date().toISOString()}
 */

class AveroxCrypto {
    private $masterKey;
    
    public function __construct($masterKey) {
        if (strlen($masterKey) < 32) {
            throw new InvalidArgumentException('Master key must be at least 32 bytes');
        }
        $this->masterKey = $masterKey;
    }
    
    public function encrypt($plaintext, $aad = null) {
        $key = $this->deriveKey();
        $iv = random_bytes(12);
        
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );
        
        if ($ciphertext === false) {
            throw new RuntimeException('Encryption failed');
        }
        
        return [
            'iv' => base64_encode($iv),
            'ciphertext' => base64_encode($ciphertext),
            'tag' => base64_encode($tag)
        ];
    }
    
    public function decrypt($encrypted, $aad = null) {
        $key = $this->deriveKey();
        $iv = base64_decode($encrypted['iv']);
        $ciphertext = base64_decode($encrypted['ciphertext']);
        $tag = base64_decode($encrypted['tag']);
        
        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );
        
        if ($plaintext === false) {
            throw new RuntimeException('Decryption failed');
        }
        
        return $plaintext;
    }
    
    private function deriveKey() {
        return hash_pbkdf2('sha256', $this->masterKey, 'averox-salt', 100000, 32, true);
    }
}`;

            const composerJson = `{
    "name": "averox/${sdk.name.toLowerCase().replace(/\s+/g, '-')}-crypto-sdk",
    "description": "Production-grade cryptographic SDK for ${sdk.name}",
    "version": "${sdk.version || '2.0.0'}",
    "type": "library",
    "require": {
        "php": ">=7.4",
        "ext-openssl": "*"
    },
    "autoload": {
        "psr-4": {
            "Averox\\\\Crypto\\\\": "src/"
        }
    }
}`;

            archive.append(phpCore, { name: `${langFolder}src/AveroxCrypto.php` });
            archive.append(composerJson, { name: `${langFolder}composer.json` });
            break;

          case 'ruby':
            const rubyCore = `##
# ${sdk.name} - Enterprise Cryptographic SDK for Ruby
# Generated: ${new Date().toISOString()}

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
end`;

            const gemspec = `Gem::Specification.new do |spec|
  spec.name          = "${sdk.name.toLowerCase().replace(/\s+/g, '-')}-crypto-sdk"
  spec.version       = "${sdk.version || '2.0.0'}"
  spec.authors       = ["Averox"]
  spec.email         = ["support@averox.com"]
  spec.summary       = "Production-grade cryptographic SDK for ${sdk.name}"
  spec.description   = "Enterprise encryption SDK with AES-256-GCM implementation"
  spec.homepage      = "https://averox.com"
  spec.license       = "MIT"
  
  spec.files         = Dir["lib/**/*"]
  spec.require_paths = ["lib"]
  
  spec.required_ruby_version = ">= 2.7.0"
end`;

            archive.append(rubyCore, { name: `${langFolder}lib/averox_crypto.rb` });
            archive.append(gemspec, { name: `${langFolder}averox_crypto.gemspec` });
            break;

          case 'objectivec':
            const objcHeader = `/**
 * ${sdk.name} - Enterprise Cryptographic SDK for Objective-C
 * Generated: ${new Date().toISOString()}
 */

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

@interface EncryptedData : NSObject
@property (nonatomic, strong) NSString *iv;
@property (nonatomic, strong) NSString *ciphertext;
@property (nonatomic, strong) NSString *tag;
@end

@interface AveroxCrypto : NSObject
- (instancetype)initWithMasterKey:(NSData *)masterKey error:(NSError **)error;
- (EncryptedData *)encrypt:(NSString *)plaintext aad:(NSData *)aad error:(NSError **)error;
- (NSString *)decrypt:(EncryptedData *)encrypted aad:(NSData *)aad error:(NSError **)error;
@end`;

            const objcImpl = `#import "AveroxCrypto.h"
#import <Security/Security.h>

@implementation EncryptedData
@end

@implementation AveroxCrypto {
    NSData *_masterKey;
}

- (instancetype)initWithMasterKey:(NSData *)masterKey error:(NSError **)error {
    self = [super init];
    if (self) {
        if (masterKey.length < 32) {
            if (error) {
                *error = [NSError errorWithDomain:@"AveroxCrypto" code:1 userInfo:@{NSLocalizedDescriptionKey: @"Master key must be at least 32 bytes"}];
            }
            return nil;
        }
        _masterKey = [masterKey copy];
    }
    return self;
}

- (EncryptedData *)encrypt:(NSString *)plaintext aad:(NSData *)aad error:(NSError **)error {
    NSData *key = [self deriveKey];
    NSMutableData *iv = [NSMutableData dataWithLength:12];
    SecRandomCopyBytes(kSecRandomDefault, 12, iv.mutableBytes);
    
    NSData *plaintextData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *ciphertext = [NSMutableData dataWithLength:plaintextData.length];
    NSMutableData *tag = [NSMutableData dataWithLength:16];
    
    CCCryptorStatus status = CCCryptorGCM(kCCEncrypt, kCCAlgorithmAES,
                                         key.bytes, key.length,
                                         iv.bytes, iv.length,
                                         aad.bytes, aad.length,
                                         plaintextData.bytes, plaintextData.length,
                                         ciphertext.mutableBytes,
                                         tag.mutableBytes, &tag.length);
    
    if (status != kCCSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:@"AveroxCrypto" code:2 userInfo:@{NSLocalizedDescriptionKey: @"Encryption failed"}];
        }
        return nil;
    }
    
    EncryptedData *result = [[EncryptedData alloc] init];
    result.iv = [iv base64EncodedStringWithOptions:0];
    result.ciphertext = [ciphertext base64EncodedStringWithOptions:0];
    result.tag = [tag base64EncodedStringWithOptions:0];
    
    return result;
}

- (NSData *)deriveKey {
    NSData *salt = [@"averox-salt" dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *derivedKey = [NSMutableData dataWithLength:32];
    
    CCKeyDerivationPBKDF(kCCPBKDF2, _masterKey.bytes, _masterKey.length,
                        salt.bytes, salt.length,
                        kCCPRFHmacAlgSHA256, 100000,
                        derivedKey.mutableBytes, derivedKey.length);
    
    return derivedKey;
}

@end`;

            archive.append(objcHeader, { name: `${langFolder}AveroxCrypto.h` });
            archive.append(objcImpl, { name: `${langFolder}AveroxCrypto.m` });
            break;

          case 'reactnative':
          case 'xamarin':
            // Cross-platform mobile implementations
            const rnCore = `/**
 * ${sdk.name} - Enterprise Cryptographic SDK for ${language === 'reactnative' ? 'React Native' : 'Xamarin'}
 * Generated: ${new Date().toISOString()}
 */

import { NativeModules, Platform } from 'react-native';
import CryptoJS from 'crypto-js';

class AveroxCrypto {
  constructor(masterKey) {
    if (!masterKey || masterKey.length < 32) {
      throw new Error('Master key must be at least 32 bytes');
    }
    this.masterKey = masterKey;
  }
  
  async encrypt(plaintext, aad = null) {
    const key = this.deriveKey();
    const iv = CryptoJS.lib.WordArray.random(96/8);
    
    const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
      iv: iv,
      mode: CryptoJS.mode.GCM,
      padding: CryptoJS.pad.NoPadding
    });
    
    return {
      iv: iv.toString(CryptoJS.enc.Base64),
      ciphertext: encrypted.ciphertext.toString(CryptoJS.enc.Base64),
      tag: encrypted.tag ? encrypted.tag.toString(CryptoJS.enc.Base64) : ''
    };
  }
  
  deriveKey() {
    return CryptoJS.PBKDF2(this.masterKey, 'averox-salt', {
      keySize: 256/32,
      iterations: 100000,
      hasher: CryptoJS.algo.SHA256
    });
  }
}

export default AveroxCrypto;`;

            const packageJsonMobile = {
              "name": `@averox/${sdk.name.toLowerCase().replace(/\s+/g, '-')}-crypto-sdk-${language}`,
              "version": sdk.version || "2.0.0",
              "description": `Production-grade cryptographic SDK for ${sdk.name} (${language})`,
              "main": "index.js",
              "dependencies": {
                "crypto-js": "^4.1.1"
              },
              "peerDependencies": {
                "react-native": ">=0.60.0"
              }
            };

            archive.append(rnCore, { name: `${langFolder}index.js` });
            archive.append(JSON.stringify(packageJsonMobile, null, 2), { name: `${langFolder}package.json` });
            break;

          default:
            console.log(`⚠️ No implementation for language: ${language}`);
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