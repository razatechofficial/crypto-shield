import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./replitAuth";
import { insertSdkSchema, insertEncryptionKeySchema, insertSecurityEventSchema } from "@shared/schema";
import { z } from "zod";
import { randomUUID } from "crypto";

// Helper functions for advanced SDK generation
function generateSetupCommands(language: string): string[] {
  const commands: Record<string, string[]> = {
    javascript: ['npm install averox-crypto-sdk --save', 'npx averox-crypto init'],
    python: ['pip install averox-crypto-sdk', 'averox-crypto init'],
    java: ['mvn install:averox-crypto-sdk', './gradlew averoxInit'],
    csharp: ['dotnet add package AveroxCrypto', 'dotnet averox init'],
    go: ['go mod init && go get github.com/averox/crypto-sdk', 'averox init'],
    rust: ['cargo add averox-crypto', 'cargo averox init'],
  };
  return commands[language] || ['# Platform-specific installation commands will be generated'];
}

function generateSDKVersion(sdkData: any): string {
  const baseVersion = '2.0.0';
  const features = Object.keys(sdkData.features || {}).length;
  const securityLevel = sdkData.securityLevel === 'maximum' ? 'enterprise' : 
                       sdkData.securityLevel === 'enhanced' ? 'pro' : 'standard';
  return `${baseVersion}-${securityLevel}.${features}`;
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Auth middleware
  await setupAuth(app);

  // Auth routes
  app.get('/api/auth/user', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      let user = await storage.getUser(userId);
      
      // If user doesn't have a tenant, create one automatically
      if (user && !user.tenantId) {
        const tenant = await storage.createTenant({
          name: `${user.firstName || user.email || 'User'}'s Workspace`,
          subscriptionTier: 'starter',
          apiKey: `ak_${randomUUID().replace(/-/g, '')}`
        });
        
        user = await storage.updateUser(userId, { tenantId: tenant.id });
      }
      
      res.json(user);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Dashboard routes
  app.get('/api/dashboard/stats', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user?.tenantId) {
        return res.status(400).json({ message: "User not associated with a tenant" });
      }

      const stats = await storage.getDashboardStats(user.tenantId);
      res.json(stats);
    } catch (error) {
      console.error("Error fetching dashboard stats:", error);
      res.status(500).json({ message: "Failed to fetch dashboard stats" });
    }
  });

  app.get('/api/dashboard/activities', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user?.tenantId) {
        return res.status(400).json({ message: "User not associated with a tenant" });
      }

      const activities = await storage.getSecurityEvents(user.tenantId, 10);
      res.json(activities);
    } catch (error) {
      console.error("Error fetching activities:", error);
      res.status(500).json({ message: "Failed to fetch activities" });
    }
  });

  // Encryption algorithms routes
  app.get('/api/algorithms', isAuthenticated, async (req, res) => {
    try {
      const algorithms = await storage.getEncryptionAlgorithms();
      res.json(algorithms);
    } catch (error) {
      console.error("Error fetching algorithms:", error);
      res.status(500).json({ message: "Failed to fetch algorithms" });
    }
  });

  app.post('/api/algorithms/recommend', isAuthenticated, async (req, res) => {
    try {
      const { applicationType, securityLevel, complianceRequirements = [], deploymentEnvironment } = req.body;
      
      // Get all algorithms
      const allAlgorithms = await storage.getEncryptionAlgorithms();
      
      // Smart recommendation logic based on application requirements
      let recommendedAlgorithms = [];
      
      // Filter by security level and application type
      if (securityLevel === 'maximum' || applicationType === 'enterprise') {
        // Prioritize post-quantum and high-security algorithms
        recommendedAlgorithms = allAlgorithms.filter(alg => 
          alg.isPostQuantum || alg.isQuantumSafe || 
          ['RSA-4096', 'AES-256', 'ChaCha20-Poly1305', 'CRYSTALS-Kyber', 'FALCON'].includes(alg.name)
        );
      } else if (securityLevel === 'enhanced') {
        // Balanced security with good performance
        recommendedAlgorithms = allAlgorithms.filter(alg => 
          ['AES-256', 'RSA-2048', 'ChaCha20-Poly1305', 'Ed25519', 'BLAKE3'].includes(alg.name)
        );
      } else {
        // Standard security - widely compatible algorithms
        recommendedAlgorithms = allAlgorithms.filter(alg => 
          ['AES-128', 'AES-256', 'RSA-2048', 'ECDSA-P256', 'SHA-256'].includes(alg.name)
        );
      }
      
      // Add compliance-specific algorithms
      if (complianceRequirements.includes('fips')) {
        const fipsAlgorithms = allAlgorithms.filter(alg => 
          ['AES-256', 'AES-128', 'RSA-2048', 'ECDSA-P256', 'SHA-256', 'SHA-384', 'HMAC-SHA256'].includes(alg.name)
        );
        recommendedAlgorithms = [...new Set([...recommendedAlgorithms, ...fipsAlgorithms])];
      }
      
      if (complianceRequirements.includes('hipaa') || complianceRequirements.includes('gdpr')) {
        const strongAlgorithms = allAlgorithms.filter(alg => 
          alg.name.includes('256') || alg.isPostQuantum || ['ChaCha20-Poly1305', 'BLAKE3'].includes(alg.name)
        );
        recommendedAlgorithms = [...new Set([...recommendedAlgorithms, ...strongAlgorithms])];
      }
      
      // Application-specific recommendations
      if (applicationType === 'mobile') {
        const mobileAlgorithms = allAlgorithms.filter(alg => 
          ['ChaCha20-Poly1305', 'Ed25519', 'AES-256', 'BLAKE3'].includes(alg.name)
        );
        recommendedAlgorithms = [...new Set([...recommendedAlgorithms, ...mobileAlgorithms])];
      }
      
      if (applicationType === 'iot') {
        const iotAlgorithms = allAlgorithms.filter(alg => 
          ['ChaCha20-Poly1305', 'Ed25519', 'AES-128', 'BLAKE2'].includes(alg.name)
        );
        recommendedAlgorithms = [...new Set([...recommendedAlgorithms, ...iotAlgorithms])];
      }
      
      // Remove duplicates and ensure we have recommendations
      recommendedAlgorithms = Array.from(new Set(recommendedAlgorithms.map(a => a.id)))
        .map(id => allAlgorithms.find(a => a.id === id))
        .filter(Boolean);
      
      // If no specific recommendations, provide general good choices
      if (recommendedAlgorithms.length === 0) {
        recommendedAlgorithms = allAlgorithms.filter(alg => 
          ['AES-256', 'RSA-2048', 'ChaCha20-Poly1305', 'Ed25519', 'SHA-256'].includes(alg.name)
        ).slice(0, 5);
      }
      
      // Sort by preference (post-quantum first, then by key strength)
      recommendedAlgorithms.sort((a, b) => {
        if (!a || !b) return 0;
        if (a.isPostQuantum && !b.isPostQuantum) return -1;
        if (!a.isPostQuantum && b.isPostQuantum) return 1;
        if (a.keySize && b.keySize) return b.keySize - a.keySize;
        return 0;
      });
      
      res.json(recommendedAlgorithms.slice(0, 6)); // Return top 6 recommendations
      
    } catch (error) {
      console.error("Error getting algorithm recommendations:", error);
      res.status(500).json({ message: "Failed to get algorithm recommendations" });
    }
  });

  // SDK generation routes
  app.post('/api/sdks/generate', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user?.tenantId) {
        return res.status(400).json({ message: "User not associated with a tenant" });
      }

      const sdkData = insertSdkSchema.parse({
        ...req.body,
        tenantId: user.tenantId,
        userId: userId,
      });

      // Generate comprehensive SDK with auto-features
      const downloadUrl = `/api/sdks/${randomUUID()}/download`;
      
      // Enhanced SDK configuration with zero-config features
      const enhancedConfiguration = {
        ...(sdkData.configuration || {}),
        
        // Auto-Installation & Setup
        installer: {
          autoDetectPlatform: true,
          dependencyResolution: 'automatic',
          configGeneration: 'zero-config',
          setupCommands: generateSetupCommands(sdkData.language),
        },
        
        // Advanced Security Features  
        security: {
          quantumReadiness: true,
          threatIntelligence: 'real-time',
          behavioralAnalysis: true,
          zeroTrustArchitecture: true,
        },
        
        // Auto-Healing & Self-Maintenance
        autoHealing: {
          selfDiagnostics: true,
          autoRecovery: true,
          performanceOptimization: 'adaptive',
          securityPatching: 'automatic',
        },
        
        // Enterprise Telemetry
        monitoring: {
          distributedTracing: true,
          metricsCollection: 'comprehensive',
          alerting: 'intelligent',
          dashboards: 'auto-generated',
        }
      };
      
      const sdk = await storage.createSDK({
        ...sdkData,
        downloadUrl,
        configuration: enhancedConfiguration,
        version: generateSDKVersion(sdkData),
      });

      // Log enhanced SDK generation activity  
      await storage.createSecurityEvent({
        tenantId: user.tenantId,
        eventType: 'sdk_generated',
        severity: 'low',
        description: `Advanced SDK generated: ${sdk.language} with ${Object.keys(enhancedConfiguration).length} auto-features enabled`,
        metadata: { 
          sdkId: sdk.id, 
          language: sdk.language,
          features: Object.keys(sdkData.features || {}),
          autoFeatures: Object.keys(enhancedConfiguration),
        },
      });

      res.json(sdk);
    } catch (error) {
      console.error("Error generating SDK:", error);
      res.status(500).json({ message: "Failed to generate SDK" });
    }
  });

  app.get('/api/sdks', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user?.tenantId) {
        return res.status(400).json({ message: "User not associated with a tenant" });
      }

      const sdks = await storage.getSDKs(user.tenantId);
      res.json(sdks);
    } catch (error) {
      console.error("Error fetching SDKs:", error);
      res.status(500).json({ message: "Failed to fetch SDKs" });
    }
  });

  // Key management routes
  app.get('/api/keys', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user?.tenantId) {
        return res.status(400).json({ message: "User not associated with a tenant" });
      }

      const keys = await storage.getEncryptionKeys(user.tenantId);
      res.json(keys);
    } catch (error) {
      console.error("Error fetching keys:", error);
      res.status(500).json({ message: "Failed to fetch keys" });
    }
  });

  app.post('/api/keys', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user?.tenantId) {
        return res.status(400).json({ message: "User not associated with a tenant" });
      }

      const keyData = insertEncryptionKeySchema.parse({
        ...req.body,
        tenantId: user.tenantId,
      });

      const key = await storage.createEncryptionKey(keyData);

      // Log key generation activity
      await storage.createSecurityEvent({
        tenantId: user.tenantId,
        eventType: 'key_generated',
        severity: 'low',
        description: `New encryption key generated: ${key.keyType}`,
        metadata: { keyId: key.keyId, keyType: key.keyType },
      });

      res.json(key);
    } catch (error) {
      console.error("Error creating key:", error);
      res.status(500).json({ message: "Failed to create key" });
    }
  });

  app.put('/api/keys/:keyId/rotate', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user?.tenantId) {
        return res.status(400).json({ message: "User not associated with a tenant" });
      }

      const { keyId } = req.params;
      await storage.updateEncryptionKeyStatus(keyId, 'rotating');

      // Log key rotation activity
      await storage.createSecurityEvent({
        tenantId: user.tenantId,
        eventType: 'key_rotated',
        severity: 'medium',
        description: `Encryption key rotated: ${keyId}`,
        metadata: { keyId },
      });

      res.json({ message: "Key rotation initiated" });
    } catch (error) {
      console.error("Error rotating key:", error);
      res.status(500).json({ message: "Failed to rotate key" });
    }
  });

  // Monitoring routes
  app.get('/api/monitoring/events', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user?.tenantId) {
        return res.status(400).json({ message: "User not associated with a tenant" });
      }

      const events = await storage.getSecurityEvents(user.tenantId);
      res.json(events);
    } catch (error) {
      console.error("Error fetching security events:", error);
      res.status(500).json({ message: "Failed to fetch security events" });
    }
  });

  app.get('/api/monitoring/usage', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user?.tenantId) {
        return res.status(400).json({ message: "User not associated with a tenant" });
      }

      const usage = await storage.getApiUsage(user.tenantId);
      res.json(usage);
    } catch (error) {
      console.error("Error fetching usage data:", error);
      res.status(500).json({ message: "Failed to fetch usage data" });
    }
  });

  // User management routes
  app.get('/api/users', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user?.tenantId) {
        return res.status(400).json({ message: "User not associated with a tenant" });
      }

      if (user.role !== 'admin') {
        return res.status(403).json({ message: "Access denied. Admin role required." });
      }

      const users = await storage.getTenantUsers(user.tenantId);
      res.json(users);
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  app.put('/api/users/:targetUserId/role', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user?.tenantId) {
        return res.status(400).json({ message: "User not associated with a tenant" });
      }

      if (user.role !== 'admin') {
        return res.status(403).json({ message: "Access denied. Admin role required." });
      }

      const { targetUserId } = req.params;
      const { role } = req.body;

      if (!['admin', 'developer', 'viewer'].includes(role)) {
        return res.status(400).json({ message: "Invalid role" });
      }

      await storage.updateUserRole(targetUserId, role);

      // Log role change activity
      await storage.createSecurityEvent({
        tenantId: user.tenantId,
        eventType: 'user_role_changed',
        severity: 'medium',
        description: `User role changed to ${role}`,
        metadata: { targetUserId, newRole: role, changedBy: userId },
      });

      res.json({ message: "User role updated successfully" });
    } catch (error) {
      console.error("Error updating user role:", error);
      res.status(500).json({ message: "Failed to update user role" });
    }
  });

  // Tenant routes
  app.get('/api/tenant', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      if (!user?.tenantId) {
        return res.status(400).json({ message: "User not associated with a tenant" });
      }

      const tenant = await storage.getTenant(user.tenantId);
      res.json(tenant);
    } catch (error) {
      console.error("Error fetching tenant:", error);
      res.status(500).json({ message: "Failed to fetch tenant" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
