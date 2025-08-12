import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./replitAuth";
import { insertSdkSchema, insertEncryptionKeySchema, insertSecurityEventSchema } from "@shared/schema";
import { z } from "zod";
import { randomUUID } from "crypto";

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
          subscriptionTier: 'starter'
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

      // Generate mock SDK download URL
      const downloadUrl = `/api/sdks/${randomUUID()}/download`;
      
      const sdk = await storage.createSDK({
        ...sdkData,
        downloadUrl,
      });

      // Log SDK generation activity
      await storage.createSecurityEvent({
        tenantId: user.tenantId,
        eventType: 'sdk_generated',
        severity: 'low',
        description: `SDK generated successfully: ${sdk.language} with ${sdkData.algorithmId}`,
        metadata: { sdkId: sdk.id, language: sdk.language },
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
