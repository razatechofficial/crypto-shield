// Enterprise SaaS Routes with RBAC Integration
import type { Express } from "express";
import { enterpriseAuth, adminOnly, requirePermission, requireRole } from "../middleware";
import { storage } from "../storage";

/**
 * Apply enterprise RBAC middleware to key routes
 * This demonstrates how to integrate the middleware system
 */
export function setupEnterpriseRoutes(app: Express) {
  
  // User Management Routes (Admin Only)
  app.get("/api/enterprise/users", adminOnly, async (req, res) => {
    try {
      const tenantId = req.user!.tenantId;
      const users = await storage.getUsersByTenant(tenantId);
      res.json(users);
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ error: "Failed to fetch users" });
    }
  });

  // User Role Management (Admin Only)
  app.put("/api/enterprise/users/:userId/role", adminOnly, async (req, res) => {
    try {
      const { userId } = req.params;
      const { role } = req.body;
      
      // Validate role matches schema
      if (!['admin', 'developer', 'viewer'].includes(role)) {
        return res.status(400).json({ error: "Invalid role" });
      }

      // CRITICAL: Validate user belongs to same tenant
      const targetUser = await storage.getUser(userId);
      if (!targetUser || targetUser.tenantId !== req.user!.tenantId) {
        return res.status(403).json({ error: "Access denied - user not in your tenant" });
      }

      const updatedUser = await storage.updateUserRole(userId, role);
      res.json({ message: "User role updated successfully", user: updatedUser });
    } catch (error) {
      console.error("Error updating user role:", error);
      res.status(500).json({ error: "Failed to update user role" });
    }
  });

  // Key Management Routes (Requires key permissions)
  app.get("/api/enterprise/keys", [
    ...enterpriseAuth, 
    requirePermission("keys:view")
  ], async (req, res) => {
    try {
      const tenantId = req.user!.tenantId;
      const keys = await storage.getEncryptionKeys(tenantId);
      res.json(keys);
    } catch (error) {
      console.error("Error fetching keys:", error);
      res.status(500).json({ error: "Failed to fetch keys" });
    }
  });

  // Key Rotation (Requires rotation permission)
  app.post("/api/enterprise/keys/:keyId/rotate", [
    ...enterpriseAuth,
    requirePermission("keys:rotate")
  ], async (req, res) => {
    try {
      const { keyId } = req.params;
      const tenantId = req.user!.tenantId;
      const userId = req.user!.id;

      // CRITICAL: Validate key belongs to user's tenant
      const keys = await storage.getEncryptionKeys(tenantId);
      const key = keys.find(k => k.id === keyId);
      if (!key) {
        return res.status(404).json({ error: "Key not found in your tenant" });
      }

      const rotatedKey = await storage.rotateKey(keyId, "manual", userId);
      res.json({ message: "Key rotated successfully", key: rotatedKey });
    } catch (error) {
      console.error("Error rotating key:", error);
      res.status(500).json({ error: "Failed to rotate key" });
    }
  });

  // Organization Settings (Developer+ access)
  app.get("/api/enterprise/organization", [
    ...enterpriseAuth,
    requireRole("developer")
  ], async (req, res) => {
    try {
      const tenantId = req.user!.tenantId;
      const tenant = await storage.getTenant(tenantId);
      
      if (!tenant) {
        return res.status(404).json({ error: "Organization not found" });
      }

      res.json({
        id: tenant.id,
        name: tenant.name,
        subscriptionTier: tenant.subscriptionTier,
        settings: tenant.settings
      });
    } catch (error) {
      console.error("Error fetching organization:", error);
      res.status(500).json({ error: "Failed to fetch organization" });
    }
  });

  // User Stats (Developer+ access)
  app.get("/api/enterprise/stats/users", [
    ...enterpriseAuth,
    requireRole("developer")
  ], async (req, res) => {
    try {
      const tenantId = req.user!.tenantId;
      const userStats = await storage.getUserStats(tenantId);
      res.json(userStats);
    } catch (error) {
      console.error("Error fetching user stats:", error);
      res.status(500).json({ error: "Failed to fetch user stats" });
    }
  });

  // Tenant Context Info (All authenticated users)
  app.get("/api/enterprise/context", enterpriseAuth, async (req, res) => {
    try {
      res.json({
        user: {
          id: req.user!.id,
          email: req.user!.email,
          role: req.user!.role,
          permissions: req.user!.permissions
        },
        tenant: req.tenant
      });
    } catch (error) {
      console.error("Error fetching context:", error);
      res.status(500).json({ error: "Failed to fetch context" });
    }
  });
}