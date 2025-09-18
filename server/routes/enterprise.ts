// Enterprise SaaS Routes with RBAC Integration
import type { Express } from "express";
import { enterpriseAuth, adminOnly, requirePermission, requireRole } from "../middleware";
import { storage } from "../storage";

/**
 * Apply enterprise RBAC middleware to key routes
 * This demonstrates how to integrate the middleware system
 */
export function setupEnterpriseRoutes(app: Express) {
  
  // ====== COMPREHENSIVE USER MANAGEMENT ROUTES ======

  // Invite User to Tenant (Admin Only)
  app.post("/api/enterprise/users/invite", adminOnly, async (req, res) => {
    try {
      const tenantId = req.user!.tenantId;
      const invitedBy = req.user!.id;
      const { email, role } = req.body;

      // Validate input
      if (!email || !role) {
        return res.status(400).json({ error: "Email and role are required" });
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ error: "Invalid email format" });
      }

      const result = await storage.inviteUserToTenant(tenantId, email, role, invitedBy);
      
      res.json({ 
        message: "User invited successfully", 
        user: result.user,
        invitation: result.invitation
      });
    } catch (error: any) {
      console.error("Error inviting user:", error);
      res.status(500).json({ error: error.message || "Failed to invite user" });
    }
  });

  // Update User Profile (Admin or authorized users)
  app.put("/api/enterprise/users/:userId/profile", [
    ...enterpriseAuth,
    requirePermission("users:manage")
  ], async (req, res) => {
    try {
      const { userId } = req.params;
      const updatedBy = req.user!.id;
      const updates = req.body;
      
      // CRITICAL: Validate user belongs to same tenant (multi-tenant check)
      const tenantUser = await storage.getTenantUser(req.user!.tenantId, userId);
      if (!tenantUser) {
        return res.status(403).json({ error: "Access denied - user not in your tenant" });
      }

      const updatedUser = await storage.updateUserProfile(userId, updates, updatedBy);
      res.json({ message: "User profile updated successfully", user: updatedUser });
    } catch (error: any) {
      console.error("Error updating user profile:", error);
      res.status(500).json({ error: error.message || "Failed to update user profile" });
    }
  });

  // Deactivate User (Admin Only)
  app.put("/api/enterprise/users/:userId/deactivate", adminOnly, async (req, res) => {
    try {
      const { userId } = req.params;
      const deactivatedBy = req.user!.id;
      
      // CRITICAL: Validate user belongs to same tenant (multi-tenant check)
      const tenantUser = await storage.getTenantUser(req.user!.tenantId, userId);
      if (!tenantUser) {
        return res.status(403).json({ error: "Access denied - user not in your tenant" });
      }

      // Prevent self-deactivation
      if (userId === req.user!.id) {
        return res.status(400).json({ error: "Cannot deactivate yourself" });
      }

      const user = await storage.deactivateUser(userId, deactivatedBy);
      res.json({ message: "User deactivated successfully", user });
    } catch (error: any) {
      console.error("Error deactivating user:", error);
      res.status(500).json({ error: error.message || "Failed to deactivate user" });
    }
  });

  // Reactivate User (Admin Only)
  app.put("/api/enterprise/users/:userId/reactivate", adminOnly, async (req, res) => {
    try {
      const { userId } = req.params;
      const reactivatedBy = req.user!.id;
      
      // CRITICAL: Validate user belongs to same tenant (multi-tenant check)
      const tenantUser = await storage.getTenantUser(req.user!.tenantId, userId);
      if (!tenantUser) {
        return res.status(403).json({ error: "Access denied - user not in your tenant" });
      }

      const user = await storage.reactivateUser(userId, reactivatedBy);
      res.json({ message: "User reactivated successfully", user });
    } catch (error: any) {
      console.error("Error reactivating user:", error);
      res.status(500).json({ error: error.message || "Failed to reactivate user" });
    }
  });

  // Delete User (Admin Only)
  app.delete("/api/enterprise/users/:userId", adminOnly, async (req, res) => {
    try {
      const { userId } = req.params;
      const deletedBy = req.user!.id;
      
      // CRITICAL: Validate user belongs to same tenant (multi-tenant check)
      const tenantUser = await storage.getTenantUser(req.user!.tenantId, userId);
      if (!tenantUser) {
        return res.status(403).json({ error: "Access denied - user not in your tenant" });
      }

      // Prevent self-deletion
      if (userId === req.user!.id) {
        return res.status(400).json({ error: "Cannot delete yourself" });
      }

      await storage.deleteUser(userId, deletedBy);
      res.json({ message: "User deleted successfully" });
    } catch (error: any) {
      console.error("Error deleting user:", error);
      res.status(500).json({ error: error.message || "Failed to delete user" });
    }
  });

  // ====== ORGANIZATION MANAGEMENT ROUTES ======

  // Create Organization (Admin Only)
  app.post("/api/enterprise/organizations", adminOnly, async (req, res) => {
    try {
      const createdBy = req.user!.id;
      const { name, subscriptionTier } = req.body;

      if (!name) {
        return res.status(400).json({ error: "Organization name is required" });
      }

      const organization = await storage.createOrganization(name, createdBy, subscriptionTier);
      res.json({ message: "Organization created successfully", organization });
    } catch (error: any) {
      console.error("Error creating organization:", error);
      res.status(500).json({ error: error.message || "Failed to create organization" });
    }
  });

  // Update Organization (Admin Only)
  app.put("/api/enterprise/organizations/:tenantId", adminOnly, async (req, res) => {
    try {
      const { tenantId } = req.params;
      const updatedBy = req.user!.id;
      const updates = req.body;

      // CRITICAL: Validate user can modify this tenant
      if (tenantId !== req.user!.tenantId) {
        return res.status(403).json({ error: "Access denied - not your organization" });
      }

      const organization = await storage.updateOrganization(tenantId, updates, updatedBy);
      res.json({ message: "Organization updated successfully", organization });
    } catch (error: any) {
      console.error("Error updating organization:", error);
      res.status(500).json({ error: error.message || "Failed to update organization" });
    }
  });

  // ====== EXISTING USER MANAGEMENT ROUTES ======

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

      // CRITICAL: Validate user belongs to same tenant (multi-tenant check)
      const tenantUser = await storage.getTenantUser(req.user!.tenantId, userId);
      if (!tenantUser) {
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