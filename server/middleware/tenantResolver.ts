import { Request, Response, NextFunction } from 'express';
import { storage } from '../storage';
import { User, TenantUser } from '@shared/schema';

// Extend Express Request to include authenticated user with RBAC context
export interface AuthenticatedUserContext extends User {
  permissions?: string[];
}

// Extend Express Request to include authenticated user and tenant info
declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUserContext;
      tenant?: {
        id: string;
        name: string;
        subscriptionTier: string;
        settings: any;
      };
    }
  }
}

/**
 * Enhanced tenant resolution middleware with RBAC support
 * Resolves tenant context and loads user permissions for enterprise access control
 */
export const tenantResolver = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.user?.id) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userId = req.user.id;
    const userEmail = req.user.email;

    // Ensure user has tenant association
    let tenantId = req.user.tenantId;
    if (!tenantId) {
      // Fallback: create or find tenant for user
      tenantId = await storage.getOrCreateTenantForUser(userId, userEmail);
      req.user.tenantId = tenantId;
    }

    // Load tenant information
    const tenant = await storage.getTenant(tenantId);
    if (!tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    // Load user's role and permissions within this tenant
    const tenantUser = await storage.getTenantUser(tenantId, userId);
    if (!tenantUser) {
      // User not explicitly added to tenant - check if they're the tenant owner
      const user = await storage.getUser(userId);
      if (user?.tenantId === tenantId) {
        // Tenant owner - assign admin role by default
        req.user.role = 'admin';
        req.user.permissions = await storage.getRolePermissions('admin');
      } else {
        return res.status(403).json({ error: 'Invalid tenant access' });
      }
    } else {
      // Load role-based permissions
      req.user.role = tenantUser.role;
      req.user.permissions = await storage.getRolePermissions(tenantUser.role);
    }

    // Attach tenant context to request
    req.tenant = {
      id: tenant.id,
      name: tenant.name,
      subscriptionTier: tenant.subscriptionTier || 'starter',
      settings: tenant.settings || {}
    };

    next();
  } catch (error) {
    console.error('Tenant resolution error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * Validates that a resource belongs to the authenticated user's tenant
 * Prevents cross-tenant data access
 */
export const validateTenantResource = (resourceTenantId: string, req: Request): boolean => {
  if (!req.user?.tenantId) {
    return false;
  }
  
  return resourceTenantId === req.user.tenantId;
};

/**
 * Middleware to ensure tenant isolation for API endpoints
 * Automatically filters requests to only return/modify tenant-scoped resources
 */
export const enforceTenantIsolation = (req: Request, res: Response, next: NextFunction) => {
  if (!req.user?.tenantId) {
    return res.status(401).json({ error: 'Tenant context required' });
  }

  // Add tenant filter to query params for automatic scoping
  req.query.tenantId = req.user.tenantId;
  
  next();
};