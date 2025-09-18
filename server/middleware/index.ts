// Enterprise SaaS Middleware Integration
// Comprehensive tenant resolution and RBAC system

export { tenantResolver, validateTenantResource, enforceTenantIsolation } from './tenantResolver';
export { 
  requirePermission, 
  requireRole, 
  requireAnyPermission, 
  requireAllPermissions 
} from './permissionGuard';

// Combined middleware for enterprise endpoints
import { isAuthenticated } from '../averoxAuth';
import { tenantResolver } from './tenantResolver';

/**
 * Complete enterprise middleware stack
 * 1. Authentication check
 * 2. Tenant resolution & context loading
 * 3. RBAC permissions loading
 * 
 * Usage: app.use('/api/admin', enterpriseAuth, requireRole('admin'), routes)
 */
export const enterpriseAuth = [isAuthenticated, tenantResolver];

/**
 * Middleware compositions for common access patterns
 */

// Admin-only endpoints
export const adminOnly = [
  ...enterpriseAuth,
  (req: any, res: any, next: any) => {
    if (req.user?.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  }
];

// Manager+ endpoints (manager and admin)
export const managerPlus = [
  ...enterpriseAuth,
  (req: any, res: any, next: any) => {
    const roleLevel = req.user?.role === 'admin' ? 4 : req.user?.role === 'manager' ? 3 : 0;
    if (roleLevel < 3) {
      return res.status(403).json({ error: 'Manager+ access required' });
    }
    next();
  }
];

// Key management endpoints
export const keyManagement = [
  ...enterpriseAuth,
  (req: any, res: any, next: any) => {
    const permissions = req.user?.permissions || [];
    const hasKeyAccess = permissions.some((p: string) => p.startsWith('keys:'));
    if (!hasKeyAccess) {
      return res.status(403).json({ error: 'Key management access required' });
    }
    next();
  }
];

// Billing endpoints  
export const billingAccess = [
  ...enterpriseAuth,
  (req: any, res: any, next: any) => {
    const permissions = req.user?.permissions || [];
    const hasBillingAccess = permissions.some((p: string) => p.startsWith('billing:'));
    if (!hasBillingAccess) {
      return res.status(403).json({ error: 'Billing access required' });
    }
    next();
  }
];