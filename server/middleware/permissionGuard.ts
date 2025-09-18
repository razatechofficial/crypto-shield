import { Request, Response, NextFunction } from 'express';

/**
 * Permission-based access control middleware
 * Checks if user has required permissions for specific endpoints
 */
export const requirePermission = (requiredPermission: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userPermissions = req.user.permissions || [];
    
    if (!userPermissions.includes(requiredPermission)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        required: requiredPermission,
        userPermissions 
      });
    }

    next();
  };
};

/**
 * Role-based access control middleware
 * Checks if user has required role (includes hierarchy)
 */
export const requireRole = (requiredRole: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userRole = req.user.role;
    const roleHierarchy: Record<string, number> = {
      'viewer': 1,
      'developer': 2, 
      'admin': 3
    };

    const userLevel = roleHierarchy[userRole] || 0;
    const requiredLevel = roleHierarchy[requiredRole] || 999;

    if (userLevel < requiredLevel) {
      return res.status(403).json({ 
        error: 'Insufficient role permissions',
        required: requiredRole,
        userRole 
      });
    }

    next();
  };
};

/**
 * Multiple permission check (user needs ANY of the listed permissions)
 */
export const requireAnyPermission = (requiredPermissions: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userPermissions = req.user.permissions || [];
    const hasPermission = requiredPermissions.some(permission => 
      userPermissions.includes(permission)
    );

    if (!hasPermission) {
      return res.status(403).json({ 
        error: 'Insufficient permissions - need any of',
        required: requiredPermissions,
        userPermissions 
      });
    }

    next();
  };
};

/**
 * All permission check (user needs ALL of the listed permissions)
 */
export const requireAllPermissions = (requiredPermissions: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userPermissions = req.user.permissions || [];
    const hasAllPermissions = requiredPermissions.every(permission => 
      userPermissions.includes(permission)
    );

    if (!hasAllPermissions) {
      const missingPermissions = requiredPermissions.filter(permission => 
        !userPermissions.includes(permission)
      );

      return res.status(403).json({ 
        error: 'Insufficient permissions - missing',
        missing: missingPermissions,
        userPermissions 
      });
    }

    next();
  };
};