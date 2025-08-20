import { Request, Response, NextFunction } from 'express';

// Simple authentication middleware with development bypass
export const isAuthenticated = (req: Request, res: Response, next: NextFunction) => {
  // Always allow access in development mode
  if (process.env.NODE_ENV === 'development') {
    return next();
  }
  
  // Production authentication check
  if (!req.isAuthenticated || !req.isAuthenticated() || !req.user) {
    return res.status(401).json({ 
      message: 'Unauthorized - not authenticated'
    });
  }
  
  next();
};