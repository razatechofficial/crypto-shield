import { Request, Response, NextFunction } from 'express';

// Enhanced authentication middleware
export const isAuthenticated = (req: Request, res: Response, next: NextFunction) => {
  console.log('🔍 isAuthenticated middleware - req.isAuthenticated():', req.isAuthenticated ? req.isAuthenticated() : false);
  console.log('🔍 isAuthenticated middleware - req.user:', req.user);
  
  // Development mode bypass for testing
  if (process.env.NODE_ENV === 'development') {
    console.log('🔍 Development mode active');
    
    // Check if user has valid authentication
    if (req.isAuthenticated && req.isAuthenticated() && req.user) {
      console.log('✅ Development mode - user authenticated, allowing access');
      return next();
    } else {
      console.log('❌ Development mode - no valid authentication found');
      console.log('❌ Authentication failed - req.isAuthenticated() is', req.isAuthenticated ? req.isAuthenticated() : 'undefined');
      return res.status(401).json({ 
        message: 'Unauthorized - not authenticated'
      });
    }
  }
  
  // Production authentication check
  if (!req.isAuthenticated || !req.isAuthenticated() || !req.user) {
    console.log('❌ Production mode - authentication failed');
    return res.status(401).json({ 
      message: 'Unauthorized - not authenticated'
    });
  }
  
  console.log('✅ Production mode - user authenticated');
  next();
};