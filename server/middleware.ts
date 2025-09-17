import { Request, Response, NextFunction } from 'express';

// Enhanced authentication middleware
export const isAuthenticated = (req: Request, res: Response, next: NextFunction) => {
  const isAuth = req.isAuthenticated ? req.isAuthenticated() : false;
  
  if (process.env.NODE_ENV === 'development') {
    console.log('🔍 isAuthenticated middleware - req.isAuthenticated():', isAuth);
    console.log('🔍 isAuthenticated middleware - req.user:', req.user);
  } else {
    // In production, only log basic auth status without sensitive data
    console.log('🔍 isAuthenticated middleware - authenticated:', isAuth);
    if (req.user) {
      console.log('🔍 User ID:', (req.user as any).id || 'unknown');
    }
  }
  
  // Development mode bypass for testing
  if (process.env.NODE_ENV === 'development') {
    console.log('🔍 Development mode active');
    
    // Check if user has valid authentication
    if (isAuth && req.user) {
      console.log('✅ Development mode - user authenticated, allowing access');
      return next();
    } else {
      console.log('❌ Development mode - no valid authentication found');
      console.log('❌ Authentication failed - req.isAuthenticated() is', isAuth);
      return res.status(401).json({ 
        message: 'Unauthorized - not authenticated'
      });
    }
  }
  
  // Production authentication check
  if (!isAuth || !req.user) {
    console.log('❌ Production mode - authentication failed');
    return res.status(401).json({ 
      message: 'Unauthorized - not authenticated'
    });
  }
  
  console.log('✅ Production mode - user authenticated');
  next();
};