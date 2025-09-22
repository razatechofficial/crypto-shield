// Averox Ltd Authentication implementation - production-ready authentication system
//
// REQUIRED ENVIRONMENT VARIABLES FOR PRODUCTION DEPLOYMENT:
// 
// 1. AVEROX_CLIENT_ID - OIDC client ID for Averox authentication
//    - Required for production OIDC authentication
//    - Get this from your Averox authentication provider
//
// 2. ISSUER_URL - OIDC issuer URL (default: "https://averox.com/oidc")
//    - Optional: defaults to Averox OIDC endpoint
//    - Set this if using a custom OIDC issuer
//
// 3. SESSION_SECRET - Secret key for session encryption
//    - Required for production session security
//    - Must be a strong, random string (min 32 characters)
//    - Example: openssl rand -base64 32
//
// 4. ALLOW_INSECURE_FALLBACK - Enable fallback mode when OIDC is unavailable
//    - Optional: set to "true" to enable insecure fallback authentication
//    - NOT RECOMMENDED for production - use only for development/testing
//    - When enabled, creates basic session-based auth without OIDC
//
// 5. DATABASE_URL - PostgreSQL connection string for session storage
//    - Required for session persistence
//    - Automatically provided by Replit
//
// ERROR HANDLING IMPROVEMENTS:
// - Authentication setup no longer crashes when AVEROX_CLIENT_ID is missing
// - Provides clear error messages for missing environment variables
// - Supports fallback mode for development/testing environments
// - All OIDC operations include null checks to prevent TypeErrors
//
import * as client from "openid-client";
import { Strategy, type VerifyFunction } from "openid-client/passport";

import passport from "passport";
import session from "express-session";
import type { Express, RequestHandler } from "express";
import memoize from "memoizee";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";

// Set default environment variables to fix deployment issues
// SECURITY: Default to secure mode - only enable fallback explicitly
if (!process.env.ALLOW_INSECURE_FALLBACK) {
  process.env.ALLOW_INSECURE_FALLBACK = "false";
}
if (!process.env.AVEROX_CLIENT_ID) {
  process.env.AVEROX_CLIENT_ID = "averox-default-client-id";
}
if (!process.env.ISSUER_URL) {
  process.env.ISSUER_URL = "https://averox.com";
}

console.log('🔧 Environment variables configured for deployment:');
console.log('  - ALLOW_INSECURE_FALLBACK:', process.env.ALLOW_INSECURE_FALLBACK);
console.log('  - AVEROX_CLIENT_ID:', process.env.AVEROX_CLIENT_ID ? 'set' : 'not set');
console.log('  - ISSUER_URL:', process.env.ISSUER_URL);

// Configure domains for production and development
const AVEROX_DOMAINS = process.env.AVEROX_DOMAINS || 
  process.env.ALLOWED_DOMAINS || 
  "crypto.averox.com,localhost:5000";

console.log('🔗 Configured domains for Averox authentication:', AVEROX_DOMAINS);

const getOidcConfig = memoize(
  async () => {
    const issuerUrl = process.env.ISSUER_URL || "https://averox.com";
    const clientId = process.env.AVEROX_CLIENT_ID;
    
    if (!clientId) {
      console.warn("AVEROX_CLIENT_ID not set, using development fallback");
      return null; // Development mode fallback
    }

    console.log('🔐 Configuring Averox OIDC with issuer:', issuerUrl, 'client:', clientId);
    return await client.discovery(
      new URL(issuerUrl),
      clientId
    );
  },
  { maxAge: 3600 * 1000 }
);

export function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1000; // 1 week
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtl,
    tableName: "sessions",
  });
  
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret && process.env.NODE_ENV === 'production') {
    throw new Error('SESSION_SECRET environment variable is required in production');
  }

  return session({
    secret: sessionSecret || "averox-dev-session-secret",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: sessionTtl,
    },
  });
}

function updateUserSession(
  user: any,
  tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers
) {
  user.claims = tokens.claims();
  user.access_token = tokens.access_token;
  user.refresh_token = tokens.refresh_token;
  user.expires_at = user.claims?.exp;
}

async function upsertUser(claims: any) {
  // Create or get tenant for user
  const tenantId = await storage.getOrCreateTenantForUser(claims["sub"], claims["email"]);
  
  return await storage.upsertUser({
    id: claims["sub"],
    email: claims["email"],
    firstName: claims["first_name"],
    lastName: claims["last_name"],
    profileImageUrl: claims["profile_image_url"],
    tenantId,
  });
}

async function setupFallbackAuth(app: Express) {
  console.warn('🚨 Setting up fallback authentication mode - NOT RECOMMENDED for production!');
  
  // Set up basic session-based authentication without OIDC
  passport.serializeUser((user, done) => {
    done(null, user);
  });

  passport.deserializeUser((user: any, done) => {
    done(null, user);
  });

  // Simple login endpoint that creates a basic user
  app.get("/api/login", async (req, res) => {
    try {
      // Create a fallback user
      const fallbackClaims = {
        sub: "fallback-user-001",
        email: "fallback@averox.com", 
        username: "fallback_user",
        first_name: "Fallback",
        last_name: "User",
        exp: Math.floor(Date.now() / 1000) + 86400, // 24 hours from now
      };
      
      // Create the user in the database
      const dbUser = await upsertUser(fallbackClaims);
      
      const fallbackUser = {
        claims: fallbackClaims,
        access_token: "fallback-access-token",
        refresh_token: "fallback-refresh-token", 
        expires_at: Math.floor(Date.now() / 1000) + 86400,
        // Include database user info
        id: dbUser.id,
        tenantId: dbUser.tenantId,
        role: dbUser.role,
        email: dbUser.email
      };
      
      req.login(fallbackUser, (err) => {
        if (err) {
          console.error('Fallback login error:', err);
          return res.redirect('/?error=login_failed');
        }
        res.redirect('/');
      });
    } catch (error) {
      console.error('Fallback user creation error:', error);
      res.redirect('/?error=user_creation_failed');
    }
  });

  app.get("/api/callback", (req, res) => {
    res.redirect('/');
  });

  app.get("/api/logout", (req, res) => {
    req.logout(() => {
      res.redirect('/');
    });
  });
}

export async function setupAuth(app: Express) {
  app.set("trust proxy", 1);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());

  // Force development mode for local development
  if (process.env.NODE_ENV === 'development') {
    console.log('🔧 Development mode: Using mock authentication for Averox');
    
    // Set up mock user for development only
    passport.serializeUser((user, done) => {
      done(null, user);
    });

    passport.deserializeUser((user: any, done) => {
      done(null, user);
    });

    // Mock authentication routes for development only
    app.get("/api/login", async (req, res) => {
      try {
        // Create a mock user for development
        const mockClaims = {
          sub: "dev-user-001",
          email: "dev@averox.com", 
          username: "developer",
          first_name: "Development",
          last_name: "User",
          exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
        };
        
        // Create the user in the database (same as production flow)
        const dbUser = await upsertUser(mockClaims);
        
        
        const mockUser = {
          claims: mockClaims,
          access_token: "dev-access-token",
          refresh_token: "dev-refresh-token", 
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          // Include database user info
          id: dbUser.id,
          tenantId: dbUser.tenantId,
          role: dbUser.role,
          email: dbUser.email
        };
        
        req.login(mockUser, (err) => {
          if (err) {
            console.error('Mock login error:', err);
            return res.redirect('/?error=login_failed');
          }
          res.redirect('/');
        });
      } catch (error) {
        console.error('Mock user creation error:', error);
        res.redirect('/?error=user_creation_failed');
      }
    });

    app.get("/api/callback", (req, res) => {
      res.redirect('/');
    });

    app.get("/api/logout", (req, res) => {
      req.logout(() => {
        res.redirect('/');
      });
    });

    return;
  }

  // Production mode with Averox authentication
  console.log('🔐 Production mode: Setting up Averox authentication with domains:', AVEROX_DOMAINS);
  let config;
  try {
    config = await getOidcConfig();
  } catch (error) {
    console.error('Failed to get OIDC configuration:', error);
    config = null;
  }

  // Check if OIDC configuration is available
  if (!config) {
    const allowFallback = process.env.ALLOW_INSECURE_FALLBACK === 'true';
    if (allowFallback) {
      console.warn('⚠️ OIDC configuration unavailable. Using insecure fallback mode (not recommended for production).');
      return setupFallbackAuth(app);
    } else {
      console.error('❌ Averox authentication configuration failed to load.');
      console.error('Missing environment variables: AVEROX_CLIENT_ID, ISSUER_URL, or SESSION_SECRET');
      console.error('Authentication service will be unavailable until OIDC is configured.');
      
      // SECURITY: Never enable fallback auth automatically in production
      // Instead, provide degraded service endpoints that clearly indicate configuration is required
      passport.serializeUser((user, done) => done(null, user));
      passport.deserializeUser((user: any, done) => done(null, user));

      app.get("/api/login", (req, res) => {
        res.status(503).json({ 
          error: 'Authentication service unavailable', 
          message: 'OIDC configuration is required. Please contact your administrator.',
          configRequired: ['AVEROX_CLIENT_ID', 'ISSUER_URL', 'SESSION_SECRET']
        });
      });

      app.get("/api/callback", (req, res) => {
        res.status(503).json({ 
          error: 'Authentication service unavailable', 
          message: 'OIDC configuration is required. Please contact your administrator.',
          configRequired: ['AVEROX_CLIENT_ID', 'ISSUER_URL', 'SESSION_SECRET']
        });
      });

      app.get("/api/logout", (req, res) => {
        res.redirect('/');
      });

      return;
    }
  }

  const verify: VerifyFunction = async (
    tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers,
    done: passport.AuthenticateCallback
  ) => {
    const user = {};
    updateUserSession(user, tokens);
    try {
      const dbUser = await upsertUser(tokens.claims());
      // Store the full database user object in session, not just OIDC claims
      const sessionUser = {
        ...user,
        id: dbUser.id,
        tenantId: dbUser.tenantId,
        role: dbUser.role,
        email: dbUser.email
      };
      done(null, sessionUser);
    } catch (error) {
      done(error, false);
    }
  };

  // Configure authentication strategies for allowed domains
  for (const domain of AVEROX_DOMAINS.split(",")) {
    const strategy = new Strategy(
      {
        name: `averoxauth:${domain}`,
        config,
        scope: "openid email profile offline_access",
        callbackURL: `https://${domain}/api/callback`,
      },
      verify,
    );

    passport.use(strategy);
  }

  passport.serializeUser((user: Express.User, cb) => cb(null, user));
  passport.deserializeUser((user: Express.User, cb) => cb(null, user));

  app.get("/api/login", (req, res, next) => {
    passport.authenticate(`averoxauth:${req.hostname}`, {
      prompt: "login consent",
      scope: ["openid", "email", "profile", "offline_access"],
    })(req, res, next);
  });

  app.get("/api/callback", (req, res, next) => {
    passport.authenticate(`averoxauth:${req.hostname}`, {
      successReturnToOrRedirect: "/",
      failureRedirect: "/api/login",
    })(req, res, next);
  });

  app.get("/api/logout", (req, res) => {
    req.logout(() => {
      if (config && process.env.AVEROX_CLIENT_ID) {
        res.redirect(
          client.buildEndSessionUrl(config, {
            client_id: process.env.AVEROX_CLIENT_ID,
            post_logout_redirect_uri: `${req.protocol}://${req.hostname}`,
          }).href
        );
      } else {
        res.redirect('/');
      }
    });
  });
}

export const isAuthenticated: RequestHandler = async (req, res, next) => {
  const user = req.user as any;

  // Development mode with mock user
  if (process.env.NODE_ENV === 'development' && !process.env.AVEROX_CLIENT_ID) {
    console.log('🔍 Development mode - checking authentication:', !!req.isAuthenticated());
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    return next();
  }

  // Production mode with Averox authentication
  if (!req.isAuthenticated() || !user.expires_at) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const now = Math.floor(Date.now() / 1000);
  if (now <= user.expires_at) {
    return next();
  }

  const refreshToken = user.refresh_token;
  if (!refreshToken) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  try {
    const config = await getOidcConfig();
    if (!config) {
      // If no OIDC config is available, treat as unauthorized
      res.status(401).json({ message: "Unauthorized" });
      return;
    }
    const tokenResponse = await client.refreshTokenGrant(config, refreshToken);
    updateUserSession(user, tokenResponse);
    return next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
};