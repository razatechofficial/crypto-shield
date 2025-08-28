import * as client from "openid-client";
import { Strategy, type VerifyFunction } from "openid-client/passport";

import passport from "passport";
import session from "express-session";
import type { Express, RequestHandler } from "express";
import memoize from "memoizee";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";

// Environment variables for generic OIDC configuration
const OIDC_ISSUER_URL = process.env.OIDC_ISSUER_URL;
const OIDC_CLIENT_ID = process.env.OIDC_CLIENT_ID;
const OIDC_CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET;
const ALLOWED_DOMAINS = process.env.ALLOWED_DOMAINS || "localhost:5000";

const getOidcConfig = memoize(
  async () => {
    if (!OIDC_ISSUER_URL || !OIDC_CLIENT_ID) {
      throw new Error("OIDC configuration not provided - running in development mode only");
    }
    return await client.discovery(
      new URL(OIDC_ISSUER_URL),
      OIDC_CLIENT_ID
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
  return session({
    secret: process.env.SESSION_SECRET || "averox-dev-session-secret",
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

async function upsertUser(
  claims: any,
) {
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

export async function setupAuth(app: Express) {
  app.set("trust proxy", 1);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());

  // Development mode: Skip OIDC configuration if not provided
  if (process.env.NODE_ENV === 'development' && (!OIDC_ISSUER_URL || !OIDC_CLIENT_ID)) {
    console.log('🔧 Development mode: Using mock authentication (no OIDC config provided)');
    
    // Set up mock user for development
    passport.serializeUser((user, done) => {
      done(null, user);
    });

    passport.deserializeUser((user: any, done) => {
      done(null, user);
    });

    // Mock authentication routes for development
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
          // Include database user info (same as production)
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

  // Production mode: Use real OIDC
  const config = await getOidcConfig();

  const verify: VerifyFunction = async (tokens, userinfo, done) => {
    updateUserSession(userinfo, tokens);
    try {
      const dbUser = await upsertUser(tokens.claims());
      // Store the full database user object in session, not just OIDC claims
      const sessionUser = {
        ...userinfo,
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
  for (const domain of ALLOWED_DOMAINS.split(",")) {
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

  passport.serializeUser((user, done) => {
    done(null, user);
  });

  passport.deserializeUser((user: any, done) => {
    done(null, user);
  });

  app.get("/api/login", (req, res, next) => {
    passport.authenticate(`averoxauth:${req.hostname || 'localhost'}`, {
      scope: "openid email profile offline_access",
    })(req, res, next);
  });

  app.get("/api/callback", (req, res, next) => {
    passport.authenticate(`averoxauth:${req.hostname || 'localhost'}`, {
      successReturnToOrRedirect: "/",
      failureRedirect: "/api/login",
    })(req, res, next);
  });

  app.get("/api/logout", (req, res) => {
    req.logout(() => {
      res.redirect(
        client.buildEndSessionUrl(config, {
          client_id: OIDC_CLIENT_ID!,
          post_logout_redirect_uri: `${req.protocol}://${req.hostname || 'localhost'}`,
        }).href
      );
    });
  });
}