import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import bcrypt from "bcryptjs";
import session from "express-session";
import type { Express, RequestHandler } from "express";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";

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
    secret: process.env.SESSION_SECRET!,
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

export async function setupAuth(app: Express) {
  app.set("trust proxy", 1);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());

  // Configure local authentication strategy
  passport.use(new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password'
    },
    async (email: string, password: string, done) => {
      try {
        const user = await storage.getUserByEmail(email);
        if (!user) {
          return done(null, false, { message: 'Invalid email or password' });
        }

        const isValidPassword = await bcrypt.compare(password, user.passwordHash || '');
        if (!isValidPassword) {
          return done(null, false, { message: 'Invalid email or password' });
        }

        return done(null, {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          tenantId: user.tenantId,
          role: user.role
        });
      } catch (error) {
        return done(error);
      }
    }
  ));

  passport.serializeUser((user: any, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id: string, done) => {
    try {
      const user = await storage.getUser(id);
      if (!user) {
        return done(null, false);
      }
      done(null, {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        tenantId: user.tenantId,
        role: user.role
      });
    } catch (error) {
      done(error);
    }
  });

  // Registration endpoint
  app.post("/api/register", async (req, res) => {
    try {
      const { email, password, firstName, lastName } = req.body;

      if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
      }

      // Check if user already exists
      const existingUser = await storage.getUserByEmail(email);
      if (existingUser) {
        return res.status(400).json({ message: "User already exists with this email" });
      }

      // Hash password
      const saltRounds = 12;
      const passwordHash = await bcrypt.hash(password, saltRounds);

      // Create user and tenant
      const tenantId = await storage.getOrCreateTenantForUser(email, email);
      const user = await storage.upsertUser({
        email,
        firstName: firstName || null,
        lastName: lastName || null,
        passwordHash,
        tenantId,
      });

      // Auto-login after registration
      req.login({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        tenantId: user.tenantId,
        role: user.role
      }, (err) => {
        if (err) {
          console.error('Auto-login error:', err);
          return res.status(500).json({ message: "Registration successful but login failed" });
        }
        res.json({ 
          message: "Registration successful", 
          user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName
          }
        });
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ message: "Registration failed" });
    }
  });

  // Login endpoint
  app.post("/api/login", (req, res, next) => {
    passport.authenticate('local', (err: any, user: any, info: any) => {
      if (err) {
        return res.status(500).json({ message: "Authentication error" });
      }
      if (!user) {
        return res.status(401).json({ message: info?.message || "Invalid credentials" });
      }
      
      req.login(user, (err) => {
        if (err) {
          return res.status(500).json({ message: "Login failed" });
        }
        res.json({ 
          message: "Login successful", 
          user: {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName
          }
        });
      });
    })(req, res, next);
  });

  // Logout endpoint
  app.post("/api/logout", (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ message: "Logout failed" });
      }
      res.json({ message: "Logout successful" });
    });
  });

  // Get current user endpoint
  app.get("/api/auth/user", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      res.json({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        tenantId: user.tenantId,
        role: user.role
      });
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });
}

export const isAuthenticated: RequestHandler = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Unauthorized" });
};