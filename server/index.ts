import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { initializeKeyRotationScheduler, shutdownKeyRotationScheduler } from "./keyRotationScheduler";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || '5000', 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`serving on port ${port}`);
    
    // Production configuration validation (graceful degradation)
    if (process.env.NODE_ENV === 'production') {
      let configIssues = [];
      
      if (!process.env.STRIPE_SECRET_KEY || process.env.STRIPE_SECRET_KEY.startsWith('sk_test_development')) {
        console.warn('⚠️ WARNING: STRIPE_SECRET_KEY not configured for production - billing features will be unavailable');
        configIssues.push('Stripe billing');
      }
      if (!process.env.STRIPE_WEBHOOK_SECRET) {
        console.warn('⚠️ WARNING: STRIPE_WEBHOOK_SECRET not configured for production - webhook processing will be unavailable');
        configIssues.push('Stripe webhooks');
      }
      
      if (configIssues.length === 0) {
        console.log('✅ Production Stripe configuration validated');
      } else {
        console.warn(`⚠️ Production running with degraded services: ${configIssues.join(', ')}`);
        console.warn('Application will continue but some features may be limited');
      }
    }
    
    // Initialize automated key rotation scheduler
    initializeKeyRotationScheduler();
  });

  // Graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n🛑 Received SIGINT, shutting down gracefully...');
    shutdownKeyRotationScheduler();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    console.log('\n🛑 Received SIGTERM, shutting down gracefully...');
    shutdownKeyRotationScheduler();
    process.exit(0);
  });
})();
