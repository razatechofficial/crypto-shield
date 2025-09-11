import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth } from "./genericAuth";
import { isAuthenticated } from "./middleware";
import { insertSdkSchema, insertEncryptionKeySchema } from "@shared/schema";
import { z } from "zod";
import archiver from "archiver";
import { EnterpriseAdapter } from "./enterpriseAdapter";

export async function registerRoutes(app: Express): Promise<Server> {
  // Setup authentication
  await setupAuth(app);

  // Authentication routes
  app.get("/api/auth/user", (req, res) => {
    if (req.user) {
      res.json(req.user);
    } else {
      res.status(401).json({ message: "Not authenticated" });
    }
  });

  // Algorithm routes
  app.get("/api/algorithms", async (req, res) => {
    try {
      const algorithms = await storage.getEncryptionAlgorithms();
      res.json(algorithms);
    } catch (error) {
      console.error("Error fetching algorithms:", error);
      res.status(500).json({ message: "Failed to fetch algorithms" });
    }
  });

  app.post("/api/algorithms/recommend", async (req, res) => {
    try {
      const config = req.body;
      const recommendations = await storage.getRecommendedAlgorithms(config);
      res.json(recommendations);
    } catch (error) {
      console.error("Error getting algorithm recommendations:", error);
      res.status(500).json({ message: "Failed to get recommendations" });
    }
  });

  // SDK routes
  app.get("/api/sdks", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const userId = user.id || user.claims?.sub;
      const userEmail = user.email || user.claims?.email;
      
      if (!userId || !userEmail) {
        return res.status(401).json({ message: "Invalid user session" });
      }
      
      const tenantId = user.tenantId || await storage.getOrCreateTenantForUser(userId, userEmail);
      const sdks = await storage.getSDKs(tenantId, userId);
      res.json(sdks);
    } catch (error) {
      console.error("Error fetching SDKs:", error);
      res.status(500).json({ message: "Failed to fetch SDKs" });
    }
  });

  app.post("/api/sdks/generate", isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const userId = user.id || user.claims?.sub;
      const userEmail = user.email || user.claims?.email;
      
      if (!userId || !userEmail) {
        return res.status(401).json({ message: "Invalid user session" });
      }
      
      const tenantId = user.tenantId || await storage.getOrCreateTenantForUser(userId, userEmail);
      
      const sdkData = insertSdkSchema.parse({
        ...req.body,
        tenantId: tenantId,
        userId: userId,
      });
      
      const sdk = await storage.createSDK(sdkData);
      const downloadUrl = `/api/sdks/${sdk.id}/download`;
      const updatedSdk = await storage.updateSDK(sdk.id, { downloadUrl });
      
      res.json(updatedSdk || { ...sdk, downloadUrl });
    } catch (error) {
      console.error("Error generating SDK:", error);
      if (error instanceof z.ZodError) {
        res.status(400).json({ message: "Invalid SDK data", errors: error.errors });
      } else {
        res.status(500).json({ message: "Failed to generate SDK" });
      }
    }
  });

  // ENTERPRISE SDK DOWNLOAD with REAL production generation + SECURITY
  app.get("/api/sdks/:downloadId/download", isAuthenticated, async (req, res) => {
    try {
      console.log(`📦 Download request for SDK ID: ${req.params.downloadId}`);
      
      // Get user and verify authentication
      const user = req.user as any;
      const userId = user.id || user.claims?.sub;
      const userEmail = user.email || user.claims?.email;
      
      if (!userId || !userEmail) {
        return res.status(401).json({ message: "Invalid user session" });
      }
      
      const sdk = await storage.getSDK(req.params.downloadId);
      if (!sdk) {
        console.error(`❌ SDK not found: ${req.params.downloadId}`);
        return res.status(404).json({ message: "SDK not found" });
      }

      // SECURITY: Verify user owns this SDK or belongs to same tenant
      const tenantId = user.tenantId || await storage.getOrCreateTenantForUser(userId, userEmail);
      if (sdk.tenantId !== tenantId && sdk.userId !== userId) {
        console.error(`❌ Unauthorized access attempt: User ${userId} tried to download SDK ${req.params.downloadId} owned by tenant ${sdk.tenantId}`);
        return res.status(403).json({ message: "Unauthorized access to SDK" });
      }

      console.log(`✅ Found SDK: ${sdk.name} (version ${sdk.version})`);

      // Parse languages safely
      const languages = Array.isArray(sdk.languages) 
        ? sdk.languages 
        : JSON.parse(sdk.languages);

      console.log(`🏭 Generating ENTERPRISE SDKs for languages: ${languages.join(', ')}`);

      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${sdk.name.toLowerCase().replace(/\s+/g, '-')}-enterprise-sdk-v${sdk.version}.zip"`);
      
      const archive = archiver('zip', { zlib: { level: 9 } });
      
      archive.on('error', (err) => {
        console.error('❌ Archive error:', err);
        if (!res.headersSent) {
          res.status(500).json({ message: 'Archive creation failed' });
        }
      });

      archive.pipe(res);
      console.log('📡 Archive piped to response with ENTERPRISE GENERATOR');

      // Generate REAL production SDKs using enterprise generator
      const sdkResults = await EnterpriseAdapter.generateSDK(sdk, languages);

      for (const [language, fileMap] of Object.entries(sdkResults)) {
        const langFolder = `${language}/`;
        for (const [filePath, content] of Object.entries(fileMap)) {
          archive.append(content, { name: `${langFolder}${filePath}` });
          console.log(`📄 Added ENTERPRISE file: ${langFolder}${filePath}`);
        }
      }

      // Finalize archive
      await new Promise<void>((resolve, reject) => {
        archive.on('end', () => {
          console.log('✅ ENTERPRISE archive finalized with ALL 18 security gates');
          resolve();
        });
        
        archive.on('error', (err) => {
          console.error('❌ Archive finalization error:', err);
          reject(err);
        });
        
        archive.finalize();
      });
    } catch (error) {
      console.error("❌ Error downloading SDK:", error);
      if (!res.headersSent) {
        res.status(500).json({ message: "Failed to download SDK" });
      }
    }
  });

  app.get("/api/sdks/:id", isAuthenticated, async (req, res) => {
    try {
      const sdk = await storage.getSDK(req.params.id);
      if (!sdk) {
        return res.status(404).json({ message: "SDK not found" });
      }
      res.json(sdk);
    } catch (error) {
      console.error("Error fetching SDK:", error);
      res.status(500).json({ message: "Failed to fetch SDK" });
    }
  });

  app.delete("/api/sdks/:id", isAuthenticated, async (req, res) => {
    try {
      await storage.deleteSDK(req.params.id);
      res.json({ message: "SDK deleted successfully" });
    } catch (error) {
      console.error("Error deleting SDK:", error);
      res.status(500).json({ message: "Failed to delete SDK" });
    }
  });

  // Health check
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  const httpServer = createServer(app);
  return httpServer;
}